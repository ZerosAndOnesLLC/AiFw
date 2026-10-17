//! GeoLite2 database lifecycle for the API process: load the CSV files at
//! boot, download a fresh release from MaxMind on the configured schedule,
//! and re-apply the geo-IP anchor whenever the rules change behind the
//! API's back (CLI, config restore, cluster sync).

use std::time::Duration;

use crate::AppState;

/// How often rules written outside the API are picked up.
const RECONCILE_EVERY: Duration = Duration::from_secs(60);
/// How often the download schedule is checked.
const SCHEDULE_EVERY: Duration = Duration::from_secs(3600);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(180);

/// Download the GeoLite2 Country CSV release with the stored license key,
/// install it and re-apply the rules. Returns the aggregated CIDR count.
pub async fn refresh(state: &AppState) -> anyhow::Result<usize> {
    let engine = &state.geoip_engine;
    let Some(key) = engine.license_key().await? else {
        anyhow::bail!(
            "no MaxMind license key configured — add one under Geo-IP → Database, or upload the CSV release"
        );
    };
    let account = engine.account_id().await?;
    let result = download(account.as_deref(), &key).await;
    engine
        .record_refresh(result.as_ref().map(|_| ()).map_err(|e| e.to_string()))
        .await?;
    let archive = result?;
    let cidrs = match engine.import_archive(archive, "maxmind").await {
        Ok(n) => n,
        Err(e) => {
            engine.record_refresh(Err(e.to_string())).await?;
            return Err(e.into());
        }
    };
    engine.apply_rules().await?;
    tracing::info!(cidrs, "geo-ip database refreshed from MaxMind");
    Ok(cidrs)
}

/// Fetch the zip. With an account ID, use MaxMind's permalink with HTTP
/// Basic auth (account ID / license key); otherwise fall back to the
/// legacy key-in-URL endpoint. Errors never include the URL or the key.
/// The permalink redirects to a presigned object-store URL; reqwest drops
/// the Authorization header on that cross-host hop.
async fn download(account_id: Option<&str>, key: &str) -> anyhow::Result<Vec<u8>> {
    let url = match account_id {
        Some(_) => aifw_core::GeoIpEngine::MAXMIND_PERMALINK.to_string(),
        None => aifw_core::GeoIpEngine::maxmind_legacy_url(key),
    };
    aifw_common::net_safety::validate_outbound_url(&url)
        .await
        .map_err(|e| anyhow::anyhow!("download.maxmind.com: {e}"))?;
    let client = reqwest::Client::builder()
        .timeout(DOWNLOAD_TIMEOUT)
        .connect_timeout(Duration::from_secs(15))
        .user_agent(format!("AiFw/{}", env!("CARGO_PKG_VERSION")))
        .build()?;
    let mut req = client.get(&url);
    if let Some(acct) = account_id {
        req = req.basic_auth(acct, Some(key));
    }
    let mut resp = req
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("MaxMind download failed: {}", e.without_url()))?;
    match resp.status() {
        s if s.is_success() => {}
        reqwest::StatusCode::UNAUTHORIZED if account_id.is_none() => anyhow::bail!(
            "MaxMind rejected the license key (HTTP 401). Keys issued by the current MaxMind \
             portal only work together with your account ID — add it next to the key."
        ),
        reqwest::StatusCode::UNAUTHORIZED => anyhow::bail!(
            "MaxMind rejected the account ID / license key pair (HTTP 401). Check both in \
             the MaxMind portal under Manage License Keys."
        ),
        reqwest::StatusCode::TOO_MANY_REQUESTS => {
            anyhow::bail!("MaxMind rate-limited the download (HTTP 429); try again later")
        }
        s => anyhow::bail!("MaxMind returned HTTP {s}"),
    }
    let cap = aifw_core::geoip::MAX_ARCHIVE_BYTES;
    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| anyhow::anyhow!("MaxMind download interrupted: {}", e.without_url()))?
    {
        if body.len() + chunk.len() > cap {
            anyhow::bail!("MaxMind archive larger than {} MB", cap / (1024 * 1024));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Boot: load the stored release (or download one when a key is present
/// and nothing is on disk), apply the rules, then keep both current.
pub async fn start(state: AppState) {
    let engine = state.geoip_engine.clone();
    match engine.load_from_dir().await {
        Ok(Some(n)) => tracing::info!(cidrs = n, "geo-ip database loaded from disk"),
        Ok(None) => {
            if engine.license_key().await.ok().flatten().is_some() {
                tracing::info!("geo-ip: no database on disk; downloading from MaxMind");
                if let Err(e) = refresh(&state).await {
                    tracing::warn!(error = %e, "geo-ip: initial download failed");
                }
            } else {
                tracing::info!(
                    "geo-ip: no database loaded — add a MaxMind license key or upload the GeoLite2 Country CSV release"
                );
            }
        }
        Err(e) => tracing::warn!(error = %e, "geo-ip: loading the database from disk failed"),
    }
    if let Err(e) = engine.apply_rules().await {
        tracing::warn!(error = %e, "geo-ip rules not applied on startup");
    } else {
        tracing::info!("Geo-IP rules applied on startup");
    }

    let mut applied = engine.rules_fingerprint().await.unwrap_or_default();
    tokio::spawn(async move {
        let mut reconcile = tokio::time::interval(RECONCILE_EVERY);
        let mut schedule = tokio::time::interval(SCHEDULE_EVERY);
        reconcile.tick().await;
        schedule.tick().await;
        loop {
            tokio::select! {
                _ = reconcile.tick() => {
                    match engine.rules_fingerprint().await {
                        Ok(now) if now != applied => {
                            match engine.apply_rules().await {
                                Ok(()) => {
                                    tracing::info!("geo-ip rules re-applied after an out-of-band change");
                                    applied = now;
                                }
                                Err(e) => tracing::warn!(error = %e, "geo-ip re-apply failed"),
                            }
                        }
                        Ok(_) => {}
                        Err(e) => tracing::debug!(error = %e, "geo-ip reconcile read failed"),
                    }
                }
                _ = schedule.tick() => {
                    match engine.refresh_due().await {
                        Ok(true) => {
                            if let Err(e) = refresh(&state).await {
                                tracing::warn!(error = %e, "geo-ip scheduled refresh failed");
                            }
                        }
                        Ok(false) => {}
                        Err(e) => tracing::debug!(error = %e, "geo-ip schedule check failed"),
                    }
                }
            }
        }
    });
}
