//! Cert export targets: where a freshly-issued cert gets pushed.
//!
//! Three target kinds today:
//!  - **File** — write fullchain + key to paths on the local filesystem,
//!    optionally chowned to a non-aifw user (so e.g. nginx can read its
//!    own key). Uses the same `sudo install` dance as `dns_blocklists`
//!    because aifw user can't write outside its own dirs.
//!  - **Webhook** — POST a JSON blob with cert/key/chain to a URL with
//!    an optional Authorization header. Lets a pull-script on a remote
//!    host get notified instantly instead of polling.
//!  - **LocalTlsStore** — drop the cert + key into AiFw's own TLS dir
//!    (/usr/local/etc/aifw/tls/) so the API switches to the new cert on
//!    next restart. Optionally restarts the named service after writing.
//!
//! Errors per-target are recorded on the row so the UI can show which
//! deployments succeeded after a renewal and which need attention.

use crate::acme::{self, AcmeCert, AcmeExportTarget, ExportTargetKind};
use chrono::Utc;
use sqlx::SqlitePool;

/// Run every export target attached to this cert. Errors are recorded on
/// the target row; the function itself never returns Err.
pub async fn publish_all(pool: &SqlitePool, cert_id: i64) {
    let cert = match acme::load_cert(pool, cert_id).await {
        Some(c) => c,
        None => return,
    };
    if cert.cert_pem.is_none() || cert.key_pem.is_none() {
        // No issued material yet — nothing to publish.
        return;
    }
    let targets = acme::load_targets_for_cert(pool, cert_id).await;
    for t in targets {
        let (ok, err) = run_target(&cert, &t).await;
        let _ = sqlx::query(
            "UPDATE acme_export_target SET last_run_at = ?, last_run_ok = ?, last_run_error = ? WHERE id = ?"
        )
        .bind(Utc::now().to_rfc3339())
        .bind(if ok { 1i64 } else { 0 })
        .bind(err.as_deref())
        .bind(t.id)
        .execute(pool).await;
    }
}

async fn run_target(cert: &AcmeCert, t: &AcmeExportTarget) -> (bool, Option<String>) {
    match t.kind {
        ExportTargetKind::File => match run_file(cert, &t.config).await {
            Ok(_) => (true, None),
            Err(e) => (false, Some(e)),
        },
        ExportTargetKind::Webhook => match run_webhook(cert, &t.config).await {
            Ok(_) => (true, None),
            Err(e) => (false, Some(e)),
        },
        ExportTargetKind::LocalTlsStore => match run_local_tls_store(cert, &t.config).await {
            Ok(_) => (true, None),
            Err(e) => (false, Some(e)),
        },
    }
}

// ---- file -----------------------------------------------------------------

async fn run_file(cert: &AcmeCert, cfg: &serde_json::Value) -> Result<(), String> {
    let cert_path = cfg
        .get("cert_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "file target missing cert_path".to_string())?;
    let key_path = cfg
        .get("key_path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "file target missing key_path".to_string())?;
    let chain_path = cfg.get("chain_path").and_then(|v| v.as_str());
    let owner = cfg.get("owner").and_then(|v| v.as_str());
    let mode_cert = cfg.get("mode").and_then(|v| v.as_str()).unwrap_or("0644");
    let mode_key = cfg
        .get("key_mode")
        .and_then(|v| v.as_str())
        .unwrap_or("0600");

    // Reject any destination that escapes our allow-listed export roots
    // (blocks writes to /root/.ssh, /etc/rc.conf.d, /etc/sudoers.d, etc).
    let cert_path_ok = crate::path_safety::validate_export_path(cert_path)?;
    let key_path_ok = crate::path_safety::validate_export_path(key_path)?;
    let chain_path_ok = match chain_path {
        Some(p) => Some(crate::path_safety::validate_export_path(p)?),
        None => None,
    };

    let leaf = cert.cert_pem.as_deref().unwrap_or("");
    let chain = cert.chain_pem.as_deref().unwrap_or("");
    let key = cert.key_pem.as_deref().unwrap_or("");
    let fullchain = format!("{leaf}\n{chain}");

    sudo_install_string(
        &fullchain,
        &cert_path_ok.to_string_lossy(),
        mode_cert,
        owner,
    )
    .await?;
    sudo_install_string(key, &key_path_ok.to_string_lossy(), mode_key, owner).await?;
    if let Some(p) = chain_path_ok {
        sudo_install_string(chain, &p.to_string_lossy(), mode_cert, owner).await?;
    }
    Ok(())
}

/// Install an export file as root (privately staged — see
/// [`crate::api_tls::install_file`]).
async fn sudo_install_string(
    body: &str,
    dest: &str,
    mode: &str,
    owner: Option<&str>,
) -> Result<(), String> {
    crate::api_tls::install_file(body, dest, mode, owner).await
}

// ---- webhook --------------------------------------------------------------

async fn run_webhook(cert: &AcmeCert, cfg: &serde_json::Value) -> Result<(), String> {
    let url = cfg
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "webhook target missing url".to_string())?;
    let auth = cfg
        .get("auth_header")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    crate::net_safety::validate_outbound_url(url).await?;

    let body = serde_json::json!({
        "common_name": cert.common_name,
        "sans": cert.sans,
        "expires_at": cert.expires_at,
        "cert_pem":  cert.cert_pem,
        "chain_pem": cert.chain_pem,
        "key_pem":   cert.key_pem,
    });

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|e| format!("reqwest build: {e}"))?;
    let mut req = client.post(url).json(&body);
    if !auth.is_empty() {
        req = req.header("Authorization", auth);
    }
    let resp = req.send().await.map_err(|e| format!("webhook POST: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("webhook returned {}", resp.status()));
    }
    Ok(())
}

// ---- local TLS store ------------------------------------------------------

async fn run_local_tls_store(cert: &AcmeCert, cfg: &serde_json::Value) -> Result<(), String> {
    let reload_service = cfg
        .get("reload_service")
        .and_then(|v| v.as_str())
        .unwrap_or("aifw_api");
    let leaf = cert.cert_pem.as_deref().unwrap_or("");
    let chain = cert.chain_pem.as_deref().unwrap_or("");
    let key = cert.key_pem.as_deref().unwrap_or("");
    let fullchain = format!("{leaf}\n{chain}");

    // Validated, privately staged, key 0440 root:aifw (#717: this used to
    // ask for 0640 root:rdns — a mode the install helper refuses, and a
    // group the API's `aifw` user isn't in).
    crate::api_tls::install(&fullchain, key).await?;

    // Reload the configured service so it picks up the new cert. The
    // helper enforces an allowlist on `reload_service` — operators
    // setting an arbitrary service name in the cert export config will
    // see the call fail loudly rather than escalate via service(8).
    if reload_service == "aifw_api" {
        // This runs inside the API: restart it a moment later so the
        // export's result is recorded first (as the updater does).
        tokio::spawn(async {
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            if let Err(e) = crate::api_tls::restart_api().await {
                tracing::warn!(error = %e, "acme export: API restart for the new certificate failed");
            }
        });
        return Ok(());
    }
    match crate::sudo::service(reload_service, "restart").await {
        Ok(out) if out.status.success() => Ok(()),
        Ok(out) => Err(format!(
            "restart {reload_service}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )),
        Err(e) => Err(format!("restart {reload_service}: {e}")),
    }
}
