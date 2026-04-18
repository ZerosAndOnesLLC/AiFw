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
use tokio::process::Command;

const SUDO: &str = "/usr/local/bin/sudo";

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
        ExportTargetKind::File          => match run_file(cert, &t.config).await { Ok(_) => (true, None), Err(e) => (false, Some(e)) },
        ExportTargetKind::Webhook       => match run_webhook(cert, &t.config).await { Ok(_) => (true, None), Err(e) => (false, Some(e)) },
        ExportTargetKind::LocalTlsStore => match run_local_tls_store(cert, &t.config).await { Ok(_) => (true, None), Err(e) => (false, Some(e)) },
    }
}

// ---- file -----------------------------------------------------------------

async fn run_file(cert: &AcmeCert, cfg: &serde_json::Value) -> Result<(), String> {
    let cert_path  = cfg.get("cert_path").and_then(|v| v.as_str())
        .ok_or_else(|| "file target missing cert_path".to_string())?;
    let key_path   = cfg.get("key_path").and_then(|v| v.as_str())
        .ok_or_else(|| "file target missing key_path".to_string())?;
    let chain_path = cfg.get("chain_path").and_then(|v| v.as_str());
    let owner      = cfg.get("owner").and_then(|v| v.as_str());
    let mode_cert  = cfg.get("mode").and_then(|v| v.as_str()).unwrap_or("0644");
    let mode_key   = cfg.get("key_mode").and_then(|v| v.as_str()).unwrap_or("0600");

    let leaf = cert.cert_pem.as_deref().unwrap_or("");
    let chain = cert.chain_pem.as_deref().unwrap_or("");
    let key  = cert.key_pem.as_deref().unwrap_or("");
    let fullchain = format!("{leaf}\n{chain}");

    sudo_install_string(&fullchain, cert_path, mode_cert, owner).await?;
    sudo_install_string(key, key_path, mode_key, owner).await?;
    if let Some(p) = chain_path {
        sudo_install_string(chain, p, mode_cert, owner).await?;
    }
    Ok(())
}

/// Stage `body` to `/tmp/aifw_acme_export.tmp`, then `sudo install` it into
/// the destination with the given mode + optional owner. Mirrors the
/// pattern used by dns_blocklists::atomic_write — same sudoers entries
/// already permit it.
async fn sudo_install_string(
    body: &str,
    dest: &str,
    mode: &str,
    owner: Option<&str>,
) -> Result<(), String> {
    let basename = std::path::Path::new(dest)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("export");
    let tmp = format!("/tmp/aifw_acme_export_{basename}.tmp");

    if let Some(parent) = std::path::Path::new(dest).parent() {
        let _ = Command::new(SUDO)
            .args(["/bin/mkdir", "-p", parent.to_str().unwrap_or("")])
            .output().await;
    }

    tokio::fs::write(&tmp, body).await.map_err(|e| format!("stage tmp: {e}"))?;

    let mut args: Vec<String> = vec!["/usr/bin/install".into(), "-m".into(), mode.into()];
    if let Some(o) = owner {
        // install(1): -o user, -g group. Accept "user:group" by splitting.
        let mut parts = o.splitn(2, ':');
        let u = parts.next().unwrap_or("").to_string();
        let g = parts.next().map(|s| s.to_string());
        if !u.is_empty() {
            args.push("-o".into());
            args.push(u);
        }
        if let Some(g) = g {
            args.push("-g".into());
            args.push(g);
        }
    }
    args.push(tmp.clone());
    args.push(dest.to_string());

    let out = Command::new(SUDO).args(&args).output().await
        .map_err(|e| format!("spawn sudo install: {e}"))?;
    let _ = tokio::fs::remove_file(&tmp).await;
    if !out.status.success() {
        return Err(format!(
            "sudo install -> {dest}: {}",
            String::from_utf8_lossy(&out.stderr).trim(),
        ));
    }
    Ok(())
}

// ---- webhook --------------------------------------------------------------

async fn run_webhook(cert: &AcmeCert, cfg: &serde_json::Value) -> Result<(), String> {
    let url = cfg.get("url").and_then(|v| v.as_str())
        .ok_or_else(|| "webhook target missing url".to_string())?;
    let auth = cfg.get("auth_header").and_then(|v| v.as_str()).unwrap_or("");

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
    let reload_service = cfg.get("reload_service")
        .and_then(|v| v.as_str())
        .unwrap_or("aifw_api");
    let dir = "/usr/local/etc/aifw/tls";
    let leaf = cert.cert_pem.as_deref().unwrap_or("");
    let chain = cert.chain_pem.as_deref().unwrap_or("");
    let key  = cert.key_pem.as_deref().unwrap_or("");
    let fullchain = format!("{leaf}\n{chain}");

    sudo_install_string(&fullchain, &format!("{dir}/cert.pem"), "0644", Some("root:rdns")).await?;
    sudo_install_string(key,        &format!("{dir}/key.pem"),  "0640", Some("root:rdns")).await?;

    // Reload the configured service so it picks up the new cert.
    let _ = Command::new(SUDO)
        .args(["/usr/sbin/service", reload_service, "restart"])
        .output().await;
    Ok(())
}
