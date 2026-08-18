//! HTTP helpers for GitHub release metadata and asset download.

use tokio::process::Command;

use super::*;

pub(super) fn release_asset_urls(
    release: &serde_json::Value,
) -> (Option<String>, Option<String>, Option<String>) {
    let mut tarball = None;
    let mut checksum = None;
    let mut signature = None;
    if let Some(assets) = release["assets"].as_array() {
        for asset in assets {
            let name = asset["name"].as_str().unwrap_or("");
            let url = asset["browser_download_url"].as_str().unwrap_or("");
            if name.starts_with("aifw-update-") && name.ends_with(".tar.xz") {
                tarball = Some(url.to_string());
            } else if name.starts_with("aifw-update-") && name.ends_with(".tar.xz.sha256.minisig") {
                signature = Some(url.to_string());
            } else if name.starts_with("aifw-update-") && name.ends_with(".tar.xz.sha256") {
                checksum = Some(url.to_string());
            }
        }
    }
    (tarball, checksum, signature)
}

pub(super) async fn http_get(url: &str) -> Result<String, UpdaterError> {
    // Try fetch (FreeBSD) first, fall back to curl
    if let Ok(o) = Command::new("fetch").args(["-qo", "-", url]).output().await
        && o.status.success()
    {
        return Ok(String::from_utf8_lossy(&o.stdout).to_string());
    }

    let output = Command::new("curl")
        .args(["-sL", "-H", "User-Agent: AiFw-Updater", url])
        .output()
        .await
        .map_err(|e| UpdaterError::Http(e.to_string()))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err(UpdaterError::Http(format!(
            "HTTP request failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}

pub(super) async fn http_download(url: &str, dest: &str) -> Result<(), UpdaterError> {
    if let Ok(o) = Command::new("fetch")
        .args(["-qo", dest, url])
        .output()
        .await
        && o.status.success()
    {
        return Ok(());
    }

    let output = Command::new("curl")
        .args(["-sL", "-H", "User-Agent: AiFw-Updater", "-o", dest, url])
        .output()
        .await
        .map_err(|e| UpdaterError::Download(e.to_string()))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(UpdaterError::Download(format!(
            "Download failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )))
    }
}
