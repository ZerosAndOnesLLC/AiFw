//! AiFw self-updater — checks GitHub Releases for new versions and installs updates.

use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{info, warn};

const GITHUB_API_URL: &str =
    "https://api.github.com/repos/ZerosAndOnesLLC/AiFw/releases/latest";
const VERSION_FILE: &str = "/usr/local/share/aifw/version";
const BACKUP_DIR: &str = "/usr/local/share/aifw/backup";
const BIN_DIR: &str = "/usr/local/sbin";
const UI_DIR: &str = "/usr/local/share/aifw/ui";
const BINARIES: &[&str] = &["aifw", "aifw-daemon", "aifw-api", "aifw-tui", "aifw-setup"];

#[derive(Debug, thiserror::Error)]
pub enum UpdaterError {
    #[error("HTTP request failed: {0}")]
    Http(String),
    #[error("JSON parse error: {0}")]
    Json(String),
    #[error("Download failed: {0}")]
    Download(String),
    #[error("Checksum verification failed")]
    Checksum,
    #[error("Installation failed: {0}")]
    Install(String),
    #[error("No backup available")]
    NoBackup,
    #[error("No update tarball found in release")]
    NoTarball,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AifwUpdateInfo {
    pub current_version: String,
    pub latest_version: String,
    pub update_available: bool,
    pub release_notes: String,
    pub published_at: String,
    pub tarball_url: Option<String>,
    pub checksum_url: Option<String>,
    pub has_backup: bool,
    pub backup_version: Option<String>,
}

/// Read the current installed AiFw version.
pub async fn get_current_version() -> String {
    tokio::fs::read_to_string(VERSION_FILE)
        .await
        .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string())
        .trim()
        .to_string()
}

/// Check GitHub Releases for a newer AiFw version.
pub async fn check_for_update() -> Result<AifwUpdateInfo, UpdaterError> {
    let current = get_current_version().await;
    let json = http_get(GITHUB_API_URL).await?;
    let release: serde_json::Value =
        serde_json::from_str(&json).map_err(|e| UpdaterError::Json(e.to_string()))?;

    let tag = release["tag_name"].as_str().unwrap_or("v0.0.0");
    let latest = tag.strip_prefix('v').unwrap_or(tag);
    let notes = release["body"].as_str().unwrap_or("").to_string();
    let published = release["published_at"].as_str().unwrap_or("").to_string();

    let assets = release["assets"].as_array();
    let mut tarball_url = None;
    let mut checksum_url = None;

    if let Some(assets) = assets {
        for asset in assets {
            let name = asset["name"].as_str().unwrap_or("");
            let url = asset["browser_download_url"].as_str().unwrap_or("");
            if name.starts_with("aifw-update-")
                && name.ends_with(".tar.xz")
                && !name.ends_with(".sha256")
            {
                tarball_url = Some(url.to_string());
            } else if name.starts_with("aifw-update-") && name.ends_with(".tar.xz.sha256") {
                checksum_url = Some(url.to_string());
            }
        }
    }

    let (has_backup, backup_version) = get_backup_info().await;

    Ok(AifwUpdateInfo {
        update_available: version_newer(&current, latest),
        current_version: current,
        latest_version: latest.to_string(),
        release_notes: notes,
        published_at: published,
        tarball_url,
        checksum_url,
        has_backup,
        backup_version,
    })
}

/// Download, verify, and install an AiFw update.
pub async fn download_and_install(info: &AifwUpdateInfo) -> Result<String, UpdaterError> {
    let tarball_url = info.tarball_url.as_deref().ok_or(UpdaterError::NoTarball)?;
    let checksum_url = info.checksum_url.as_deref().ok_or(UpdaterError::NoTarball)?;

    let tmp_dir = "/tmp/aifw-update";
    let tarball_path = format!("{}/update.tar.xz", tmp_dir);
    let checksum_path = format!("{}/update.tar.xz.sha256", tmp_dir);

    // Clean and create temp dir
    let _ = tokio::fs::remove_dir_all(tmp_dir).await;
    tokio::fs::create_dir_all(tmp_dir)
        .await
        .map_err(|e| UpdaterError::Install(format!("Failed to create temp dir: {}", e)))?;

    // Download tarball and checksum
    info!("Downloading AiFw update v{}...", info.latest_version);
    http_download(tarball_url, &tarball_path).await?;
    http_download(checksum_url, &checksum_path).await?;

    // Verify checksum
    info!("Verifying checksum...");
    let expected = tokio::fs::read_to_string(&checksum_path)
        .await
        .map_err(|e| UpdaterError::Download(format!("Failed to read checksum: {}", e)))?;
    let expected_hash = extract_hash(&expected);
    if !verify_sha256(&tarball_path, &expected_hash).await? {
        let _ = tokio::fs::remove_dir_all(tmp_dir).await;
        return Err(UpdaterError::Checksum);
    }

    // Backup current installation
    info!("Backing up current installation...");
    backup_current().await?;

    // Extract tarball
    info!("Extracting update...");
    let extract_dir = format!("{}/extracted", tmp_dir);
    tokio::fs::create_dir_all(&extract_dir)
        .await
        .map_err(|e| UpdaterError::Install(format!("Failed to create extract dir: {}", e)))?;

    let output = Command::new("tar")
        .args(["xf", &tarball_path, "-C", &extract_dir])
        .output()
        .await
        .map_err(|e| UpdaterError::Install(format!("tar failed: {}", e)))?;

    if !output.status.success() {
        return Err(UpdaterError::Install(format!(
            "tar extract failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    // Find the extracted directory (aifw-update-VERSION-amd64/)
    let mut entries = tokio::fs::read_dir(&extract_dir)
        .await
        .map_err(|e| UpdaterError::Install(e.to_string()))?;
    let update_dir = if let Some(entry) = entries
        .next_entry()
        .await
        .map_err(|e| UpdaterError::Install(e.to_string()))?
    {
        entry.path()
    } else {
        return Err(UpdaterError::Install("Empty tarball".to_string()));
    };

    // Install binaries
    info!("Installing binaries...");
    let bin_src = update_dir.join("bin");
    for bin in BINARIES {
        let src = bin_src.join(bin);
        if src.exists() {
            let dst = format!("{}/{}", BIN_DIR, bin);
            let output = Command::new("sudo")
                .args(["install", "-m", "755", src.to_str().unwrap(), &dst])
                .output()
                .await
                .map_err(|e| UpdaterError::Install(format!("Failed to install {}: {}", bin, e)))?;
            if !output.status.success() {
                warn!(
                    "Failed to install {}: {}",
                    bin,
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }

    // Install UI
    let ui_src = update_dir.join("ui");
    if ui_src.exists() {
        info!("Installing UI...");
        let _ = Command::new("sudo")
            .args(["rm", "-rf", UI_DIR])
            .output()
            .await;
        let _ = Command::new("sudo")
            .args(["cp", "-a", ui_src.to_str().unwrap(), UI_DIR])
            .output()
            .await;
    }

    // Update version file
    let ver_src = update_dir.join("version");
    if ver_src.exists() {
        let _ = Command::new("sudo")
            .args(["cp", ver_src.to_str().unwrap(), VERSION_FILE])
            .output()
            .await;
    }

    // Cleanup temp dir
    let _ = tokio::fs::remove_dir_all(tmp_dir).await;

    info!("AiFw updated to v{}", info.latest_version);
    Ok(format!(
        "AiFw updated from v{} to v{}",
        info.current_version, info.latest_version
    ))
}

/// Restart AiFw services (spawns background process, returns immediately).
pub async fn restart_services() {
    let _ = Command::new("sudo")
        .args([
            "sh",
            "-c",
            "(sleep 2; service aifw_daemon restart; service aifw_api restart) &",
        ])
        .output()
        .await;
}

/// Restart AiFw services synchronously (blocks until restart completes, use from CLI).
pub async fn restart_services_sync() {
    let _ = Command::new("sudo")
        .args(["service", "aifw_daemon", "restart"])
        .output()
        .await;
    let _ = Command::new("sudo")
        .args(["service", "aifw_api", "restart"])
        .output()
        .await;
}

/// Rollback to the previous version from backup.
pub async fn rollback() -> Result<String, UpdaterError> {
    let backup_ver = format!("{}/version", BACKUP_DIR);
    if !std::path::Path::new(&backup_ver).exists() {
        return Err(UpdaterError::NoBackup);
    }

    let version = tokio::fs::read_to_string(&backup_ver)
        .await
        .map_err(|_| UpdaterError::NoBackup)?
        .trim()
        .to_string();

    info!("Rolling back to v{}...", version);

    // Restore binaries
    for bin in BINARIES {
        let src = format!("{}/bin/{}", BACKUP_DIR, bin);
        if std::path::Path::new(&src).exists() {
            let dst = format!("{}/{}", BIN_DIR, bin);
            let _ = Command::new("sudo")
                .args(["install", "-m", "755", &src, &dst])
                .output()
                .await;
        }
    }

    // Restore UI
    let backup_ui = format!("{}/ui", BACKUP_DIR);
    if std::path::Path::new(&backup_ui).exists() {
        let _ = Command::new("sudo")
            .args(["rm", "-rf", UI_DIR])
            .output()
            .await;
        let _ = Command::new("sudo")
            .args(["cp", "-a", &backup_ui, UI_DIR])
            .output()
            .await;
    }

    // Restore version file
    let _ = Command::new("sudo")
        .args(["cp", &backup_ver, VERSION_FILE])
        .output()
        .await;

    info!("Rolled back to v{}", version);
    Ok(format!("Rolled back to v{}", version))
}

// --- Private helpers ---

async fn backup_current() -> Result<(), UpdaterError> {
    let _ = Command::new("sudo")
        .args(["rm", "-rf", BACKUP_DIR])
        .output()
        .await;
    let _ = Command::new("sudo")
        .args(["mkdir", "-p", &format!("{}/bin", BACKUP_DIR)])
        .output()
        .await;

    for bin in BINARIES {
        let src = format!("{}/{}", BIN_DIR, bin);
        if std::path::Path::new(&src).exists() {
            let _ = Command::new("sudo")
                .args(["cp", "-p", &src, &format!("{}/bin/{}", BACKUP_DIR, bin)])
                .output()
                .await;
        }
    }

    if std::path::Path::new(UI_DIR).exists() {
        let _ = Command::new("sudo")
            .args(["cp", "-a", UI_DIR, &format!("{}/ui", BACKUP_DIR)])
            .output()
            .await;
    }

    if std::path::Path::new(VERSION_FILE).exists() {
        let _ = Command::new("sudo")
            .args(["cp", VERSION_FILE, &format!("{}/version", BACKUP_DIR)])
            .output()
            .await;
    }

    Ok(())
}

async fn get_backup_info() -> (bool, Option<String>) {
    let ver_path = format!("{}/version", BACKUP_DIR);
    match tokio::fs::read_to_string(&ver_path).await {
        Ok(v) => (true, Some(v.trim().to_string())),
        Err(_) => (false, None),
    }
}

fn version_newer(current: &str, latest: &str) -> bool {
    let parse = |v: &str| -> Vec<u32> {
        v.split('.').filter_map(|s| s.parse().ok()).collect()
    };
    parse(latest) > parse(current)
}

fn extract_hash(checksum_content: &str) -> String {
    let line = checksum_content.trim();
    // Format: "SHA256 (file) = hash" (FreeBSD sha256)
    if let Some(pos) = line.rfind("= ") {
        return line[pos + 2..].trim().to_string();
    }
    // Format: "hash  filename" or "hash filename" (sha256sum)
    line.split_whitespace().next().unwrap_or("").to_string()
}

async fn http_get(url: &str) -> Result<String, UpdaterError> {
    // Try fetch (FreeBSD) first, fall back to curl
    if let Ok(o) = Command::new("fetch")
        .args(["-qo", "-", url])
        .output()
        .await
    {
        if o.status.success() {
            return Ok(String::from_utf8_lossy(&o.stdout).to_string());
        }
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

async fn http_download(url: &str, dest: &str) -> Result<(), UpdaterError> {
    if let Ok(o) = Command::new("fetch")
        .args(["-qo", dest, url])
        .output()
        .await
    {
        if o.status.success() {
            return Ok(());
        }
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

async fn verify_sha256(file: &str, expected: &str) -> Result<bool, UpdaterError> {
    // Try sha256 -q (FreeBSD)
    if let Ok(o) = Command::new("sha256").args(["-q", file]).output().await {
        if o.status.success() {
            let hash = String::from_utf8_lossy(&o.stdout).trim().to_string();
            return Ok(hash == expected);
        }
    }

    // Fall back to sha256sum (Linux)
    let output = Command::new("sha256sum")
        .arg(file)
        .output()
        .await
        .map_err(|e| UpdaterError::Download(format!("sha256 check failed: {}", e)))?;

    let hash = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string();

    Ok(hash == expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_newer() {
        assert!(version_newer("5.3.3", "5.3.4"));
        assert!(version_newer("5.3.3", "5.4.0"));
        assert!(version_newer("5.3.3", "6.0.0"));
        assert!(!version_newer("5.3.3", "5.3.3"));
        assert!(!version_newer("5.3.4", "5.3.3"));
    }

    #[test]
    fn test_extract_hash_freebsd() {
        let input = "SHA256 (aifw-update-5.3.4-amd64.tar.xz) = abc123def456";
        assert_eq!(extract_hash(input), "abc123def456");
    }

    #[test]
    fn test_extract_hash_linux() {
        let input = "abc123def456  aifw-update-5.3.4-amd64.tar.xz";
        assert_eq!(extract_hash(input), "abc123def456");
    }

    #[test]
    fn test_extract_hash_plain() {
        let input = "abc123def456";
        assert_eq!(extract_hash(input), "abc123def456");
    }
}
