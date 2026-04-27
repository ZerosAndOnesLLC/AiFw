//! AiFw self-updater — checks GitHub Releases for new versions and installs updates.
//!
//! Component lists are driven by `freebsd/manifest.json` (single source of truth).
//! The manifest is embedded at compile time so no runtime file dependency.

use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{info, warn};

const GITHUB_API_URL: &str = "https://api.github.com/repos/ZerosAndOnesLLC/AiFw/releases/latest";
const VERSION_FILE: &str = "/usr/local/share/aifw/version";
const BACKUP_DIR: &str = "/usr/local/share/aifw/backup";
const BIN_DIR: &str = "/usr/local/sbin";
const UI_DIR: &str = "/usr/local/share/aifw/ui";

/// Manifest embedded at compile time from freebsd/manifest.json.
const MANIFEST_JSON: &str = include_str!("../../freebsd/manifest.json");

#[derive(Deserialize)]
struct Manifest {
    binaries: ManifestBinaries,
    external_repos: Vec<ExternalRepo>,
    rc_scripts: Vec<String>,
    #[allow(dead_code)]
    sbin_scripts: Vec<String>,
    directories: Vec<String>,
}

#[derive(Deserialize)]
struct ManifestBinaries {
    local: Vec<String>,
}

#[derive(Deserialize)]
struct ExternalRepo {
    binaries: Vec<String>,
    #[allow(dead_code)]
    name: String,
    #[allow(dead_code)]
    repo: String,
}

fn load_manifest() -> Manifest {
    serde_json::from_str(MANIFEST_JSON).expect("freebsd/manifest.json is invalid")
}

/// All binary names from manifest (local + external).
fn all_binaries() -> Vec<String> {
    let m = load_manifest();
    let mut bins = m.binaries.local;
    for repo in &m.external_repos {
        bins.extend(repo.binaries.iter().cloned());
    }
    bins
}

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
    let checksum_url = info
        .checksum_url
        .as_deref()
        .ok_or(UpdaterError::NoTarball)?;

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

    // Install binaries. We iterate the tarball's bin/ directory rather than
    // the compiled-in `all_binaries()` list — that way a release that adds a
    // new binary (e.g. aifw-ids in 5.76) doesn't require the *running*
    // updater to know about it. The tarball is the source of truth.
    info!("Installing binaries...");
    let bin_src = update_dir.join("bin");
    let mut installed = 0u32;
    if bin_src.exists() {
        let mut entries = tokio::fs::read_dir(&bin_src)
            .await
            .map_err(|e| UpdaterError::Install(format!("read bin dir: {}", e)))?;
        while let Some(entry) = entries
            .next_entry()
            .await
            .map_err(|e| UpdaterError::Install(e.to_string()))?
        {
            if !entry.file_type().await.map(|t| t.is_file()).unwrap_or(false) {
                continue;
            }
            let src = entry.path();
            let name = match src.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            let dst = format!("{}/{}", BIN_DIR, name);
            let output = Command::new("/usr/local/bin/sudo")
                .args(["/usr/bin/install", "-m", "755", src.to_str().unwrap(), &dst])
                .output()
                .await
                .map_err(|e| UpdaterError::Install(format!("Failed to install {}: {}", name, e)))?;
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                return Err(UpdaterError::Install(format!(
                    "Failed to install {}: {}",
                    name, stderr
                )));
            }
            installed += 1;
        }
    }
    if installed == 0 {
        return Err(UpdaterError::Install(
            "No binaries found in update tarball".to_string(),
        ));
    }
    info!(count = installed, "binaries installed");

    // Install UI
    let ui_src = update_dir.join("ui");
    if ui_src.exists() {
        info!("Installing UI...");
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["/bin/rm", "-rf", UI_DIR])
            .output()
            .await;
        let output = Command::new("/usr/local/bin/sudo")
            .args(["/bin/cp", "-a", ui_src.to_str().unwrap(), UI_DIR])
            .output()
            .await
            .map_err(|e| UpdaterError::Install(format!("Failed to install UI: {}", e)))?;
        if !output.status.success() {
            return Err(UpdaterError::Install(format!(
                "Failed to install UI: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
    }

    // Ensure wg is in sudoers for aifw user (older installs may be missing it)
    {
        let sudoers_path = "/usr/local/etc/sudoers.d/aifw";
        if let Ok(content) = tokio::fs::read_to_string(sudoers_path).await
            && !content.contains("/usr/bin/wg")
        {
            let patched = format!("{content}aifw ALL=(ALL) NOPASSWD: /usr/bin/wg *\n");
            let _ = tokio::fs::write(sudoers_path, patched).await;
            info!("Added wg to sudoers for aifw user");
        }
    }

    // Ensure required packages are installed (older installs may be missing curl)
    for pkg in &["curl"] {
        let check = Command::new("pkg").args(["info", "-q", pkg]).output().await;
        let installed = check.map(|o| o.status.success()).unwrap_or(false);
        if !installed {
            info!(package = pkg, "Installing missing dependency");
            let _ = Command::new("/usr/local/bin/sudo")
                .args(["pkg", "install", "-y", pkg])
                .output()
                .await;
        }
    }

    let manifest = load_manifest();

    // Install rc.d scripts. Same reasoning as binaries above: iterate the
    // tarball directory rather than the compiled-in manifest.rc_scripts list,
    // so a release that ships a new rc.d (e.g. aifw_ids in 5.76) gets
    // installed even when the running updater predates it.
    let rcd_src = update_dir.join("rc.d");
    if rcd_src.exists() {
        info!("Installing rc.d scripts...");
        if let Ok(mut entries) = tokio::fs::read_dir(&rcd_src).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if !entry.file_type().await.map(|t| t.is_file()).unwrap_or(false) {
                    continue;
                }
                let src = entry.path();
                let name = match src.file_name().and_then(|n| n.to_str()) {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                let dst = format!("/usr/local/etc/rc.d/{}", name);
                let _ = Command::new("/usr/local/bin/sudo")
                    .args(["/usr/bin/install", "-m", "755", src.to_str().unwrap(), &dst])
                    .output()
                    .await;
            }
        }
    }

    // Install sbin scripts (console, installer). Iterate tarball/sbin/ for
    // the same reason as above.
    let sbin_src = update_dir.join("sbin");
    if sbin_src.exists() {
        info!("Installing utility scripts...");
        if let Ok(mut entries) = tokio::fs::read_dir(&sbin_src).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if !entry.file_type().await.map(|t| t.is_file()).unwrap_or(false) {
                    continue;
                }
                let src = entry.path();
                let name = match src.file_name().and_then(|n| n.to_str()) {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                let dst = format!("{}/{}", BIN_DIR, name);
                let _ = Command::new("/usr/local/bin/sudo")
                    .args(["/usr/bin/install", "-m", "755", src.to_str().unwrap(), &dst])
                    .output()
                    .await;
            }
        }
    }


    // Ensure required directories exist (new services may need them)
    for dir in &manifest.directories {
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["/bin/mkdir", "-p", dir])
            .output()
            .await;
    }

    // Update version file
    let ver_src = update_dir.join("version");
    if ver_src.exists() {
        let output = Command::new("/usr/local/bin/sudo")
            .args(["/bin/cp", ver_src.to_str().unwrap(), VERSION_FILE])
            .output()
            .await
            .map_err(|e| UpdaterError::Install(format!("Failed to update version file: {}", e)))?;
        if !output.status.success() {
            warn!(
                "Failed to update version file: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    // Strip stale AiFw version from MOTD template. Idempotent and respects
    // the marker file that `system_apply::apply_banner` sets when the admin
    // edits MOTD via the UI.
    #[cfg(target_os = "freebsd")]
    {
        let _ = Command::new("/usr/local/libexec/aifw-motd-cleanup.sh")
            .output()
            .await;
    }

    // One-shot migration: enforce password-protected console login on
    // existing installs that were shipped with autologin. Idempotent.
    #[cfg(target_os = "freebsd")]
    {
        let _ = Command::new("/usr/local/libexec/aifw-login-migrate.sh")
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

/// Services that may have had their rc.d script replaced by an update and
/// therefore need a restart for the new script to take effect. Order
/// matters for aifw_api (last) so HTTP stays up as long as possible.
const RESTARTABLE_SERVICES: &[&str] = &[
    "rdns",
    "rdhcpd",
    "rtime",
    "trafficcop",
    "aifw_daemon",
    // aifw_ids must be restarted before aifw_api — aifw_api REQUIREs aifw_ids,
    // and the API connects to the IDS IPC socket on startup.
    "aifw_ids",
    "aifw_api",
];

/// Restart AiFw services (spawns background task, returns immediately).
///
/// Every companion service is restarted, not just aifw_daemon/aifw_api,
/// because rc.d script updates arrive via the update tarball and only
/// take effect on service restart. Skipping companions has burned us
/// before (e.g. the rDNS control-socket chown fix landing in rc.d but
/// the running daemon ignoring it until the next reboot).
pub async fn restart_services() {
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        for svc in RESTARTABLE_SERVICES {
            let _ = Command::new("/usr/local/bin/sudo")
                .args(["/usr/sbin/service", svc, "restart"])
                .output()
                .await;
        }
    });
}

/// Restart AiFw services synchronously (blocks until restart completes, use from CLI).
pub async fn restart_services_sync() {
    for svc in RESTARTABLE_SERVICES {
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["service", svc, "restart"])
            .output()
            .await;
    }
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
    for bin in &all_binaries() {
        let src = format!("{}/bin/{}", BACKUP_DIR, bin);
        if std::path::Path::new(&src).exists() {
            let dst = format!("{}/{}", BIN_DIR, bin);
            let _ = Command::new("/usr/local/bin/sudo")
                .args(["/usr/bin/install", "-m", "755", &src, &dst])
                .output()
                .await;
        }
    }

    // Restore rc.d scripts
    let manifest = load_manifest();
    for script in &manifest.rc_scripts {
        let src = format!("{}/rc.d/{}", BACKUP_DIR, script);
        if std::path::Path::new(&src).exists() {
            let dst = format!("/usr/local/etc/rc.d/{}", script);
            let _ = Command::new("/usr/local/bin/sudo")
                .args(["/usr/bin/install", "-m", "755", &src, &dst])
                .output()
                .await;
        }
    }

    // Restore UI
    let backup_ui = format!("{}/ui", BACKUP_DIR);
    if std::path::Path::new(&backup_ui).exists() {
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["/bin/rm", "-rf", UI_DIR])
            .output()
            .await;
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["/bin/cp", "-a", &backup_ui, UI_DIR])
            .output()
            .await;
    }

    // Restore version file
    let _ = Command::new("/usr/local/bin/sudo")
        .args(["/bin/cp", &backup_ver, VERSION_FILE])
        .output()
        .await;

    info!("Rolled back to v{}", version);
    Ok(format!("Rolled back to v{}", version))
}

// --- Private helpers ---

async fn backup_current() -> Result<(), UpdaterError> {
    let _ = Command::new("/usr/local/bin/sudo")
        .args(["/bin/rm", "-rf", BACKUP_DIR])
        .output()
        .await;
    let _ = Command::new("/usr/local/bin/sudo")
        .args([
            "/bin/mkdir",
            "-p",
            &format!("{}/bin", BACKUP_DIR),
            &format!("{}/rc.d", BACKUP_DIR),
        ])
        .output()
        .await;

    for bin in &all_binaries() {
        let src = format!("{}/{}", BIN_DIR, bin);
        if std::path::Path::new(&src).exists() {
            let _ = Command::new("/usr/local/bin/sudo")
                .args([
                    "/bin/cp",
                    "-p",
                    &src,
                    &format!("{}/bin/{}", BACKUP_DIR, bin),
                ])
                .output()
                .await;
        }
    }

    // Backup rc.d scripts
    let manifest = load_manifest();
    for script in &manifest.rc_scripts {
        let src = format!("/usr/local/etc/rc.d/{}", script);
        if std::path::Path::new(&src).exists() {
            let _ = Command::new("/usr/local/bin/sudo")
                .args([
                    "/bin/cp",
                    "-p",
                    &src,
                    &format!("{}/rc.d/{}", BACKUP_DIR, script),
                ])
                .output()
                .await;
        }
    }

    if std::path::Path::new(UI_DIR).exists() {
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["/bin/cp", "-a", UI_DIR, &format!("{}/ui", BACKUP_DIR)])
            .output()
            .await;
    }

    if std::path::Path::new(VERSION_FILE).exists() {
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["/bin/cp", VERSION_FILE, &format!("{}/version", BACKUP_DIR)])
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
    let parse = |v: &str| -> Vec<u32> { v.split('.').filter_map(|s| s.parse().ok()).collect() };
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

async fn http_download(url: &str, dest: &str) -> Result<(), UpdaterError> {
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

async fn verify_sha256(file: &str, expected: &str) -> Result<bool, UpdaterError> {
    // Try sha256 -q (FreeBSD)
    if let Ok(o) = Command::new("sha256").args(["-q", file]).output().await
        && o.status.success()
    {
        let hash = String::from_utf8_lossy(&o.stdout).trim().to_string();
        return Ok(hash == expected);
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
