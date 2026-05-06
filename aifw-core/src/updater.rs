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

/// Restart-driver and watchdog scripts embedded into the binary at compile
/// time. Written to /usr/local/libexec/ on aifw-api startup so a transitional
/// upgrade — where the running updater predates `libexec/` iteration in
/// the install path — can still self-bootstrap. Without this, an old
/// updater installs new aifw-api binaries but leaves the supporting
/// scripts missing, and the next restart_services call falls back to the
/// fragile in-process loop. Embedding closes that loop.
const EMBEDDED_RESTART_SH: &str =
    include_str!("../../freebsd/overlay/usr/local/libexec/aifw-restart.sh");
const EMBEDDED_WATCHDOG_SH: &str =
    include_str!("../../freebsd/overlay/usr/local/libexec/aifw-watchdog.sh");

#[derive(Deserialize)]
struct Manifest {
    binaries: ManifestBinaries,
    external_repos: Vec<ExternalRepo>,
    rc_scripts: Vec<String>,
    #[allow(dead_code)]
    sbin_scripts: Vec<String>,
    #[allow(dead_code)]
    #[serde(default)]
    libexec_scripts: Vec<String>,
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
    /// On-disk version differs from the running binary's compiled-in
    /// version — install completed but services have not been restarted.
    /// Drives the "Restart pending" banner and survives page reloads.
    #[serde(default)]
    pub restart_pending: bool,
    /// Version actually executing in the current `aifw-api` process. The
    /// UI compares this to `current_version` to know what the restart
    /// will activate.
    #[serde(default)]
    pub running_version: String,
    /// True when the release notes contain `[reboot-recommended]`. The
    /// UI surfaces a Reboot button as the primary action when this is
    /// set. Reserved for releases that change service supervision,
    /// install rc.d-managed services, or otherwise touch state that a
    /// service-only restart can't reliably refresh.
    #[serde(default)]
    pub reboot_recommended: bool,
    /// Free-form line extracted from the release notes after the
    /// `[reboot-recommended]` marker, if present. Shown in the modal so
    /// the operator knows *why* reboot was recommended.
    #[serde(default)]
    pub reboot_reason: Option<String>,
}

/// Read the current installed AiFw version.
pub async fn get_current_version() -> String {
    tokio::fs::read_to_string(VERSION_FILE)
        .await
        .unwrap_or_else(|_| env!("CARGO_PKG_VERSION").to_string())
        .trim()
        .to_string()
}

/// Version compiled into the running binary. Used together with
/// `get_current_version()` to detect a pending restart: when the on-disk
/// version (just written by an update tarball install) differs from this
/// one, the new binary is on disk but not yet executing.
pub fn running_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// True when the on-disk version differs from the running binary's
/// compiled-in version. Drives the "restart pending" UI banner.
pub async fn restart_pending() -> bool {
    let on_disk = match tokio::fs::read_to_string(VERSION_FILE).await {
        Ok(s) => s.trim().to_string(),
        Err(_) => return false,
    };
    !on_disk.is_empty() && on_disk != running_version()
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
    let restart_pending = restart_pending().await;
    let (reboot_recommended, reboot_reason) = parse_reboot_hint(&notes);

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
        restart_pending,
        running_version: running_version().to_string(),
        reboot_recommended,
        reboot_reason,
    })
}

/// Look for `[reboot-recommended]` in release notes. If present, the
/// UI/CLI surface the reboot path as the primary action. Anything on the
/// same line after the marker becomes the human-readable reason.
///
/// Example release-note line:
///   `[reboot-recommended] changes service-supervision rc.d scripts`
fn parse_reboot_hint(notes: &str) -> (bool, Option<String>) {
    const MARKER: &str = "[reboot-recommended]";
    for line in notes.lines() {
        if let Some(idx) = line.find(MARKER) {
            let tail = line[idx + MARKER.len()..].trim();
            let reason = if tail.is_empty() {
                None
            } else {
                Some(tail.to_string())
            };
            return (true, reason);
        }
    }
    (false, None)
}

/// Install an AiFw update from a local tarball path.
///
/// This is the shared install primitive used by both `download_and_install`
/// (which downloads first, then delegates here) and the API's
/// `install-local` endpoint (which receives an uploaded tarball and
/// delegates here directly).
///
/// `expected_hash` — if `Some`, the tarball's sha256 is verified before
/// extraction.  Pass `None` only when the caller has already verified the
/// hash or when `--skip-checksum` was explicitly requested.
pub async fn install_from_path(
    tarball_path: &std::path::Path,
    expected_hash: Option<&str>,
) -> Result<String, UpdaterError> {
    let tarball_str = tarball_path
        .to_str()
        .ok_or_else(|| UpdaterError::Install("tarball path is not valid UTF-8".to_string()))?;

    // Optionally verify checksum
    if let Some(hash) = expected_hash {
        info!("Verifying checksum...");
        if !verify_sha256(tarball_str, hash).await? {
            return Err(UpdaterError::Checksum);
        }
    }

    // Backup current installation
    info!("Backing up current installation...");
    backup_current().await?;

    // Extract tarball into a sibling directory
    let extract_dir = {
        let parent = tarball_path
            .parent()
            .unwrap_or(std::path::Path::new("/tmp"));
        parent.join("extracted")
    };
    tokio::fs::create_dir_all(&extract_dir)
        .await
        .map_err(|e| UpdaterError::Install(format!("Failed to create extract dir: {}", e)))?;

    let output = Command::new("tar")
        .args(["xf", tarball_str, "-C", extract_dir.to_str().unwrap()])
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

    // Ensure /usr/sbin/daemon is in sudoers. Without it, the detached
    // restart driver in restart_services() spawns sudo, sudo refuses
    // for lack of NOPASSWD, and we silently skip the bounce — leaving
    // the appliance with on-disk version != running version (the
    // "Restart pending" loop). Same pattern as the wg migration above.
    ensure_sudoers_daemon().await;

    // Ensure required packages are installed (older installs may be missing curl)
    for pkg in &["curl"] {
        let check = Command::new("pkg").args(["info", "-q", pkg]).output().await;
        let pkg_installed = check.map(|o| o.status.success()).unwrap_or(false);
        if !pkg_installed {
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

    // Install libexec scripts (restart driver, watchdog loop, motd
    // cleanup, login migrate). Same iterate-the-tarball pattern: a
    // release that adds a new libexec script (e.g. aifw-restart.sh in
    // 5.79.0) lands even when the running updater predates it.
    let libexec_src = update_dir.join("libexec");
    if libexec_src.exists() {
        info!("Installing libexec scripts...");
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["/bin/mkdir", "-p", "/usr/local/libexec"])
            .output()
            .await;
        if let Ok(mut entries) = tokio::fs::read_dir(&libexec_src).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if !entry.file_type().await.map(|t| t.is_file()).unwrap_or(false) {
                    continue;
                }
                let src = entry.path();
                let name = match src.file_name().and_then(|n| n.to_str()) {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                let dst = format!("/usr/local/libexec/{}", name);
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

    // Read the installed version from the tarball's version file
    let installed_version = {
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
            tokio::fs::read_to_string(&ver_src)
                .await
                .unwrap_or_default()
                .trim()
                .to_string()
        } else {
            String::new()
        }
    };

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

    // Cleanup extract dir
    let _ = tokio::fs::remove_dir_all(&extract_dir).await;

    let version_display = if installed_version.is_empty() {
        "unknown".to_string()
    } else {
        installed_version.clone()
    };
    info!(version = %version_display, "AiFw install_from_path completed");
    Ok(version_display)
}

/// Download, verify, and install an AiFw update.
pub async fn download_and_install(info: &AifwUpdateInfo) -> Result<String, UpdaterError> {
    let tarball_url = info.tarball_url.as_deref().ok_or(UpdaterError::NoTarball)?;
    let checksum_url = info
        .checksum_url
        .as_deref()
        .ok_or(UpdaterError::NoTarball)?;

    let tmp_dir = "/tmp/aifw-update";
    let tarball_path = std::path::PathBuf::from(format!("{}/update.tar.xz", tmp_dir));
    let checksum_path = format!("{}/update.tar.xz.sha256", tmp_dir);

    // Clean and create temp dir
    let _ = tokio::fs::remove_dir_all(tmp_dir).await;
    tokio::fs::create_dir_all(tmp_dir)
        .await
        .map_err(|e| UpdaterError::Install(format!("Failed to create temp dir: {}", e)))?;

    // Download tarball and checksum
    info!("Downloading AiFw update v{}...", info.latest_version);
    http_download(tarball_url, tarball_path.to_str().unwrap()).await?;
    http_download(checksum_url, &checksum_path).await?;

    // Read and parse the expected hash from the downloaded checksum file
    let expected = tokio::fs::read_to_string(&checksum_path)
        .await
        .map_err(|e| UpdaterError::Download(format!("Failed to read checksum: {}", e)))?;
    let expected_hash = extract_hash(&expected);

    // Delegate to the shared install primitive (verifies hash, extracts, installs)
    let version = install_from_path(&tarball_path, Some(&expected_hash)).await?;

    // Cleanup temp dir
    let _ = tokio::fs::remove_dir_all(tmp_dir).await;

    let new_ver = if version.is_empty() {
        info.latest_version.clone()
    } else {
        version
    };
    info!(version = %new_ver, "AiFw updated");
    Ok(format!(
        "AiFw updated from v{} to v{}",
        info.current_version, new_ver
    ))
}

/// Services that may have had their rc.d script replaced by an update and
/// therefore need a restart for the new script to take effect. Order
/// matters for aifw_api (last) so HTTP stays up as long as possible.
/// Used by the synchronous CLI path; the API path delegates to
/// /usr/local/libexec/aifw-restart.sh which keeps its own ordering in
/// sync with this list.
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
    // Watchdog last so it doesn't observe transient down-states during
    // the bounce window and redundantly try to start things.
    "aifw_watchdog",
];

const RESTART_SCRIPT: &str = "/usr/local/libexec/aifw-restart.sh";

/// Services we own. `aifw_firstboot` is excluded — it's a one-shot that
/// disables itself after the first run and must not be re-enabled here.
const OWNED_RCVARS: &[&str] = &[
    "aifw_daemon_enable",
    "aifw_ids_enable",
    "aifw_api_enable",
    "aifw_watchdog_enable",
];

/// Write the embedded libexec scripts to /usr/local/libexec/ if missing or
/// stale. Idempotent. Called from aifw-api startup so the appliance
/// self-bootstraps the bouncer + watchdog scripts even when the install
/// was driven by an old updater that didn't iterate `libexec/`.
///
/// Compares content first to avoid touching the file on every startup
/// (mtime churn matters for log-watching tools). Uses sudo because
/// /usr/local/libexec is root-owned and aifw-api runs as the aifw user.
pub async fn ensure_libexec_scripts() {
    write_embedded_script("aifw-restart.sh", EMBEDDED_RESTART_SH).await;
    write_embedded_script("aifw-watchdog.sh", EMBEDDED_WATCHDOG_SH).await;
}

async fn write_embedded_script(name: &str, content: &str) {
    let path = format!("/usr/local/libexec/{}", name);
    if let Ok(existing) = tokio::fs::read_to_string(&path).await
        && existing == content
    {
        return;
    }
    // Stage in /tmp first, then sudo install -m 755 so the write is atomic
    // and gets correct ownership/perms regardless of who runs us.
    let tmp = format!("/tmp/.{}.aifw-bootstrap", name);
    if tokio::fs::write(&tmp, content).await.is_err() {
        warn!(name, "failed to stage embedded script");
        return;
    }
    let _ = Command::new("/usr/local/bin/sudo")
        .args(["/bin/mkdir", "-p", "/usr/local/libexec"])
        .output()
        .await;
    let result = Command::new("/usr/local/bin/sudo")
        .args(["/usr/bin/install", "-m", "755", &tmp, &path])
        .output()
        .await;
    let _ = tokio::fs::remove_file(&tmp).await;
    match result {
        Ok(o) if o.status.success() => info!(name, "libexec script bootstrapped"),
        Ok(o) => warn!(name, stderr = %String::from_utf8_lossy(&o.stderr), "install failed"),
        Err(e) => warn!(name, error = %e, "install errored"),
    }
}

/// Ensure `/usr/sbin/daemon -f *` is in the aifw user's sudoers. Idempotent.
///
/// Older installs (and in-place upgrades from before v5.81.0) wrote the
/// sudoers file without this entry; without it, the detached restart
/// driver fails silently — sudo refuses, our `spawn()` succeeds, and we
/// log "restart driver detached" while nothing actually restarted.
///
/// The sudoers file is `r--r----- root:wheel`, so a direct `fs::write`
/// from the aifw user (under whom aifw-api runs) silently fails. We
/// stage the new content in /tmp and re-install via `sudo install` —
/// /usr/bin/install is already in the existing sudoers entries.
pub async fn ensure_sudoers_daemon() {
    let path = "/usr/local/etc/sudoers.d/aifw";
    let Ok(content) = tokio::fs::read_to_string(path).await else {
        return;
    };
    if content.contains("/usr/sbin/daemon") {
        return;
    }
    let mut patched = content;
    if !patched.ends_with('\n') {
        patched.push('\n');
    }
    patched.push_str("aifw ALL=(root) NOPASSWD: /usr/sbin/daemon -f *\n");

    let stage = "/tmp/aifw-sudoers-patch";
    if tokio::fs::write(stage, &patched).await.is_err() {
        warn!("failed to stage sudoers patch");
        return;
    }
    let result = Command::new("/usr/local/bin/sudo")
        .args([
            "/usr/bin/install",
            "-m",
            "440",
            "-o",
            "root",
            "-g",
            "wheel",
            stage,
            path,
        ])
        .output()
        .await;
    let _ = tokio::fs::remove_file(stage).await;
    match result {
        Ok(o) if o.status.success() => {
            info!("added /usr/sbin/daemon to sudoers for aifw user")
        }
        Ok(o) => warn!(
            stderr = %String::from_utf8_lossy(&o.stderr),
            "sudoers patch install failed"
        ),
        Err(e) => warn!(error = %e, "sudoers patch errored"),
    }
}

/// Ensure each AiFw service has its rcvar set to YES in /etc/rc.conf.
///
/// Appliances upgraded from versions predating a service (notably aifw_ids
/// added in v5.76.0) only got the binary + rc.d script installed by the
/// updater — the rcvar stayed unset, so `service aifw_ids restart` was a
/// silent no-op and the IPC socket never came up. Idempotent: `sysrc`
/// rewrites the line whether or not it exists.
pub async fn ensure_rcvars() {
    for var in OWNED_RCVARS {
        let arg = format!("{}=YES", var);
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["/usr/sbin/sysrc", &arg])
            .output()
            .await;
    }
}

/// Restart AiFw services after an install or rollback. Spawns the
/// /usr/local/libexec/aifw-restart.sh driver detached via daemon(8) and
/// returns immediately so the HTTP response can leave the box.
///
/// The previous implementation ran the bounce loop inside aifw-api
/// itself via tokio::spawn. When the loop reached `service aifw_api
/// restart`, the rc.d stop killed aifw-api and took the loop with it —
/// any failure during the start half had no driver left to retry, and
/// the appliance would sit with the API down until an operator noticed.
/// Detaching via daemon(8) reparents the script to init, so aifw-api
/// dying mid-iteration cannot kill the bounce.
///
/// Falls back to the in-process loop on appliances that don't yet have
/// the libexec script (mid-upgrade from a pre-detached version). The
/// fragility we're fixing beats no restart at all.
pub async fn restart_services() {
    if std::path::Path::new(RESTART_SCRIPT).exists()
        && spawn_detached_restart().await.is_ok()
    {
        return;
    }
    // Either the libexec script isn't present (mid-transitional upgrade)
    // or sudo refused (older sudoers without /usr/sbin/daemon). Fall
    // back to the in-process loop. It has the bounce-self-last bug, but
    // that's strictly better than silently doing nothing — which is
    // what the previous code did when sudo refused.
    warn!("falling back to in-process restart loop");
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        ensure_rcvars().await;
        for svc in RESTARTABLE_SERVICES {
            restart_one(svc).await;
        }
    });
}

/// Try to spawn /usr/local/libexec/aifw-restart.sh detached via daemon(8).
/// Returns Err when sudo refuses or the spawn itself fails so the
/// caller can fall back to the in-process loop instead of silently
/// pretending the bounce happened.
async fn spawn_detached_restart() -> Result<(), String> {
    // .output() (not .spawn() + .wait()) so we observe sudo's exit
    // status. sudo returns non-zero when NOPASSWD doesn't cover the
    // command — the tell-tale signature of an older sudoers file
    // without /usr/sbin/daemon. Without checking, we'd log "restart
    // driver detached" while nothing happened.
    let result = Command::new("/usr/local/bin/sudo")
        .args([
            "-n", // never prompt; fail fast if NOPASSWD doesn't apply
            "/usr/sbin/daemon",
            "-f",
            "-o",
            "/var/log/aifw/restart.log",
            RESTART_SCRIPT,
        ])
        .output()
        .await
        .map_err(|e| format!("spawn: {}", e))?;
    if !result.status.success() {
        let stderr = String::from_utf8_lossy(&result.stderr);
        warn!(
            stderr = %stderr,
            "sudo refused detached restart spawn"
        );
        return Err(format!("sudo exit={:?}", result.status.code()));
    }
    info!("restart driver detached");
    Ok(())
}

/// Restart AiFw services synchronously (blocks until restart completes, use from CLI).
pub async fn restart_services_sync() {
    ensure_rcvars().await;
    for svc in RESTARTABLE_SERVICES {
        restart_one(svc).await;
    }
}

/// Schedule a system reboot via FreeBSD's `shutdown(8)`. The +1 syntax
/// gives the HTTP response a full minute to flush and gives the operator
/// a window to cancel via console (`shutdown -c`). `shutdown` returns
/// immediately after registering with init; we await the sudo wrapper
/// just to reap it.
///
/// sudoers (set in deploy.sh + aifw-setup) allows `/sbin/shutdown` for
/// the aifw user without a password. We deliberately don't go through
/// `daemon(8)` here — that would need a separate sudoers entry, and
/// shutdown is already detached from our process tree by init.
pub async fn schedule_reboot() -> Result<(), UpdaterError> {
    let result = Command::new("/usr/local/bin/sudo")
        .args([
            "/sbin/shutdown",
            "-r",
            "+1",
            "AiFw: operator-requested reboot",
        ])
        .spawn();
    match result {
        Ok(mut child) => {
            let _ = child.wait().await;
            info!("reboot scheduled (+1 min)");
            Ok(())
        }
        Err(e) => Err(UpdaterError::Install(format!("schedule reboot: {}", e))),
    }
}

/// Restart a single service with a hard 60-second timeout. If the underlying
/// `service X restart` hangs (e.g. graceful-drain stuck, daemon(8) supervisor
/// waiting on a child whose tokio runtime won't exit), we move on rather than
/// wedge the entire upgrade. The next restart cycle's `start_precmd` pkill
/// will reap any orphans we leave behind.
async fn restart_one(svc: &str) {
    let cmd = Command::new("/usr/local/bin/sudo")
        .args(["service", svc, "restart"])
        .output();
    match tokio::time::timeout(std::time::Duration::from_secs(60), cmd).await {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => warn!(service = svc, error = %e, "service restart errored"),
        Err(_) => warn!(
            service = svc,
            "service restart timed out after 60s — moving on"
        ),
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

/// Parse the hex digest from a checksum file line.
///
/// Exposed as `extract_hash_pub` for use by the API's local-install handler
/// which needs to strip the filename part from an uploaded .sha256 sidecar
/// before passing it to `install_from_path`.
pub fn extract_hash_pub(checksum_content: &str) -> String {
    extract_hash(checksum_content)
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
