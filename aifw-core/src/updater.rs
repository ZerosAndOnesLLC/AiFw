//! AiFw self-updater — checks GitHub Releases for new versions and installs updates.
//!
//! Component lists are driven by `freebsd/manifest.json` (single source of truth).
//! The manifest is embedded at compile time so no runtime file dependency.

use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{debug, info, warn};

const GITHUB_API_URL: &str = "https://api.github.com/repos/ZerosAndOnesLLC/AiFw/releases/latest";
// Lists releases newest-first INCLUDING pre-releases (and drafts), unlike
// /releases/latest which silently skips them. Used only when the operator
// opts into the pre-release channel.
const GITHUB_RELEASES_URL: &str =
    "https://api.github.com/repos/ZerosAndOnesLLC/AiFw/releases?per_page=20";
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

/// All `aifw-sudo-*` narrow-grant helper scripts, embedded at compile time.
/// `ensure_libexec_scripts()` writes them at every aifw-api startup so an
/// in-place tarball upgrade from a pre-#204 appliance (no narrow helpers on
/// disk yet) self-bootstraps the wrapper inventory. Without this, the new
/// code's `crate::sudo::*` wrappers would all fail (helper not found, sudo
/// refused) on cold-boot from an old image.
const EMBEDDED_SUDO_HELPERS: &[(&str, &str)] = &[
    (
        "aifw-sudo-install",
        include_str!("../../freebsd/overlay/usr/local/libexec/aifw-sudo-install"),
    ),
    (
        "aifw-sudo-write",
        include_str!("../../freebsd/overlay/usr/local/libexec/aifw-sudo-write"),
    ),
    (
        "aifw-sudo-wg",
        include_str!("../../freebsd/overlay/usr/local/libexec/aifw-sudo-wg"),
    ),
    (
        "aifw-sudo-freebsd-update",
        include_str!("../../freebsd/overlay/usr/local/libexec/aifw-sudo-freebsd-update"),
    ),
    (
        "aifw-sudo-pkg",
        include_str!("../../freebsd/overlay/usr/local/libexec/aifw-sudo-pkg"),
    ),
    (
        "aifw-sudo-service",
        include_str!("../../freebsd/overlay/usr/local/libexec/aifw-sudo-service"),
    ),
    (
        "aifw-sudo-chown",
        include_str!("../../freebsd/overlay/usr/local/libexec/aifw-sudo-chown"),
    ),
    (
        "aifw-sudo-ifconfig",
        include_str!("../../freebsd/overlay/usr/local/libexec/aifw-sudo-ifconfig"),
    ),
    (
        "aifw-sudo-sysrc",
        include_str!("../../freebsd/overlay/usr/local/libexec/aifw-sudo-sysrc"),
    ),
    (
        "aifw-sudo-dhclient",
        include_str!("../../freebsd/overlay/usr/local/libexec/aifw-sudo-dhclient"),
    ),
    (
        "aifw-sudo-route",
        include_str!("../../freebsd/overlay/usr/local/libexec/aifw-sudo-route"),
    ),
    (
        "aifw-sudo-pkill",
        include_str!("../../freebsd/overlay/usr/local/libexec/aifw-sudo-pkill"),
    ),
    (
        "aifw-sudo-rm",
        include_str!("../../freebsd/overlay/usr/local/libexec/aifw-sudo-rm"),
    ),
    (
        "aifw-sudo-mkdir",
        include_str!("../../freebsd/overlay/usr/local/libexec/aifw-sudo-mkdir"),
    ),
    (
        "aifw-sudo-cp",
        include_str!("../../freebsd/overlay/usr/local/libexec/aifw-sudo-cp"),
    ),
    (
        "aifw-sudo-tar",
        include_str!("../../freebsd/overlay/usr/local/libexec/aifw-sudo-tar"),
    ),
    (
        "aifw-sudo-tcpdump",
        include_str!("../../freebsd/overlay/usr/local/libexec/aifw-sudo-tcpdump"),
    ),
    (
        "aifw-sudo-swanctl",
        include_str!("../../freebsd/overlay/usr/local/libexec/aifw-sudo-swanctl"),
    ),
];

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
    /// OS packages the appliance needs at runtime. Installed by
    /// build-iso.sh at image build; the updater installs any that are
    /// missing so in-place upgrades pick up new dependencies (#530
    /// added strongswan this way).
    #[serde(default)]
    packages: Vec<String>,
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

/// OS packages this build requires, from the embedded manifest. Exposed
/// for `aifw-setup --print-packages`, which aifw-restart.sh queries to
/// install dependencies a transitional upgrade missed (#565: the old
/// updater binary's embedded manifest predates newly-added packages).
pub fn manifest_packages() -> Vec<String> {
    load_manifest().packages
}

fn load_manifest() -> Manifest {
    serde_json::from_str(MANIFEST_JSON).expect("freebsd/manifest.json is invalid")
}

/// SEC-H11: reject a `tar tf` listing if any entry would escape the extract
/// directory — an absolute path or a `..` path component. Pure so it can be
/// unit-tested without touching the filesystem or a real tarball.
fn validate_tar_listing(listing: &str) -> Result<(), String> {
    for raw in listing.lines() {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        let path = entry.trim_start_matches("./");
        if entry.starts_with('/') || path.starts_with('/') || path.split('/').any(|c| c == "..") {
            return Err(format!(
                "refusing unsafe tarball: entry escapes extract dir: {entry}"
            ));
        }
    }
    Ok(())
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

/// Describe a failed best-effort privileged step, or `None` on success.
///
/// The `crate::sudo::*` wrappers (and raw `Command::output()`) return
/// `Ok(Output)` even when the command exits non-zero, so a bare
/// `let _ =` used to hide both spawn errors and failed commands
/// (QUAL-H1 #421). Callers log the returned description and continue —
/// these steps stay non-fatal by design.
fn step_failure(result: &std::io::Result<std::process::Output>) -> Option<String> {
    match result {
        Ok(o) if o.status.success() => None,
        Ok(o) => Some(format!(
            "exit {}: {}",
            o.status,
            String::from_utf8_lossy(&o.stderr).trim()
        )),
        Err(e) => Some(format!("spawn failed: {e}")),
    }
}

/// Failures from the self-update flow (release check, download, verify,
/// install, rollback)
#[derive(Debug, thiserror::Error)]
pub enum UpdaterError {
    /// GitHub API request failed
    #[error("HTTP request failed: {0}")]
    Http(String),
    /// Release JSON couldn't be parsed
    #[error("JSON parse error: {0}")]
    Json(String),
    /// Fetching the tarball or checksum asset failed
    #[error("Download failed: {0}")]
    Download(String),
    /// Downloaded tarball didn't match its published SHA-256
    #[error("Checksum verification failed")]
    Checksum,
    /// The release did not contain a detached signature for its checksum
    #[error("Release checksum signature is missing")]
    NoSignature,
    /// The checksum's publisher signature could not be verified
    #[error("Release signature verification failed")]
    Signature,
    /// minisign could not be located or executed, so the signature could
    /// not be checked at all (distinct from a signature that checked and
    /// failed — the operator fixes this one with `pkg install minisign`)
    #[error("Signature verification unavailable: {0}")]
    VerifyUnavailable(String),
    /// Extracting or installing the update failed
    #[error("Installation failed: {0}")]
    Install(String),
    /// Rollback requested but no backup exists on disk
    #[error("No backup available")]
    NoBackup,
    /// The release has no update tarball asset to install
    #[error("No update tarball found in release")]
    NoTarball,
}

/// Update status reported to the UI/API by the GitHub release check
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AifwUpdateInfo {
    /// Version currently installed on disk
    pub current_version: String,
    /// Newest version published on GitHub Releases
    pub latest_version: String,
    /// True when `latest_version` is newer than `current_version`
    pub update_available: bool,
    /// Release notes body from the GitHub release
    pub release_notes: String,
    /// Release publish timestamp from GitHub
    pub published_at: String,
    /// Download URL of the update tarball asset, if the release has one
    pub tarball_url: Option<String>,
    /// Download URL of the tarball's SHA-256 checksum asset, if present
    pub checksum_url: Option<String>,
    /// Download URL of the checksum's detached minisign signature.
    #[serde(default)]
    pub checksum_signature_url: Option<String>,
    /// True when a rollback backup exists on disk
    pub has_backup: bool,
    /// Version the on-disk backup was taken from, when known
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
    /// Operator opted into the pre-release update channel (for test boxes).
    /// When set, checks/installs consider GitHub pre-releases instead of just
    /// the stable `/releases/latest`. Field appliances leave this off so they
    /// only ever pull stable releases.
    #[serde(default)]
    pub include_prereleases: bool,
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
///
/// When `include_prereleases` is false (field default) this consults
/// `/releases/latest`, which only ever returns the newest *stable* release.
/// When true (operator opted into the pre-release channel on a test box) it
/// lists `/releases` and takes the newest non-draft entry, which may be a
/// pre-release.
pub async fn check_for_update(include_prereleases: bool) -> Result<AifwUpdateInfo, UpdaterError> {
    let current = get_current_version().await;
    let release: serde_json::Value = if include_prereleases {
        let json = http_get(GITHUB_RELEASES_URL).await?;
        let releases: serde_json::Value =
            serde_json::from_str(&json).map_err(|e| UpdaterError::Json(e.to_string()))?;
        releases
            .as_array()
            .and_then(|rs| {
                rs.iter()
                    .find(|r| !r["draft"].as_bool().unwrap_or(false))
                    .cloned()
            })
            .ok_or_else(|| UpdaterError::Json("no releases found".to_string()))?
    } else {
        let json = http_get(GITHUB_API_URL).await?;
        serde_json::from_str(&json).map_err(|e| UpdaterError::Json(e.to_string()))?
    };

    let tag = release["tag_name"].as_str().unwrap_or("v0.0.0");
    let latest = tag.strip_prefix('v').unwrap_or(tag);
    let notes = release["body"].as_str().unwrap_or("").to_string();
    let published = release["published_at"].as_str().unwrap_or("").to_string();

    let (tarball_url, checksum_url, checksum_signature_url) = release_asset_urls(&release);

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
        checksum_signature_url,
        has_backup,
        backup_version,
        restart_pending,
        running_version: running_version().to_string(),
        reboot_recommended,
        reboot_reason,
        include_prereleases,
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

    // Extract the tarball into a dedicated, always-clean staging dir.
    //
    // The tarball is extracted as root (via the sudo-tar helper), so anything
    // left over from a prior update is root-owned and the aifw user can't
    // remove it with std fs. Previously these accumulated in
    // <tarball_parent>/extracted and the installer selected one with
    // read_dir().next_entry() — an ARBITRARY directory-order pick — so a stale
    // older version (e.g. 5.96.8) got installed instead of the one just
    // downloaded, making every in-app upgrade a silent no-op.
    //
    // Fix: stage in a fixed path inside the /tmp/aifw-* allowlist (so the sudo
    // rm/tar helpers accept it), scrub it before AND after extraction (via the
    // sudo helper, since the content is root-owned), and select the update dir
    // DETERMINISTICALLY from the tarball's own top-level entry rather than
    // trusting directory order.
    const EXTRACT_DIR: &str = "/tmp/aifw-update-extract";
    // Scrub current + legacy staging. Root-owned, so the sudo helper is
    // required; best-effort because a clean run has nothing to remove.
    if let Some(err) = step_failure(&crate::sudo::rm(&["-rf", EXTRACT_DIR]).await) {
        debug!(path = EXTRACT_DIR, error = %err, "update: staging dir scrub failed");
    }
    if let Some(err) = step_failure(&crate::sudo::rm(&["-rf", "/tmp/aifw-update/extracted"]).await)
    {
        debug!(
            path = "/tmp/aifw-update/extracted",
            error = %err,
            "update: legacy staging dir scrub failed"
        );
    }
    let extract_dir = std::path::PathBuf::from(EXTRACT_DIR);
    tokio::fs::create_dir_all(&extract_dir)
        .await
        .map_err(|e| UpdaterError::Install(format!("Failed to create extract dir: {}", e)))?;

    // Read the tarball's top-level directory name straight from the archive,
    // so we install exactly what we extracted regardless of any siblings.
    let listing = Command::new("tar")
        .args(["tf", tarball_str])
        .output()
        .await
        .map_err(|e| UpdaterError::Install(format!("tar list failed: {}", e)))?;
    if !listing.status.success() {
        return Err(UpdaterError::Install(format!(
            "tar list failed: {}",
            String::from_utf8_lossy(&listing.stderr)
        )));
    }
    let listing_text = String::from_utf8_lossy(&listing.stdout);

    // SEC-H11: path-traversal guard. Extraction runs as root via the sudo
    // helper, so an entry with an absolute path or a `..` component could
    // write outside EXTRACT_DIR. bsdtar strips these by default, but we do
    // not rely on that — reject the whole tarball up front.
    validate_tar_listing(&listing_text).map_err(UpdaterError::Install)?;

    let top_name = listing_text
        .lines()
        .find_map(|l| {
            l.trim_start_matches("./")
                .split('/')
                .next()
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
        })
        .ok_or_else(|| UpdaterError::Install("Empty tarball".to_string()))?;

    // Use the aifw-sudo-tar helper which rejects --use-compress-program /
    // --checkpoint-action / -I (SEC-C2 PE primitives). The helper also
    // restricts tarball + dest to staging dirs we already own.
    let output = crate::sudo::tar(&["xf", tarball_str, "-C", EXTRACT_DIR])
        .await
        .map_err(|e| UpdaterError::Install(format!("tar failed: {}", e)))?;

    if !output.status.success() {
        return Err(UpdaterError::Install(format!(
            "tar extract failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let update_dir = extract_dir.join(&top_name);
    if !update_dir.is_dir() {
        return Err(UpdaterError::Install(format!(
            "extracted dir '{}' not found (corrupt tarball?)",
            top_name
        )));
    }

    // Install binaries from the tarball's bin/ directory.
    //
    // SEC-H11: only install names on the compiled-in allowlist derived from
    // the embedded manifest (`all_binaries()`). The local-upload install path
    // has an optional (bypassable) checksum, so a malicious tarball can carry
    // arbitrary `bin/<name>` files; without this gate an `UpdatesInstall`
    // actor could plant a new root-owned `aifw-*` binary under a trusted name.
    // Trade-off: a genuinely new binary in a future release is skipped by the
    // *currently running* updater (logged loudly) until the core binaries
    // update carries a manifest that lists it.
    info!("Installing binaries...");
    let allowed: std::collections::HashSet<String> = all_binaries().into_iter().collect();
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
            if !entry
                .file_type()
                .await
                .map(|t| t.is_file())
                .unwrap_or(false)
            {
                continue;
            }
            let src = entry.path();
            let name = match src.file_name().and_then(|n| n.to_str()) {
                Some(n) => n.to_string(),
                None => continue,
            };
            if !allowed.contains(&name) {
                warn!(
                    binary = %name,
                    "refusing to install binary not on the manifest allowlist (SEC-H11)"
                );
                continue;
            }
            let dst = format!("{}/{}", BIN_DIR, name);
            let src_str = src
                .to_str()
                .expect("src path is utf-8 (file_name validated above)");
            let output = crate::sudo::install(Some("755"), None, None, src_str, &dst)
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

    // Install UI — both rm and cp go through the narrow helpers (SEC-C2).
    // The helpers restrict UI_DIR and a /tmp staging dir as the only legal
    // operands; a compromised aifw user can't sudo-cp /tmp/x to /root/.ssh.
    let ui_src = update_dir.join("ui");
    if ui_src.exists() {
        info!("Installing UI...");
        if let Some(err) = step_failure(&crate::sudo::rm(&["-rf", UI_DIR]).await) {
            warn!(
                path = UI_DIR,
                error = %err,
                "update: failed to remove old UI dir — stale UI files may remain"
            );
        }
        let ui_src_str = ui_src
            .to_str()
            .ok_or_else(|| UpdaterError::Install("ui_src path is not UTF-8".into()))?;
        let output = crate::sudo::cp(&["-a", ui_src_str, UI_DIR])
            .await
            .map_err(|e| UpdaterError::Install(format!("Failed to install UI: {}", e)))?;
        if !output.status.success() {
            return Err(UpdaterError::Install(format!(
                "Failed to install UI: {}",
                String::from_utf8_lossy(&output.stderr)
            )));
        }
    }

    // SEC-C1: runtime sudoers migration has been removed.
    //
    // The previous design ran nine `ensure_sudoers_*` functions here, each
    // re-writing /usr/local/etc/sudoers.d/aifw via the `aifw-sudo-install`
    // helper to add new narrow-helper grants on upgrade. That made the
    // helper script able to install ANY content into the sudoers file
    // (audited as a critical PE primitive). The helper's destination
    // allowlist no longer accepts that path; sudoers is now an install-time
    // artifact shipped by the update tarball / ISO / deploy.sh, written by
    // a privileged installer step.

    // Ensure required packages are installed — older installs may predate a
    // dependency (curl pre-5.x, strongswan pre-#530). Driven by the
    // manifest `packages` list so new deps flow to upgraded boxes.
    for pkg in &load_manifest().packages {
        let pkg = pkg.as_str();
        let check = Command::new("pkg").args(["info", "-q", pkg]).output().await;
        let pkg_installed = check.map(|o| o.status.success()).unwrap_or(false);
        if !pkg_installed {
            info!(package = pkg, "Installing missing dependency");
            if let Some(err) = step_failure(&crate::sudo::pkg("install", &["-y", pkg]).await) {
                warn!(package = pkg, error = %err, "update: dependency install failed");
            }
        }
    }

    // Keep the operator-facing copy of the release-signing public key in
    // sync with the running build (it changes only on key rotation).
    // Verification itself uses the compiled-in key, so this is best-effort.
    let on_disk_pubkey = tokio::fs::read_to_string(PUBKEY_PATH).await.ok();
    if on_disk_pubkey.as_deref() != Some(EMBEDDED_PUBKEY) {
        let staged = "/tmp/aifw-update-signing.pub";
        let stage_ok = tokio::fs::write(staged, EMBEDDED_PUBKEY).await.is_ok();
        if stage_ok {
            if let Some(err) = step_failure(
                &crate::sudo::install(
                    Some("0644"),
                    Some("root"),
                    Some("wheel"),
                    staged,
                    PUBKEY_PATH,
                )
                .await,
            ) {
                warn!(error = %err, "update: could not provision update-signing.pub");
            }
            if let Err(e) = tokio::fs::remove_file(staged).await {
                debug!(error = %e, "update: staged pubkey cleanup failed");
            }
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
                if !entry
                    .file_type()
                    .await
                    .map(|t| t.is_file())
                    .unwrap_or(false)
                {
                    continue;
                }
                let src = entry.path();
                let name = match src.file_name().and_then(|n| n.to_str()) {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                let dst = format!("/usr/local/etc/rc.d/{}", name);
                let src_str = src
                    .to_str()
                    .expect("src path is utf-8 (file_name validated above)");
                if let Some(err) = step_failure(
                    &crate::sudo::install(Some("755"), None, None, src_str, &dst).await,
                ) {
                    warn!(script = %name, dest = %dst, error = %err, "update: rc.d script install failed");
                }
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
        if let Some(err) = step_failure(&crate::sudo::mkdir(&["-p", "/usr/local/libexec"]).await) {
            warn!(error = %err, "update: mkdir /usr/local/libexec failed");
        }
        if let Ok(mut entries) = tokio::fs::read_dir(&libexec_src).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                if !entry
                    .file_type()
                    .await
                    .map(|t| t.is_file())
                    .unwrap_or(false)
                {
                    continue;
                }
                let src = entry.path();
                let name = match src.file_name().and_then(|n| n.to_str()) {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                let dst = format!("/usr/local/libexec/{}", name);
                let src_str = src
                    .to_str()
                    .expect("src path is utf-8 (file_name validated above)");
                if let Some(err) = step_failure(
                    &crate::sudo::install(Some("755"), None, None, src_str, &dst).await,
                ) {
                    warn!(script = %name, dest = %dst, error = %err, "update: libexec script install failed");
                }
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
                if !entry
                    .file_type()
                    .await
                    .map(|t| t.is_file())
                    .unwrap_or(false)
                {
                    continue;
                }
                let src = entry.path();
                let name = match src.file_name().and_then(|n| n.to_str()) {
                    Some(n) => n.to_string(),
                    None => continue,
                };
                let dst = format!("{}/{}", BIN_DIR, name);
                let src_str = src
                    .to_str()
                    .expect("src path is utf-8 (file_name validated above)");
                if let Some(err) = step_failure(
                    &crate::sudo::install(Some("755"), None, None, src_str, &dst).await,
                ) {
                    warn!(script = %name, dest = %dst, error = %err, "update: utility script install failed");
                }
            }
        }
    }

    // Ensure required directories exist (new services may need them)
    for dir in &manifest.directories {
        if let Some(err) = step_failure(&crate::sudo::mkdir(&["-p", dir]).await) {
            warn!(path = %dir, error = %err, "update: required directory create failed");
        }
    }

    // Read the installed version from the tarball's version file
    let installed_version = {
        let ver_src = update_dir.join("version");
        if ver_src.exists() {
            let ver_src_str = ver_src
                .to_str()
                .ok_or_else(|| UpdaterError::Install("ver_src path is not UTF-8".into()))?;
            let output = crate::sudo::cp(&[ver_src_str, VERSION_FILE])
                .await
                .map_err(|e| {
                    UpdaterError::Install(format!("Failed to update version file: {}", e))
                })?;
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

    // Install the component-revision record (#538) next to the version file
    // so an appliance can report exactly which AiFw + companion commits it
    // runs. Best-effort: pre-#538 tarballs don't contain it.
    {
        let comp_src = update_dir.join("components.json");
        if comp_src.exists() {
            match comp_src.to_str() {
                Some(comp_src_str) => {
                    if let Some(err) = step_failure(
                        &crate::sudo::cp(&[comp_src_str, "/usr/local/share/aifw/components.json"])
                            .await,
                    ) {
                        warn!(error = %err, "update: components.json install failed");
                    }
                }
                None => warn!("update: components.json path is not UTF-8; skipping"),
            }
        }
    }

    // Strip stale AiFw version from MOTD template. Idempotent and respects
    // the marker file that `system_apply::apply_banner` sets when the admin
    // edits MOTD via the UI.
    #[cfg(target_os = "freebsd")]
    {
        let result = Command::new("/usr/local/libexec/aifw-motd-cleanup.sh")
            .output()
            .await;
        if let Some(err) = step_failure(&result) {
            debug!(error = %err, "update: motd cleanup script failed");
        }
    }

    // One-shot migration: enforce password-protected console login on
    // existing installs that were shipped with autologin. Idempotent.
    #[cfg(target_os = "freebsd")]
    {
        let result = Command::new("/usr/local/libexec/aifw-login-migrate.sh")
            .output()
            .await;
        if let Some(err) = step_failure(&result) {
            warn!(error = %err, "update: console login migration script failed — autologin may remain enabled");
        }
    }

    // Cleanup extract dir. Contents are root-owned (sudo-tar), so std fs
    // remove_dir_all would fail silently and leak staging across updates —
    // exactly what let stale dirs pile up before. Use the sudo helper.
    if let Some(err) = step_failure(&crate::sudo::rm(&["-rf", EXTRACT_DIR]).await) {
        debug!(path = EXTRACT_DIR, error = %err, "update: staging dir cleanup failed");
    }

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
    let signature_url = info
        .checksum_signature_url
        .as_deref()
        .ok_or(UpdaterError::NoSignature)?;

    let tmp_dir = "/tmp/aifw-update";
    let tarball_path = std::path::PathBuf::from(format!("{}/update.tar.xz", tmp_dir));
    let checksum_path = format!("{}/update.tar.xz.sha256", tmp_dir);
    let signature_path = format!("{}/update.tar.xz.sha256.minisig", tmp_dir);

    // Clean and create temp dir. NotFound is the normal clean-run case.
    if let Err(e) = tokio::fs::remove_dir_all(tmp_dir).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        debug!(path = tmp_dir, error = %e, "update: temp dir scrub failed");
    }
    tokio::fs::create_dir_all(tmp_dir)
        .await
        .map_err(|e| UpdaterError::Install(format!("Failed to create temp dir: {}", e)))?;

    // Download tarball and checksum
    info!("Downloading AiFw update v{}...", info.latest_version);
    let tarball_path_str = tarball_path
        .to_str()
        .ok_or_else(|| UpdaterError::Install("tarball_path is not UTF-8".into()))?;
    http_download(tarball_url, tarball_path_str).await?;
    http_download(checksum_url, &checksum_path).await?;
    http_download(signature_url, &signature_path).await?;

    // Publisher authenticity is checked before trusting the checksum. The
    // public key is compiled into the running binary, so replacing a release
    // asset and its checksum is insufficient to authorize an install.
    verify_minisign_checksum(&checksum_path, &signature_path).await?;

    // Read and parse the expected hash from the downloaded checksum file
    let expected = tokio::fs::read_to_string(&checksum_path)
        .await
        .map_err(|e| UpdaterError::Download(format!("Failed to read checksum: {}", e)))?;
    let expected_hash = extract_hash(&expected);

    // Delegate to the shared install primitive (verifies hash, extracts, installs)
    let version = install_from_path(&tarball_path, Some(&expected_hash)).await?;

    // Cleanup temp dir
    if let Err(e) = tokio::fs::remove_dir_all(tmp_dir).await
        && e.kind() != std::io::ErrorKind::NotFound
    {
        debug!(path = tmp_dir, error = %e, "update: temp dir cleanup failed");
    }

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

/// On-disk copy of the release-signing public key. Informational only —
/// provisioned for operators who want to run `minisign -Vm` by hand.
/// Verification always uses the compiled-in key below, so an appliance
/// upgraded from a build that never shipped this file still enforces.
const PUBKEY_PATH: &str = "/usr/local/etc/aifw/update-signing.pub";

/// Release-signing public key, compiled in from the repo. Trust is pinned
/// to the running build: a key rotation ships a release signed with the
/// OLD key that embeds the NEW key, so every appliance crosses over by
/// installing that release (see freebsd/RELEASE-SIGNING.md).
const EMBEDDED_PUBKEY: &str =
    include_str!("../../freebsd/overlay/usr/local/etc/aifw/update-signing.pub");

/// The base64 key line of the embedded minisign public key (the line after
/// the "untrusted comment:" header), suitable for `minisign -P`.
fn embedded_pubkey_b64() -> Result<&'static str, UpdaterError> {
    EMBEDDED_PUBKEY
        .lines()
        .map(str::trim)
        .rfind(|l| !l.is_empty() && !l.starts_with("untrusted comment:"))
        .filter(|l| l.starts_with("RW"))
        .ok_or_else(|| {
            UpdaterError::VerifyUnavailable(
                "embedded update-signing public key is malformed".into(),
            )
        })
}

async fn verify_minisign_checksum(checksum: &str, signature: &str) -> Result<(), UpdaterError> {
    let pubkey = embedded_pubkey_b64()?;
    let args = ["-Vm", checksum, "-x", signature, "-P", pubkey];

    let mut result = Command::new("minisign").args(args).output().await;
    if matches!(&result, Err(e) if e.kind() == std::io::ErrorKind::NotFound) {
        // An appliance upgraded from a pre-signing build doesn't have
        // minisign yet: the OLD updater that installed this build worked
        // from its own embedded package list, which predates the minisign
        // entry in the manifest. The pkg sudo grant does exist on such
        // appliances, so install it here rather than failing the upgrade.
        info!("minisign not found; installing via pkg");
        if let Some(err) = step_failure(&crate::sudo::pkg("install", &["-y", "minisign"]).await) {
            return Err(UpdaterError::VerifyUnavailable(format!(
                "minisign is not installed and installing it failed: {err}"
            )));
        }
        result = Command::new("minisign").args(args).output().await;
    }
    let output = result
        .map_err(|e| UpdaterError::VerifyUnavailable(format!("failed to run minisign: {e}")))?;
    if output.status.success() {
        Ok(())
    } else {
        warn!(
            stderr = %String::from_utf8_lossy(&output.stderr),
            "release checksum signature rejected"
        );
        Err(UpdaterError::Signature)
    }
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
    // Bootstrap the narrow-grant sudo helpers (#204 / SEC-C2). These ship
    // in the tarball overlay AND are embedded here so an in-place upgrade
    // from a pre-#204 box — which has no `aifw-sudo-*` on disk and no
    // narrow grants in sudoers — still ends up with the helpers in place.
    // write_embedded_script falls back to direct `sudo /usr/bin/install`
    // when the narrow `aifw-sudo-install` helper isn't on disk yet.
    for (name, content) in EMBEDDED_SUDO_HELPERS {
        write_embedded_script(name, content).await;
    }
}

async fn write_embedded_script(name: &str, content: &str) {
    let path = format!("/usr/local/libexec/{}", name);
    if let Ok(existing) = tokio::fs::read_to_string(&path).await
        && existing == content
        && is_executable(&path).await
    {
        // Matching content alone isn't enough to skip: ISO installs before
        // v5.97.6 laid these down mode 644 (#469), and sudo reports a
        // non-executable helper as "command not found". Reinstalling with
        // -m 755 below is the only self-heal path such a box has.
        return;
    }
    // Stage in /tmp first, then install -m 755 so the write is atomic
    // and gets correct ownership/perms regardless of who runs us.
    let tmp = format!("/tmp/.{}.aifw-bootstrap", name);
    if tokio::fs::write(&tmp, content).await.is_err() {
        warn!(name, "failed to stage embedded script");
        return;
    }
    if let Some(err) = step_failure(&crate::sudo::mkdir(&["-p", "/usr/local/libexec"]).await) {
        warn!(name, error = %err, "bootstrap: mkdir /usr/local/libexec failed");
    }
    // Prefer the narrow `aifw-sudo-install` helper when it's already on
    // disk. Otherwise fall back to direct `sudo /usr/bin/install`, which
    // the broad pre-#204 sudoers grant permits. This is the bootstrap path
    // used on first upgrade from an old box; once the helpers exist on
    // disk, every subsequent boot takes the narrow path.
    let aifw_sudo_install_exists =
        std::path::Path::new("/usr/local/libexec/aifw-sudo-install").exists();
    let result = if aifw_sudo_install_exists {
        crate::sudo::install(Some("755"), None, None, &tmp, &path).await
    } else {
        Command::new("/usr/local/bin/sudo")
            .args(["/usr/bin/install", "-m", "755", &tmp, &path])
            .output()
            .await
    };
    if let Err(e) = tokio::fs::remove_file(&tmp).await {
        debug!(name, path = %tmp, error = %e, "failed to remove staged bootstrap script");
    }
    match result {
        Ok(o) if o.status.success() => info!(name, "libexec script bootstrapped"),
        Ok(o) => warn!(name, stderr = %String::from_utf8_lossy(&o.stderr), "install failed"),
        Err(e) => warn!(name, error = %e, "install errored"),
    }
}

/// True when any execute bit is set. The helpers are root-owned and run
/// via sudo, so a single x bit anywhere is what sudo's path resolution
/// requires; a 644 file fails with "command not found".
async fn is_executable(path: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    tokio::fs::metadata(path)
        .await
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

// SEC-C1: ensure_sudoers_* functions removed.
//
// The previous design migrated the runtime sudoers.d/aifw file from this
// process via the aifw-sudo-install helper. That made the helper able to
// install arbitrary content into the sudoers file (PE primitive). The
// helper allowlist no longer accepts /usr/local/etc/sudoers.d/aifw; the
// sudoers file is now written by a root-running installer step
// (deploy.sh / aifw-setup) and is immutable at aifw-uid runtime.

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
        if let Some(err) = step_failure(&crate::sudo::sysrc(&[&arg]).await) {
            warn!(rcvar = var, error = %err, "failed to set rcvar — service restart may be a silent no-op");
        }
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
    if std::path::Path::new(RESTART_SCRIPT).exists() && spawn_detached_restart().await.is_ok() {
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
            match child.wait().await {
                Ok(status) if !status.success() => warn!(
                    %status,
                    "shutdown exited non-zero — reboot may not be scheduled"
                ),
                Err(e) => warn!(error = %e, "failed to reap shutdown command"),
                Ok(_) => {}
            }
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
    let cmd = crate::sudo::service(svc, "restart");
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
            if let Some(err) =
                step_failure(&crate::sudo::install(Some("755"), None, None, &src, &dst).await)
            {
                warn!(binary = %bin, error = %err, "rollback: binary restore failed");
            }
        }
    }

    // Restore rc.d scripts
    let manifest = load_manifest();
    for script in &manifest.rc_scripts {
        let src = format!("{}/rc.d/{}", BACKUP_DIR, script);
        if std::path::Path::new(&src).exists() {
            let dst = format!("/usr/local/etc/rc.d/{}", script);
            if let Some(err) =
                step_failure(&crate::sudo::install(Some("755"), None, None, &src, &dst).await)
            {
                warn!(script = %script, error = %err, "rollback: rc.d script restore failed");
            }
        }
    }

    // Restore UI
    let backup_ui = format!("{}/ui", BACKUP_DIR);
    if std::path::Path::new(&backup_ui).exists() {
        if let Some(err) = step_failure(&crate::sudo::rm(&["-rf", UI_DIR]).await) {
            warn!(path = UI_DIR, error = %err, "rollback: failed to remove current UI dir");
        }
        if let Some(err) = step_failure(&crate::sudo::cp(&["-a", &backup_ui, UI_DIR]).await) {
            warn!(path = UI_DIR, error = %err, "rollback: UI restore failed");
        }
    }

    // Restore version file
    if let Some(err) = step_failure(&crate::sudo::cp(&[&backup_ver, VERSION_FILE]).await) {
        warn!(path = VERSION_FILE, error = %err, "rollback: version file restore failed");
    }

    info!("Rolled back to v{}", version);
    Ok(format!("Rolled back to v{}", version))
}

// --- Private helpers ---

async fn backup_current() -> Result<(), UpdaterError> {
    if let Some(err) = step_failure(&crate::sudo::rm(&["-rf", BACKUP_DIR]).await) {
        warn!(path = BACKUP_DIR, error = %err, "backup: failed to clear old backup dir");
    }
    // The mkdir helper takes exactly one target, so create each dir
    // separately (rather than one mkdir with two operands).
    for sub in ["bin", "rc.d"] {
        let dir = format!("{}/{}", BACKUP_DIR, sub);
        if let Some(err) = step_failure(&crate::sudo::mkdir(&["-p", &dir]).await) {
            warn!(path = %dir, error = %err, "backup: failed to create backup dir");
        }
    }

    for bin in &all_binaries() {
        let src = format!("{}/{}", BIN_DIR, bin);
        if std::path::Path::new(&src).exists()
            && let Some(err) = step_failure(
                &crate::sudo::cp(&["-p", &src, &format!("{}/bin/{}", BACKUP_DIR, bin)]).await,
            )
        {
            warn!(binary = %bin, error = %err, "backup: binary copy failed — rollback may be incomplete");
        }
    }

    // Backup rc.d scripts
    let manifest = load_manifest();
    for script in &manifest.rc_scripts {
        let src = format!("/usr/local/etc/rc.d/{}", script);
        if std::path::Path::new(&src).exists()
            && let Some(err) = step_failure(
                &crate::sudo::cp(&["-p", &src, &format!("{}/rc.d/{}", BACKUP_DIR, script)]).await,
            )
        {
            warn!(script = %script, error = %err, "backup: rc.d script copy failed");
        }
    }

    if std::path::Path::new(UI_DIR).exists()
        && let Some(err) =
            step_failure(&crate::sudo::cp(&["-a", UI_DIR, &format!("{}/ui", BACKUP_DIR)]).await)
    {
        warn!(path = UI_DIR, error = %err, "backup: UI copy failed — rollback may be incomplete");
    }

    if std::path::Path::new(VERSION_FILE).exists()
        && let Some(err) = step_failure(
            &crate::sudo::cp(&[VERSION_FILE, &format!("{}/version", BACKUP_DIR)]).await,
        )
    {
        warn!(path = VERSION_FILE, error = %err, "backup: version file copy failed — rollback will report no backup");
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

fn release_asset_urls(
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

    // SEC-H11 (#296): the tar-listing guard must reject any archive entry
    // that would escape the extraction directory.
    #[test]
    fn tar_listing_rejects_traversal_and_absolute() {
        for bad in [
            "aifw-5.97/\n../evil",
            "../../etc/cron.d/x",
            "/etc/passwd",
            "aifw-5.97/bin/../../../root/.ssh/authorized_keys",
            "./../escape",
        ] {
            assert!(
                validate_tar_listing(bad).is_err(),
                "should reject listing: {bad:?}"
            );
        }
    }

    #[test]
    fn tar_listing_accepts_normal_release() {
        let ok = "aifw-5.97.9/\naifw-5.97.9/bin/\naifw-5.97.9/bin/aifw-api\n./aifw-5.97.9/ui/index.html\n";
        assert!(validate_tar_listing(ok).is_ok());
    }

    // SEC-H11 (#296): the install allowlist is derived from the embedded
    // manifest and must contain the core binaries but not arbitrary names.
    #[test]
    fn binary_allowlist_covers_core_but_not_arbitrary() {
        let allowed: std::collections::HashSet<String> = all_binaries().into_iter().collect();
        assert!(
            allowed.contains("aifw-api"),
            "core binary must be allowlisted"
        );
        assert!(
            allowed.contains("aifw-daemon"),
            "core binary must be allowlisted"
        );
        assert!(
            !allowed.contains("aifw-evil"),
            "arbitrary aifw-* name must not be allowlisted"
        );
        assert!(!allowed.contains("evil"));
    }

    // Regression gate (#188-style): both root-run drivers must refresh the
    // sudoers file from the canonical aifw-setup definition. An in-place
    // tarball upgrade installs new aifw-sudo-* helpers but the aifw-uid
    // updater cannot write sudoers (SEC-C1); these scripts are the only
    // root-context hook that closes the gap. If someone strips the refresh,
    // upgraded boxes silently regress to "sudo: a password is required" on
    // every operation that calls a narrow helper (e.g. DNS resolver apply).
    #[test]
    fn test_restart_driver_refreshes_sudoers() {
        for (name, script) in [
            ("aifw-restart.sh", EMBEDDED_RESTART_SH),
            ("aifw-watchdog.sh", EMBEDDED_WATCHDOG_SH),
        ] {
            assert!(
                script.contains("aifw-setup --print-sudoers"),
                "{name} must regenerate sudoers from aifw-setup"
            );
            assert!(
                script.contains("visudo -cf"),
                "{name} must validate sudoers with visudo before installing"
            );
            assert!(
                script.contains("/usr/local/etc/sudoers.d/aifw"),
                "{name} must install to the canonical sudoers path"
            );
            assert!(
                script.contains("refresh_sudoers"),
                "{name} must invoke the refresh_sudoers routine"
            );
        }
    }

    // #565: the restart driver (new-tarball code, runs as root) must
    // install packages the old updater binary's embedded manifest didn't
    // know about — the only reliable hook on a transitional upgrade.
    #[test]
    fn test_restart_driver_ensures_packages() {
        assert!(
            EMBEDDED_RESTART_SH.contains("aifw-setup --print-packages"),
            "aifw-restart.sh must query the new binary's package list"
        );
        assert!(
            EMBEDDED_RESTART_SH.contains("pkg install"),
            "aifw-restart.sh must install missing packages"
        );
        assert!(
            EMBEDDED_RESTART_SH.contains("ensure_packages"),
            "aifw-restart.sh must invoke the ensure_packages routine"
        );
    }

    // #564: aifw-console is root's login shell; it must exec `-c`
    // commands (ssh/scp/sftp) instead of rendering the menu, and must
    // exit — not busy-loop — when stdin hits EOF.
    #[test]
    fn test_console_passthrough_and_eof_exit() {
        let console = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../freebsd/overlay/usr/local/sbin/aifw-console"),
        )
        .expect("aifw-console exists in the overlay");
        assert!(
            console.contains(r#"exec /bin/sh -c "$@""#),
            "aifw-console must pass -c commands through to a real shell"
        );
        assert!(
            console.contains("read choice || exit"),
            "aifw-console menu must exit on stdin EOF, not busy-loop"
        );
    }

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

    // The compiled-in signing key is the trust root for every self-update:
    // if the committed .pub file is reformatted into something this parser
    // rejects, all appliances fail closed on the next release.
    #[test]
    fn embedded_update_signing_pubkey_parses() {
        let key = embedded_pubkey_b64().expect("embedded public key must parse");
        assert!(
            key.starts_with("RW"),
            "minisign keys are RW-prefixed: {key}"
        );
        assert!(!key.contains(char::is_whitespace));
        assert_eq!(key.len(), 56, "Ed25519 minisign pubkey is 56 base64 chars");
    }

    #[test]
    fn release_assets_require_distinct_checksum_and_signature_sidecars() {
        let release = serde_json::json!({"assets": [
            {"name": "aifw-update-6.0.0-amd64.tar.xz", "browser_download_url": "tar"},
            {"name": "aifw-update-6.0.0-amd64.tar.xz.sha256", "browser_download_url": "sum"},
            {"name": "aifw-update-6.0.0-amd64.tar.xz.sha256.minisig", "browser_download_url": "sig"}
        ]});
        assert_eq!(
            release_asset_urls(&release),
            (Some("tar".into()), Some("sum".into()), Some("sig".into()))
        );
    }

    // Regression gate for #469: every overlay libexec script must carry the
    // execute bit in git. Eight aifw-sudo-* helpers were committed mode 644,
    // build-iso.sh's `cp -a` preserved that onto installed systems, and sudo
    // reports a non-executable helper as "command not found" — bricking the
    // in-app updater on every ISO install. The exec bit lives in the git
    // index, so a plain checkout is enough to assert on.
    #[test]
    fn test_overlay_libexec_scripts_are_executable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../freebsd/overlay/usr/local/libexec");
        let mut checked = 0;
        for entry in std::fs::read_dir(&dir).expect("overlay libexec dir exists") {
            let entry = entry.expect("readable dir entry");
            if !entry.file_type().expect("file type").is_file() {
                continue;
            }
            let mode = entry.metadata().expect("metadata").permissions().mode();
            assert!(
                mode & 0o111 != 0,
                "{} is not executable (mode {:o}) — sudo will report it as \
                 'command not found' on the appliance (#469)",
                entry.path().display(),
                mode
            );
            checked += 1;
        }
        assert!(checked > 0, "no files found in {}", dir.display());
    }

    // The embedded self-heal list must cover every aifw-sudo-* helper in the
    // overlay, or an upgraded box misses helpers that never shipped in its
    // original image (the tarball libexec/ install covers them too, but CI
    // tarballs lacked libexec/ entirely until v5.97.6 — belt and suspenders).
    #[test]
    fn test_embedded_helpers_cover_overlay() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../freebsd/overlay/usr/local/libexec");
        for entry in std::fs::read_dir(&dir).expect("overlay libexec dir exists") {
            let name = entry.expect("readable dir entry").file_name();
            let name = name.to_string_lossy();
            if !name.starts_with("aifw-sudo-") {
                continue;
            }
            assert!(
                EMBEDDED_SUDO_HELPERS.iter().any(|(n, _)| *n == name),
                "{} exists in the overlay but is missing from \
                 EMBEDDED_SUDO_HELPERS in updater.rs",
                name
            );
        }
    }

    // manifest.json `packages` is the source of truth for runtime OS
    // dependencies, but build-iso.sh and deploy.sh carry hardcoded copies
    // (no jq in the ISO build chroot). Keep them in sync (#530 added
    // strongswan this way).
    #[test]
    fn test_manifest_packages_synced_with_build_scripts() {
        let manifest = load_manifest();
        assert!(
            !manifest.packages.is_empty(),
            "manifest.json packages list is empty"
        );
        let build_iso = include_str!("../../freebsd/build-iso.sh");
        let deploy = include_str!("../../freebsd/deploy.sh");
        let iso_line = build_iso
            .lines()
            .find(|l| l.contains("pkg install -y"))
            .expect("build-iso.sh has a pkg install line");
        let deploy_line = deploy
            .lines()
            .find(|l| l.trim_start().starts_with("for pkg in "))
            .expect("deploy.sh has a dependency for-loop");
        for pkg in &manifest.packages {
            let pkg = pkg.as_str();
            assert!(
                iso_line.split_whitespace().any(|w| w == pkg),
                "package {pkg:?} from manifest.json missing from build-iso.sh pkg install line: {iso_line}"
            );
            assert!(
                deploy_line
                    .split_whitespace()
                    .any(|w| w.trim_end_matches(';') == pkg),
                "package {pkg:?} from manifest.json missing from deploy.sh dependency loop: {deploy_line}"
            );
        }
    }
}
