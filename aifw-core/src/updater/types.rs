//! `UpdaterError`, `AifwUpdateInfo` and small result helpers.

use serde::{Deserialize, Serialize};

/// Describe a failed best-effort privileged step, or `None` on success.
///
/// The `crate::sudo::*` wrappers (and raw `Command::output()`) return
/// `Ok(Output)` even when the command exits non-zero, so a bare
/// `let _ =` used to hide both spawn errors and failed commands
/// (QUAL-H1 #421). Callers log the returned description and continue —
/// these steps stay non-fatal by design.
pub(super) fn step_failure(result: &std::io::Result<std::process::Output>) -> Option<String> {
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
    /// The release's binaries need a newer FreeBSD than the running one.
    /// Raised before any file is swapped, so the current install is intact.
    #[error(
        "this release requires FreeBSD {required} but this system runs {current} — upgrade the OS first (System → Updates), then install the AiFw update"
    )]
    OsUpgradeRequired {
        /// Minimum FreeBSD release the update's binaries link against
        required: String,
        /// FreeBSD release currently running
        current: String,
    },
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
    /// Minimum FreeBSD release the update's binaries need, parsed from the
    /// `Requires-OS:` line in the release notes (e.g. "15.1"). None for
    /// releases published before OS stamping.
    #[serde(default)]
    pub required_os: Option<String>,
    /// True when `required_os` is newer than the running FreeBSD release.
    /// The UI/CLI must steer the operator to the OS upgrade flow instead of
    /// the AiFw install; the installer refuses anyway (#612). Since #624
    /// this only occurs when NO OS-compatible release exists at all.
    #[serde(default)]
    pub os_upgrade_required: bool,
    /// Newest published version the running OS can NOT execute (#624),
    /// when one exists above `latest_version`. Drives the OS-upgrade card
    /// while `latest_version` stays independently installable.
    #[serde(default)]
    pub blocked_version: Option<String>,
    /// FreeBSD release `blocked_version` needs, from its Requires-OS stamp.
    #[serde(default)]
    pub blocked_requires_os: Option<String>,
}
