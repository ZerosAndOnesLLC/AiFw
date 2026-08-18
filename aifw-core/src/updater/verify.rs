//! Signature and checksum verification (minisign pubkey pinned at build time).

use tokio::process::Command;
use tracing::{info, warn};

use super::*;

/// On-disk copy of the release-signing public key. Informational only —
/// provisioned for operators who want to run `minisign -Vm` by hand.
/// Verification always uses the compiled-in key below, so an appliance
/// upgraded from a build that never shipped this file still enforces.
pub(super) const PUBKEY_PATH: &str = "/usr/local/etc/aifw/update-signing.pub";

/// Release-signing public key, compiled in from the repo. Trust is pinned
/// to the running build: a key rotation ships a release signed with the
/// OLD key that embeds the NEW key, so every appliance crosses over by
/// installing that release (see freebsd/RELEASE-SIGNING.md).
pub(super) const EMBEDDED_PUBKEY: &str =
    include_str!("../../../freebsd/overlay/usr/local/etc/aifw/update-signing.pub");

/// The base64 key line of the embedded minisign public key (the line after
/// the "untrusted comment:" header), suitable for `minisign -P`.
pub(super) fn embedded_pubkey_b64() -> Result<&'static str, UpdaterError> {
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

pub(super) async fn verify_minisign_checksum(
    checksum: &str,
    signature: &str,
) -> Result<(), UpdaterError> {
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

/// Parse the hex digest from a checksum file line.
///
/// Exposed as `extract_hash_pub` for use by the API's local-install handler
/// which needs to strip the filename part from an uploaded .sha256 sidecar
/// before passing it to `install_from_path`.
pub fn extract_hash_pub(checksum_content: &str) -> String {
    extract_hash(checksum_content)
}

pub(super) fn extract_hash(checksum_content: &str) -> String {
    let line = checksum_content.trim();
    // Format: "SHA256 (file) = hash" (FreeBSD sha256)
    if let Some(pos) = line.rfind("= ") {
        return line[pos + 2..].trim().to_string();
    }
    // Format: "hash  filename" or "hash filename" (sha256sum)
    line.split_whitespace().next().unwrap_or("").to_string()
}

pub(super) async fn verify_sha256(file: &str, expected: &str) -> Result<bool, UpdaterError> {
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
