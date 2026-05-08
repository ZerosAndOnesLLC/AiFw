//! Narrow-privilege wrappers around helper scripts under
//! `/usr/local/libexec/aifw-sudo-*`. Each helper enforces an internal
//! allowlist of valid arguments — paths, services, interface names — so
//! a compromise of the `aifw` user can't pivot to root via a broad
//! NOPASSWD grant on something like `tee`, `cp`, or `chmod`.
//!
//! Background: GHSA-mjqh-2vx8-7hq7 follow-up #204. Pre-fix sudoers gave
//! `aifw` full-arg NOPASSWD on a dozen utilities — `sudo cp /etc/master.passwd /tmp/x`
//! was a one-liner to root. Each call site that genuinely needs root is
//! migrated through here so the broad grant can be dropped.

use std::path::Path;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const SUDO: &str = "/usr/local/bin/sudo";
const HELPER_WRITE: &str = "/usr/local/libexec/aifw-sudo-write";

/// Atomically write `contents` to `path`, as root, via the
/// `aifw-sudo-write` helper script.
///
/// The helper enforces a closed allowlist of paths — see the script at
/// `freebsd/overlay/usr/local/libexec/aifw-sudo-write`. Adding a new
/// write target requires editing the script, not just the call site.
pub async fn write_file(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let path_str = path.to_str().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "non-utf8 path")
    })?;

    let mut child = Command::new(SUDO)
        .args([HELPER_WRITE, path_str])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(contents).await?;
        stdin.shutdown().await?;
        drop(stdin);
    }

    let output = child.wait_with_output().await?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(std::io::Error::other(format!(
            "aifw-sudo-write failed (exit {}): {}",
            output.status,
            stderr.trim()
        )));
    }
    Ok(())
}
