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
const HELPER_WG: &str = "/usr/local/libexec/aifw-sudo-wg";
const HELPER_FREEBSD_UPDATE: &str = "/usr/local/libexec/aifw-sudo-freebsd-update";
const HELPER_PKG: &str = "/usr/local/libexec/aifw-sudo-pkg";
const HELPER_SERVICE: &str = "/usr/local/libexec/aifw-sudo-service";

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

/// Run `wg <subcommand> <iface> [args...]` as root via the
/// `aifw-sudo-wg` helper.
///
/// The helper restricts `subcommand` to `set` / `show` and `iface` to
/// `wg<N>` patterns; remaining args are passed through. Returns the raw
/// `Output` so callers can inspect stdout (e.g. `wg show … dump`) and
/// surface `stderr` themselves on failure.
pub async fn wg(
    subcommand: &str,
    iface: &str,
    extra_args: &[&str],
) -> std::io::Result<std::process::Output> {
    let mut args: Vec<&str> = vec![HELPER_WG, subcommand, iface];
    args.extend_from_slice(extra_args);
    Command::new(SUDO).args(&args).output().await
}

/// Run `freebsd-update <action> [args...]` as root via the
/// `aifw-sudo-freebsd-update` helper.
///
/// The helper restricts `action` to `updatesready` / `fetch` / `install`
/// and validates the small set of allowed args per action (currently
/// just `--not-running-from-cron` for `fetch`). Returns the raw
/// `Output` so callers can branch on `status.success()` and surface
/// `stderr`/`stdout` themselves.
pub async fn freebsd_update(
    action: &str,
    extra_args: &[&str],
) -> std::io::Result<std::process::Output> {
    let mut args: Vec<&str> = vec![HELPER_FREEBSD_UPDATE, action];
    args.extend_from_slice(extra_args);
    Command::new(SUDO).args(&args).output().await
}

/// Run `pkg <action> [args...]` as root via the `aifw-sudo-pkg` helper.
///
/// The helper restricts `action` to `update` / `install` / `upgrade`
/// and validates each form (`install -y <pkg>...` requires alnum/dot/
/// underscore/plus/hyphen-only package names; `upgrade` must be `-y`
/// or `-n`). Other subcommands and arbitrary flags are denied.
pub async fn pkg(action: &str, extra_args: &[&str]) -> std::io::Result<std::process::Output> {
    let mut args: Vec<&str> = vec![HELPER_PKG, action];
    args.extend_from_slice(extra_args);
    Command::new(SUDO).args(&args).output().await
}

/// Run `service <name> <action>` as root via the `aifw-sudo-service`
/// helper.
///
/// The helper restricts both the service name (closed allowlist of
/// AiFw-managed services + `unbound`/`sshd`) and the action verb
/// (`start` / `stop` / `restart` / `reload` / `status`, plus the
/// `one*` force variants). Adding a new managed service requires
/// updating the helper script's case block.
pub async fn service(name: &str, action: &str) -> std::io::Result<std::process::Output> {
    Command::new(SUDO)
        .args([HELPER_SERVICE, name, action])
        .output()
        .await
}
