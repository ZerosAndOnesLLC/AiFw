//! FreeBSD apply implementations — filled in Tasks 5–9.
#![cfg(target_os = "freebsd")]

use super::{ApplyReport, BannerInput, ConsoleInput, GeneralInput, SshInput, SystemInfo};
use super::freebsd_helpers::{rewrite_hosts_loopback, rewrite_resolv_conf_search};

pub async fn apply_general(i: &GeneralInput) -> ApplyReport {
    let mut warnings: Vec<String> = Vec::new();

    // --- hostname: sysrc (persistent) + live ---
    if let Err(e) = sudo_run("/usr/sbin/sysrc", &[&format!("hostname={}", i.hostname)]).await {
        warnings.push(format!("sysrc hostname failed: {}", e));
    }
    if let Err(e) = sudo_run("/bin/hostname", &[&i.hostname]).await {
        warnings.push(format!("live hostname failed: {}", e));
    }

    // --- /etc/hosts loopback line ---
    let hosts_content = read_best_effort("/etc/hosts").await;
    let new_hosts = rewrite_hosts_loopback(&hosts_content, &i.hostname, &i.domain);
    if let Err(e) = sudo_install_content("/etc/hosts", new_hosts.as_bytes(), "0644").await {
        warnings.push(format!("/etc/hosts write failed: {}", e));
    }

    // --- domain: /etc/resolv.conf search line ---
    let resolv_content = read_best_effort("/etc/resolv.conf").await;
    let new_resolv = rewrite_resolv_conf_search(&resolv_content, &i.domain);
    if let Err(e) = sudo_install_content("/etc/resolv.conf", new_resolv.as_bytes(), "0644").await {
        warnings.push(format!("resolv.conf write failed: {}", e));
    }

    // --- timezone: /etc/localtime + /var/db/zoneinfo ---
    let zoneinfo = format!("/usr/share/zoneinfo/{}", i.timezone);
    if !tokio::fs::try_exists(&zoneinfo).await.unwrap_or(false) {
        warnings.push(format!("timezone {} not found in /usr/share/zoneinfo", i.timezone));
    } else {
        if let Err(e) = sudo_install_from(&zoneinfo, "/etc/localtime", "0644").await {
            warnings.push(format!("/etc/localtime install failed: {}", e));
        }
        if let Err(e) = sudo_install_content("/var/db/zoneinfo", i.timezone.as_bytes(), "0644").await {
            warnings.push(format!("/var/db/zoneinfo write failed: {}", e));
        }
    }

    if warnings.is_empty() {
        ApplyReport::ok()
    } else {
        let mut r = ApplyReport::ok();
        r.warning = Some(warnings.join("; "));
        r
    }
}

pub async fn apply_banner(i: &BannerInput) -> ApplyReport {
    let mut warnings: Vec<String> = Vec::new();

    if let Err(e) = sudo_install_content("/etc/issue", i.login_banner.as_bytes(), "0644").await {
        warnings.push(format!("/etc/issue write failed: {}", e));
    }
    if let Err(e) = sudo_install_content("/etc/motd.template", i.motd.as_bytes(), "0644").await {
        warnings.push(format!("/etc/motd.template write failed: {}", e));
    }

    // Create marker so the MOTD-version updater cleanup script skips
    // this appliance — the admin is managing MOTD via the UI.
    if let Err(e) = ensure_motd_marker().await {
        // Marker failure is non-fatal; the banner itself was applied.
        warnings.push(format!("motd marker failed: {}", e));
    }

    if warnings.is_empty() {
        ApplyReport::ok()
    } else {
        let mut r = ApplyReport::ok();
        r.warning = Some(warnings.join("; "));
        r
    }
}

pub async fn motd_user_edited_marker_set() -> bool {
    tokio::fs::try_exists("/var/db/aifw/motd.user-edited").await.unwrap_or(false)
}

// Stubs — filled in Tasks 7-9.
pub async fn apply_console(_i: &ConsoleInput) -> ApplyReport { ApplyReport::ok_requires_reboot() }
pub async fn apply_ssh(_i: &SshInput) -> ApplyReport { ApplyReport::ok_requires_restart("sshd") }
pub async fn collect_info() -> SystemInfo { SystemInfo::default() }

// ---------- Privileged helpers ----------

const SUDO: &str = "/usr/local/bin/sudo";

/// Run a command under sudo, returning stderr as Err on non-zero exit.
async fn sudo_run(cmd: &str, args: &[&str]) -> Result<(), String> {
    let mut full: Vec<&str> = Vec::with_capacity(args.len() + 1);
    full.push(cmd);
    full.extend(args);
    let out = tokio::process::Command::new(SUDO).args(&full).output().await
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(())
}

/// Atomically place `data` at `path` with the given mode via `sudo install`.
/// Writes to a tempfile as the aifw user, then invokes
/// `sudo /usr/bin/install -m <mode> <tmp> <path>` which atomically renames
/// with correct ownership (root:wheel by default).
async fn sudo_install_content(path: &str, data: &[u8], mode: &str) -> Result<(), String> {
    let tmp = make_tmp_path(path);
    tokio::fs::write(&tmp, data).await.map_err(|e| format!("tmp write: {}", e))?;
    let result = sudo_run("/usr/bin/install", &["-m", mode, &tmp, path]).await;
    // Best-effort cleanup regardless of install result.
    let _ = tokio::fs::remove_file(&tmp).await;
    result
}

/// Atomically place an existing file at `path` via `sudo install`.
/// The source must already exist and be readable.
async fn sudo_install_from(src: &str, path: &str, mode: &str) -> Result<(), String> {
    sudo_run("/usr/bin/install", &["-m", mode, src, path]).await
}

/// Create `/var/db/aifw/motd.user-edited` (mode 0644, root-owned).
/// Creates the parent directory if needed. Idempotent.
async fn ensure_motd_marker() -> Result<(), String> {
    // Parent dir — `/var/db/aifw` must exist before install can place the file.
    // `/bin/mkdir` is in the sudoers allowlist.
    let _ = sudo_run("/bin/mkdir", &["-p", "/var/db/aifw"]).await;
    sudo_install_content("/var/db/aifw/motd.user-edited", b"1\n", "0644").await
}

/// Build a tempfile path alongside /tmp so the aifw user can create it.
fn make_tmp_path(target: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    let base = target.rsplit('/').next().unwrap_or("aifw");
    format!("/tmp/aifw.{}.{}.tmp", base, nanos)
}

async fn read_best_effort(path: &str) -> String {
    tokio::fs::read_to_string(path).await.unwrap_or_default()
}
