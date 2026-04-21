//! FreeBSD apply implementations — filled in Tasks 5–9.
#![cfg(target_os = "freebsd")]

use super::freebsd_helpers::{rewrite_hosts_loopback, rewrite_resolv_conf_search};
use super::{ApplyReport, BannerInput, ConsoleInput, GeneralInput, SshInput, SystemInfo};
use crate::system_apply_helpers::replace_managed_block;

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
        warnings.push(format!(
            "timezone {} not found in /usr/share/zoneinfo",
            i.timezone
        ));
    } else {
        if let Err(e) = sudo_install_from(&zoneinfo, "/etc/localtime", "0644").await {
            warnings.push(format!("/etc/localtime install failed: {}", e));
        }
        if let Err(e) =
            sudo_install_content("/var/db/zoneinfo", i.timezone.as_bytes(), "0644").await
        {
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
    tokio::fs::try_exists("/var/db/aifw/motd.user-edited")
        .await
        .unwrap_or(false)
}

pub async fn apply_ssh(i: &SshInput) -> ApplyReport {
    let mut warnings: Vec<String> = Vec::new();

    // --- sysrc sshd_enable=YES|NO ---
    if let Err(e) = sudo_run(
        "/usr/sbin/sysrc",
        &[&format!(
            "sshd_enable={}",
            if i.enabled { "YES" } else { "NO" }
        )],
    )
    .await
    {
        warnings.push(format!("sysrc sshd_enable failed: {}", e));
    }

    // --- managed block in /etc/ssh/sshd_config ---
    let path = "/etc/ssh/sshd_config";
    let existing = read_best_effort(path).await;
    let block = format!(
        "Port {}\nPasswordAuthentication {}\nPermitRootLogin {}\n",
        i.port,
        if i.password_auth { "yes" } else { "no" },
        if i.permit_root_login { "yes" } else { "no" },
    );
    let updated = replace_managed_block(&existing, "AiFw", &block);
    if let Err(e) = sudo_install_content(path, updated.as_bytes(), "0644").await {
        warnings.push(format!("sshd_config write failed: {}", e));
    }

    // --- service action ---
    let service_action = if i.enabled { "start" } else { "stop" };
    if let Err(e) = sudo_run("/usr/sbin/service", &["sshd", service_action]).await {
        // Ignore "already running" / "not running" style non-zero exits — surface them as hints, not errors.
        warnings.push(format!("service sshd {} failed: {}", service_action, e));
    }
    if i.enabled {
        // Reload after starting so the config changes take effect without dropping connections unnecessarily.
        let _ = sudo_run("/usr/sbin/service", &["sshd", "reload"]).await;
    }

    let mut r = ApplyReport::ok_requires_restart("sshd");
    if !warnings.is_empty() {
        r.warning = Some(warnings.join("; "));
    }
    r
}

pub async fn apply_console(i: &ConsoleInput) -> ApplyReport {
    let console_val = match i.kind {
        crate::config::ConsoleKind::Serial => "comconsole",
        crate::config::ConsoleKind::Dual => "comconsole vidconsole",
        crate::config::ConsoleKind::Video => "vidconsole",
    };
    let block = format!(
        "console=\"{}\"\ncomconsole_speed=\"{}\"\n",
        console_val, i.baud,
    );

    let path = "/boot/loader.conf";
    let existing = read_best_effort(path).await;
    let updated =
        crate::system_apply_helpers::replace_managed_block(&existing, "AiFw console", &block);

    let mut r = ApplyReport::ok_requires_reboot();
    if let Err(e) = sudo_install_content(path, updated.as_bytes(), "0644").await {
        r.warning = Some(format!("/boot/loader.conf write failed: {}", e));
    }
    r
}

pub async fn collect_info() -> SystemInfo {
    let hostname = read_sysctl_str("kern.hostname").unwrap_or_default();
    let os_release = run_stdout("/usr/bin/uname", &["-sr"])
        .await
        .unwrap_or_default();
    let kernel = run_stdout("/usr/bin/uname", &["-v"])
        .await
        .unwrap_or_default();
    let cpu_model = read_sysctl_str("hw.model").unwrap_or_default();
    let cpu_count: u32 = read_sysctl_int("hw.ncpu").unwrap_or(1);
    let mem_total: u64 = read_sysctl_int("hw.physmem").unwrap_or(0);
    let uptime_secs = uptime_from_boottime().unwrap_or(0);
    let load_avg = read_loadavg().unwrap_or([0.0, 0.0, 0.0]);
    let domain = tokio::fs::read_to_string("/etc/resolv.conf")
        .await
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| {
                    l.strip_prefix("search ")
                        .or_else(|| l.strip_prefix("domain "))
                        .map(|v| v.to_string())
                })
                .map(|v| v.split_whitespace().next().unwrap_or("").to_string())
        })
        .unwrap_or_default();
    let (disk_total, disk_used) = df_root().await.unwrap_or((0, 0));
    let (mem_used, _) = mem_used_bytes().unwrap_or((0, 0));
    let temperatures_c = read_cpu_temps(cpu_count);

    SystemInfo {
        hostname,
        domain,
        os_version: os_release.trim().to_string(),
        kernel: kernel.trim().to_string(),
        uptime_secs,
        load_avg,
        cpu_model,
        cpu_count,
        cpu_usage_pct: 0.0, // dual-sample CPU usage is best-effort; skip for v1
        mem_total_bytes: mem_total,
        mem_used_bytes: mem_used,
        disk_total_bytes: disk_total,
        disk_used_bytes: disk_used,
        temperatures_c,
    }
}

async fn run_stdout(cmd: &str, args: &[&str]) -> Option<String> {
    let out = tokio::process::Command::new(cmd)
        .args(args)
        .output()
        .await
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn read_sysctl_str(name: &str) -> Option<String> {
    let out = std::process::Command::new("/sbin/sysctl")
        .args(["-n", name])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn read_sysctl_int<T: std::str::FromStr>(name: &str) -> Option<T> {
    read_sysctl_str(name)?.parse().ok()
}

fn uptime_from_boottime() -> Option<u64> {
    // `sysctl -n kern.boottime` → "{ sec = 1234567890, usec = 0 } ..."
    let s = read_sysctl_str("kern.boottime")?;
    let sec: u64 = s
        .split("sec = ")
        .nth(1)?
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(now.saturating_sub(sec))
}

fn read_loadavg() -> Option<[f64; 3]> {
    // `sysctl -n vm.loadavg` → "{ 0.05 0.10 0.08 }"
    let s = read_sysctl_str("vm.loadavg")?;
    let nums: Vec<f64> = s
        .split_whitespace()
        .filter_map(|w| {
            w.trim_matches(|c: char| !c.is_ascii_digit() && c != '.')
                .parse()
                .ok()
        })
        .collect();
    if nums.len() >= 3 {
        Some([nums[0], nums[1], nums[2]])
    } else {
        None
    }
}

async fn df_root() -> Option<(u64, u64)> {
    // `df -k /` → "Filesystem  1K-blocks  Used  Avail  Capacity  Mounted on"
    let out = run_stdout("/bin/df", &["-k", "/"]).await?;
    let line = out.lines().nth(1)?;
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.len() < 4 {
        return None;
    }
    let total: u64 = cols[1].parse().ok()?;
    let used: u64 = cols[2].parse().ok()?;
    Some((total * 1024, used * 1024))
}

fn mem_used_bytes() -> Option<(u64, u64)> {
    let page_size: u64 = read_sysctl_int("hw.pagesize").unwrap_or(4096);
    let total: u64 = read_sysctl_int("hw.physmem")?;
    let free: u64 = read_sysctl_int("vm.stats.vm.v_free_count")?;
    Some((total.saturating_sub(free * page_size), total))
}

fn read_cpu_temps(n: u32) -> Vec<super::CpuTemp> {
    let mut out = Vec::new();
    for core in 0..n {
        let name = format!("dev.cpu.{}.temperature", core);
        let Some(raw) = read_sysctl_str(&name) else {
            continue;
        };
        // FreeBSD reports "38.0C"
        let celsius: f32 = raw.trim_end_matches('C').parse().unwrap_or(0.0);
        out.push(super::CpuTemp { core, celsius });
    }
    out
}

// ---------- Privileged helpers ----------

const SUDO: &str = "/usr/local/bin/sudo";

/// Run a command under sudo, returning stderr as Err on non-zero exit.
async fn sudo_run(cmd: &str, args: &[&str]) -> Result<(), String> {
    let mut full: Vec<&str> = Vec::with_capacity(args.len() + 1);
    full.push(cmd);
    full.extend(args);
    let out = tokio::process::Command::new(SUDO)
        .args(&full)
        .output()
        .await
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
    tokio::fs::write(&tmp, data)
        .await
        .map_err(|e| format!("tmp write: {}", e))?;
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
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let base = target.rsplit('/').next().unwrap_or("aifw");
    format!("/tmp/aifw.{}.{}.tmp", base, nanos)
}

async fn read_best_effort(path: &str) -> String {
    tokio::fs::read_to_string(path).await.unwrap_or_default()
}
