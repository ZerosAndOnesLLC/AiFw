//! Linux/WSL (dev) implementation: every apply is a no-op returning OK,
//! matching the `PfMock` philosophy, and `collect_info` returns a stub
//! readout. Gated as a whole via `#[cfg(not(target_os = "freebsd"))]` at
//! the module declaration, mirroring `freebsd_impl`.

use super::types::{ApplyReport, BannerInput, ConsoleInput, GeneralInput, SshInput, SystemInfo};

/// Dev stub for the General section: no-op, always reports success
pub async fn apply_general(_i: &GeneralInput) -> ApplyReport {
    ApplyReport::ok()
}

/// Dev stub for the banner/MOTD section: no-op, always reports success
pub async fn apply_banner(_i: &BannerInput) -> ApplyReport {
    ApplyReport::ok()
}

/// Dev stub for the console section: no-op, reports success requiring a
/// reboot (matching the FreeBSD implementation's contract)
pub async fn apply_console(_i: &ConsoleInput) -> ApplyReport {
    ApplyReport::ok_requires_reboot()
}

/// Dev stub for the SSH section: no-op, reports success requiring an sshd
/// restart (matching the FreeBSD implementation's contract)
pub async fn apply_ssh(_i: &SshInput) -> ApplyReport {
    ApplyReport::ok_requires_restart("sshd")
}

/// Return a fixed dev-host readout (hostname from env/`/etc/hostname`, CPU
/// count from `available_parallelism`, everything else canned values)
pub async fn collect_info() -> SystemInfo {
    SystemInfo {
        hostname: hostname_stub(),
        domain: String::new(),
        os_version: format!("{} (dev)", std::env::consts::OS),
        kernel: "dev-kernel".into(),
        uptime_secs: 0,
        load_avg: [0.0, 0.0, 0.0],
        cpu_model: "dev-cpu".into(),
        cpu_count: num_cpus(),
        cpu_usage_pct: 0.0,
        mem_total_bytes: 8 * 1024 * 1024 * 1024,
        mem_used_bytes: 0,
        disk_total_bytes: 100 * 1024 * 1024 * 1024,
        disk_used_bytes: 0,
        temperatures_c: Vec::new(),
    }
}

fn hostname_stub() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .unwrap_or_else(|| "dev".to_string())
}

fn num_cpus() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

/// Dev stub: always false (on FreeBSD this checks the marker file that
/// records a manual edit of /etc/motd)
pub async fn motd_user_edited_marker_set() -> bool {
    false
}
