//! Linux/WSL (dev) implementation: every apply is a no-op returning OK,
//! matching the `PfMock` philosophy, and `collect_info` returns a stub
//! readout. Gated as a whole via `#[cfg(not(target_os = "freebsd"))]` at
//! the module declaration, mirroring `freebsd_impl`.

use super::types::{ApplyReport, BannerInput, ConsoleInput, GeneralInput, SshInput, SystemInfo};

pub async fn apply_general(_i: &GeneralInput) -> ApplyReport {
    ApplyReport::ok()
}

pub async fn apply_banner(_i: &BannerInput) -> ApplyReport {
    ApplyReport::ok()
}

pub async fn apply_console(_i: &ConsoleInput) -> ApplyReport {
    ApplyReport::ok_requires_reboot()
}

pub async fn apply_ssh(_i: &SshInput) -> ApplyReport {
    ApplyReport::ok_requires_restart("sshd")
}

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

pub async fn motd_user_edited_marker_set() -> bool {
    false
}
