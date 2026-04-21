//! Apply-layer for System settings.
//!
//! Linux/WSL build: every apply is a no-op that returns OK, matching
//! the `PfMock` philosophy. FreeBSD build: writes to /etc/* and
//! /boot/loader.conf and runs service/sysrc commands.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct ApplyReport {
    pub ok: bool,
    pub requires_reboot: bool,
    pub requires_service_restart: Option<String>,
    pub warning: Option<String>,
}

impl ApplyReport {
    pub fn ok() -> Self {
        Self {
            ok: true,
            requires_reboot: false,
            requires_service_restart: None,
            warning: None,
        }
    }
    pub fn ok_requires_reboot() -> Self {
        Self {
            ok: true,
            requires_reboot: true,
            requires_service_restart: None,
            warning: None,
        }
    }
    pub fn ok_requires_restart(service: &str) -> Self {
        Self {
            ok: true,
            requires_reboot: false,
            requires_service_restart: Some(service.to_string()),
            warning: None,
        }
    }
    pub fn warn(msg: impl Into<String>) -> Self {
        Self {
            ok: true,
            requires_reboot: false,
            requires_service_restart: None,
            warning: Some(msg.into()),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct GeneralInput {
    pub hostname: String,
    pub domain: String,
    pub timezone: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct BannerInput {
    pub login_banner: String,
    pub motd: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ConsoleInput {
    pub kind: crate::config::ConsoleKind,
    pub baud: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SshInput {
    pub enabled: bool,
    pub port: u16,
    pub password_auth: bool,
    pub permit_root_login: bool,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct SystemInfo {
    pub hostname: String,
    pub domain: String,
    pub os_version: String,
    pub kernel: String,
    pub uptime_secs: u64,
    pub load_avg: [f64; 3],
    pub cpu_model: String,
    pub cpu_count: u32,
    pub cpu_usage_pct: f32,
    pub mem_total_bytes: u64,
    pub mem_used_bytes: u64,
    pub disk_total_bytes: u64,
    pub disk_used_bytes: u64,
    pub temperatures_c: Vec<CpuTemp>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CpuTemp {
    pub core: u32,
    pub celsius: f32,
}

// ----- Linux/WSL (dev): no-op apply, stub info -----

#[cfg(not(target_os = "freebsd"))]
pub async fn apply_general(_i: &GeneralInput) -> ApplyReport {
    ApplyReport::ok()
}

#[cfg(not(target_os = "freebsd"))]
pub async fn apply_banner(_i: &BannerInput) -> ApplyReport {
    ApplyReport::ok()
}

#[cfg(not(target_os = "freebsd"))]
pub async fn apply_console(_i: &ConsoleInput) -> ApplyReport {
    ApplyReport::ok_requires_reboot()
}

#[cfg(not(target_os = "freebsd"))]
pub async fn apply_ssh(_i: &SshInput) -> ApplyReport {
    ApplyReport::ok_requires_restart("sshd")
}

#[cfg(not(target_os = "freebsd"))]
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

#[cfg(not(target_os = "freebsd"))]
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

#[cfg(not(target_os = "freebsd"))]
fn num_cpus() -> u32 {
    std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1)
}

#[cfg(not(target_os = "freebsd"))]
pub async fn motd_user_edited_marker_set() -> bool {
    false
}

// ----- FreeBSD: real apply (bodies filled in Tasks 5–9) -----

pub mod freebsd_helpers;

#[cfg(target_os = "freebsd")]
mod freebsd_impl;

#[cfg(target_os = "freebsd")]
pub use freebsd_impl::{
    apply_banner, apply_console, apply_general, apply_ssh, collect_info,
    motd_user_edited_marker_set,
};
