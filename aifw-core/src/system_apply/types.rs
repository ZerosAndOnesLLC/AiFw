//! Shared data types for the System apply-layer: the `ApplyReport` result,
//! the per-section `*Input` payloads, and the `SystemInfo` readout. Used by
//! both the FreeBSD and stub implementations.

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
