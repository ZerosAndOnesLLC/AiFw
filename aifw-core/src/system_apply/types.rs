//! Shared data types for the System apply-layer: the `ApplyReport` result,
//! the per-section `*Input` payloads, and the `SystemInfo` readout. Used by
//! both the FreeBSD and stub implementations.

use serde::{Deserialize, Serialize};

/// Outcome of applying one System settings section to the host
#[derive(Debug, Clone, Serialize)]
pub struct ApplyReport {
    /// Whether the apply succeeded
    pub ok: bool,
    /// True when the change only takes effect after a reboot (e.g. console settings)
    pub requires_reboot: bool,
    /// Name of a service that must be restarted for the change to take effect (e.g. "sshd")
    pub requires_service_restart: Option<String>,
    /// Non-fatal warning produced while applying, if any
    pub warning: Option<String>,
}

impl ApplyReport {
    /// Successful apply with no follow-up action needed
    pub fn ok() -> Self {
        Self {
            ok: true,
            requires_reboot: false,
            requires_service_restart: None,
            warning: None,
        }
    }
    /// Successful apply that only takes effect after a reboot
    pub fn ok_requires_reboot() -> Self {
        Self {
            ok: true,
            requires_reboot: true,
            requires_service_restart: None,
            warning: None,
        }
    }
    /// Successful apply that requires restarting the named service to take effect
    pub fn ok_requires_restart(service: &str) -> Self {
        Self {
            ok: true,
            requires_reboot: false,
            requires_service_restart: Some(service.to_string()),
            warning: None,
        }
    }
    /// Successful apply (`ok = true`) that carries a non-fatal warning message
    pub fn warn(msg: impl Into<String>) -> Self {
        Self {
            ok: true,
            requires_reboot: false,
            requires_service_restart: None,
            warning: Some(msg.into()),
        }
    }
}

/// Payload for the General system section (identity and time settings)
#[derive(Debug, Clone, Deserialize)]
pub struct GeneralInput {
    /// System hostname (RFC 1123 single label, no dots)
    pub hostname: String,
    /// DNS domain suffix; empty means none
    pub domain: String,
    /// IANA timezone name (e.g. "America/New_York")
    pub timezone: String,
}

/// Payload for the login banner / message-of-the-day section
#[derive(Debug, Clone, Deserialize)]
pub struct BannerInput {
    /// Text shown before login (SSH banner)
    pub login_banner: String,
    /// Message of the day shown after login
    pub motd: String,
}

/// Payload for the console configuration section
#[derive(Debug, Clone, Deserialize)]
pub struct ConsoleInput {
    /// Console type (video/serial/both)
    pub kind: crate::config::ConsoleKind,
    /// Serial console baud rate (9600–115200)
    pub baud: u32,
}

/// Payload for the SSH daemon configuration section
#[derive(Debug, Clone, Deserialize)]
pub struct SshInput {
    /// Whether sshd is enabled
    pub enabled: bool,
    /// TCP port sshd listens on (1–65535)
    pub port: u16,
    /// Whether password authentication is allowed (vs. keys only)
    pub password_auth: bool,
    /// Whether root may log in over SSH
    pub permit_root_login: bool,
}

/// Live host readout for the System dashboard (identity, load, memory, disk, temps)
#[derive(Debug, Clone, Serialize, Default)]
pub struct SystemInfo {
    /// System hostname
    pub hostname: String,
    /// DNS domain suffix; empty means none
    pub domain: String,
    /// Operating system release string
    pub os_version: String,
    /// Kernel version string
    pub kernel: String,
    /// Seconds since boot
    pub uptime_secs: u64,
    /// 1-, 5-, and 15-minute load averages
    pub load_avg: [f64; 3],
    /// CPU model name
    pub cpu_model: String,
    /// Number of logical CPUs
    pub cpu_count: u32,
    /// Current overall CPU utilization as a percentage (0–100)
    pub cpu_usage_pct: f32,
    /// Total physical memory in bytes
    pub mem_total_bytes: u64,
    /// Memory currently in use, in bytes
    pub mem_used_bytes: u64,
    /// Total root filesystem capacity in bytes
    pub disk_total_bytes: u64,
    /// Root filesystem space in use, in bytes
    pub disk_used_bytes: u64,
    /// Per-core CPU temperature readings (empty when unavailable)
    pub temperatures_c: Vec<CpuTemp>,
}

/// Temperature reading for one CPU core
#[derive(Debug, Clone, Serialize)]
pub struct CpuTemp {
    /// Core index the reading belongs to
    pub core: u32,
    /// Temperature in degrees Celsius
    pub celsius: f32,
}
