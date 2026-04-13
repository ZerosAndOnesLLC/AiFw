use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A logical WAN container bound to a FreeBSD FIB number.
///
/// Each RoutingInstance maps 1:1 to a FIB (Juniper routing-instance analogue).
/// Interfaces are assigned to the instance via `ifconfig fib N` at boot and on change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingInstance {
    pub id: Uuid,
    pub name: String,
    pub fib_number: u32,
    pub description: Option<String>,
    /// True for the default instance (FIB 0) or any instance that must remain
    /// reachable for management traffic. Guards against lock-out on policy changes.
    pub mgmt_reachable: bool,
    pub status: InstanceStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InstanceStatus {
    /// Instance is configured and pf rules active.
    Active,
    /// Instance exists but no gateways/policies are targeting it.
    Idle,
    /// Instance is administratively disabled.
    Disabled,
}

impl InstanceStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Idle => "idle",
            Self::Disabled => "disabled",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "active" => Some(Self::Active),
            "idle" => Some(Self::Idle),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }
}

/// Membership of a physical/virtual interface in a RoutingInstance.
/// The interface is pinned to the instance's FIB via `ifconfig fib N`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstanceMember {
    pub instance_id: Uuid,
    pub interface: String,
}

/// UUID of the built-in default instance (FIB 0). Seeded on first migration.
pub const DEFAULT_INSTANCE_ID: Uuid = Uuid::from_u128(0x6169_6677_0000_0000_0000_0000_0000_0000);
pub const DEFAULT_INSTANCE_NAME: &str = "default";
pub const DEFAULT_FIB_NUMBER: u32 = 0;

/// A monitored next-hop within a RoutingInstance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gateway {
    pub id: Uuid,
    pub name: String,
    pub instance_id: Uuid,
    pub interface: String,
    pub next_hop: String,
    pub ip_version: String,
    pub monitor_kind: String,
    pub monitor_target: Option<String>,
    pub monitor_port: Option<u16>,
    pub monitor_expect: Option<String>,
    pub interval_ms: u64,
    pub timeout_ms: u64,
    pub loss_pct_down: f64,
    pub loss_pct_up: f64,
    pub latency_ms_down: Option<u64>,
    pub latency_ms_up: Option<u64>,
    pub consec_fail_down: u32,
    pub consec_ok_up: u32,
    pub weight: u32,
    pub dampening_secs: u32,
    pub dscp_tag: Option<u8>,
    pub enabled: bool,
    pub state: GatewayState,
    pub last_rtt_ms: Option<f64>,
    pub last_jitter_ms: Option<f64>,
    pub last_loss_pct: Option<f64>,
    pub last_mos: Option<f64>,
    pub last_probe_ts: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayState {
    Up,
    Warning,
    Down,
    Unknown,
}

impl GatewayState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Warning => "warning",
            Self::Down => "down",
            Self::Unknown => "unknown",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "up" => Some(Self::Up),
            "warning" => Some(Self::Warning),
            "down" => Some(Self::Down),
            "unknown" => Some(Self::Unknown),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayEvent {
    pub id: i64,
    pub gateway_id: Uuid,
    pub ts: DateTime<Utc>,
    pub from_state: Option<GatewayState>,
    pub to_state: GatewayState,
    pub reason: Option<String>,
    pub probe_snapshot_json: Option<String>,
}
