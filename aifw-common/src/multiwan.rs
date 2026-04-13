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
