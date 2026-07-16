use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A logical WAN container bound to a FreeBSD FIB number.
///
/// Each RoutingInstance maps 1:1 to a FIB (Juniper routing-instance analogue).
/// Interfaces are assigned to the instance via `ifconfig fib N` at boot and on change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingInstance {
    /// Unique instance identifier
    pub id: Uuid,
    /// Human-readable instance name (unique)
    pub name: String,
    /// FreeBSD FIB number this instance owns (0 = system default table)
    pub fib_number: u32,
    /// Optional free-form description
    pub description: Option<String>,
    /// True for the default instance (FIB 0) or any instance that must remain
    /// reachable for management traffic. Guards against lock-out on policy changes.
    pub mgmt_reachable: bool,
    /// Current lifecycle state (active/idle/disabled)
    pub status: InstanceStatus,
    /// When the instance was created
    pub created_at: DateTime<Utc>,
    /// When the instance was last modified
    pub updated_at: DateTime<Utc>,
}

/// Lifecycle state of a RoutingInstance (serialized as snake_case)
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
    /// Canonical lowercase string used in the DB and API ("active", "idle", "disabled")
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Idle => "idle",
            Self::Disabled => "disabled",
        }
    }

    /// Case-insensitive parse of the canonical string; `None` for anything else
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
    /// Instance the interface belongs to
    pub instance_id: Uuid,
    /// Interface name (e.g. "igb0")
    pub interface: String,
}

/// UUID of the built-in default instance (FIB 0). Seeded on first migration.
pub const DEFAULT_INSTANCE_ID: Uuid = Uuid::from_u128(0x6169_6677_0000_0000_0000_0000_0000_0000);
/// Name of the built-in default instance
pub const DEFAULT_INSTANCE_NAME: &str = "default";
/// FIB number of the built-in default instance (the system routing table)
pub const DEFAULT_FIB_NUMBER: u32 = 0;

/// A monitored next-hop within a RoutingInstance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Gateway {
    /// Unique gateway identifier
    pub id: Uuid,
    /// Human-readable gateway name
    pub name: String,
    /// RoutingInstance (FIB) this gateway belongs to
    pub instance_id: Uuid,
    /// Egress interface (e.g. "igb0")
    pub interface: String,
    /// Next-hop IP address traffic is routed to
    pub next_hop: String,
    /// IP version of the gateway ("v4" or "v6")
    pub ip_version: String,
    /// Health-probe type: "icmp", "tcp", "http", or "dns" (unknown values fall back to icmp)
    pub monitor_kind: String,
    /// Host/IP/URL to probe; `None` = probe the next hop itself
    pub monitor_target: Option<String>,
    /// Port for tcp/dns probes; `None` = probe default (53 for dns)
    pub monitor_port: Option<u16>,
    /// Probe expectation: HTTP status code for http probes (default 200),
    /// query domain for dns probes (default "example.com")
    pub monitor_expect: Option<String>,
    /// Milliseconds between probes (floored to 100 ms)
    pub interval_ms: u64,
    /// Per-probe timeout in milliseconds
    pub timeout_ms: u64,
    /// Loss percentage above which the gateway degrades to warning
    pub loss_pct_down: f64,
    /// Loss percentage the gateway must stay at or below to recover to up
    pub loss_pct_up: f64,
    /// Latency threshold (ms) for degrading; stored but not yet evaluated by the probe loop
    pub latency_ms_down: Option<u64>,
    /// Latency threshold (ms) for recovery; stored but not yet evaluated by the probe loop
    pub latency_ms_up: Option<u64>,
    /// Consecutive failed probes required to transition to down
    pub consec_fail_down: u32,
    /// Consecutive successful probes required to transition back to up
    pub consec_ok_up: u32,
    /// Relative weight for load-balancing across group members
    pub weight: u32,
    /// Hold-down after a state change to suppress flapping, in seconds
    pub dampening_secs: u32,
    /// DSCP value to tag traffic steered through this gateway; `None` = no tagging
    pub dscp_tag: Option<u8>,
    /// Whether health monitoring is active for this gateway
    pub enabled: bool,
    /// Current health state as judged by the probe loop
    pub state: GatewayState,
    /// Round-trip time of the most recent probe window, in ms
    pub last_rtt_ms: Option<f64>,
    /// Jitter of the most recent probe window, in ms
    pub last_jitter_ms: Option<f64>,
    /// Packet loss over the recent probe window, in percent
    pub last_loss_pct: Option<f64>,
    /// Estimated MOS voice-quality score (1.0-4.5) from recent probes
    pub last_mos: Option<f64>,
    /// When the gateway was last probed; `None` if never
    pub last_probe_ts: Option<DateTime<Utc>>,
    /// When the gateway was created
    pub created_at: DateTime<Utc>,
    /// When the gateway was last modified
    pub updated_at: DateTime<Utc>,
}

/// Health state of a Gateway, driven by the background probe loop (serialized as snake_case)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayState {
    /// Healthy — probes succeeding within thresholds
    Up,
    /// Degraded — reachable but loss above the configured threshold
    Warning,
    /// Failed — consecutive probe failures reached the down threshold
    Down,
    /// Not yet probed (initial state)
    Unknown,
}

impl GatewayState {
    /// Canonical lowercase string used in the DB and API ("up", "warning", "down", "unknown")
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Up => "up",
            Self::Warning => "warning",
            Self::Down => "down",
            Self::Unknown => "unknown",
        }
    }
    /// Case-insensitive parse of the canonical string; `None` for anything else
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

/// A recorded gateway state transition, persisted for history and broadcast to subscribers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayEvent {
    /// Auto-increment row ID (0 before the event is persisted)
    pub id: i64,
    /// Gateway that changed state
    pub gateway_id: Uuid,
    /// When the transition occurred
    pub ts: DateTime<Utc>,
    /// State before the transition; `None` if unrecorded
    pub from_state: Option<GatewayState>,
    /// State after the transition
    pub to_state: GatewayState,
    /// Probe error message that triggered the change, if any
    pub reason: Option<String>,
    /// JSON snapshot of probe metrics (rtt/jitter/loss/mos/consec counters) at transition time
    pub probe_snapshot_json: Option<String>,
}

/// Member-selection strategy for a GatewayGroup (serialized as snake_case)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GroupPolicy {
    /// Strict tier order, first healthy gateway wins.
    Failover,
    /// Weighted round-robin inside a tier.
    WeightedLb,
    /// Weight scaled by live MOS/RTT health.
    Adaptive,
    /// Flow-hash distribution across all healthy members.
    LoadBalance,
}

impl GroupPolicy {
    /// Canonical lowercase string used in the DB and API
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Failover => "failover",
            Self::WeightedLb => "weighted_lb",
            Self::Adaptive => "adaptive",
            Self::LoadBalance => "load_balance",
        }
    }
    /// Case-insensitive parse; accepts aliases ("weighted", "load-balance", "lb"). `None` for anything else
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "failover" => Some(Self::Failover),
            "weighted_lb" | "weighted" => Some(Self::WeightedLb),
            "adaptive" => Some(Self::Adaptive),
            "load_balance" | "load-balance" | "lb" => Some(Self::LoadBalance),
            _ => None,
        }
    }
}

/// Flow-affinity mode for load-balanced traffic (serialized as snake_case)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StickyMode {
    /// No affinity — each flow may pick a different gateway
    None,
    /// Pin flows from the same source address to the same gateway
    Src,
    /// Pin flows with the same 5-tuple (src/dst addr+port, protocol) to the same gateway
    FiveTuple,
}

impl StickyMode {
    /// Canonical lowercase string used in the DB and API ("none", "src", "five_tuple")
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Src => "src",
            Self::FiveTuple => "five_tuple",
        }
    }
    /// Case-insensitive parse; accepts aliases ("five-tuple", "5tuple"). `None` for anything else
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "none" => Some(Self::None),
            "src" => Some(Self::Src),
            "five_tuple" | "five-tuple" | "5tuple" => Some(Self::FiveTuple),
            _ => None,
        }
    }
}

/// A named set of gateways with a shared failover/load-balancing policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayGroup {
    /// Unique group identifier
    pub id: Uuid,
    /// Human-readable group name
    pub name: String,
    /// How traffic is distributed across members
    pub policy: GroupPolicy,
    /// Return traffic to a higher-priority member when it recovers
    pub preempt: bool,
    /// Flow-affinity mode applied to balanced traffic
    pub sticky: StickyMode,
    /// Minimum milliseconds between group re-selections, to damp flapping
    pub hysteresis_ms: u32,
    /// Kill existing pf states on failover so flows re-route immediately
    pub kill_states_on_failover: bool,
    /// When the group was created
    pub created_at: DateTime<Utc>,
    /// When the group was last modified
    pub updated_at: DateTime<Utc>,
}

/// Membership of a Gateway in a GatewayGroup with its tier and weight
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupMember {
    /// Group the gateway belongs to
    pub group_id: Uuid,
    /// Member gateway
    pub gateway_id: Uuid,
    /// Priority tier — lower tiers are preferred; higher tiers are failover targets
    pub tier: u32,
    /// Relative load-balancing weight within the tier
    pub weight: u32,
}

/// Policy routing rule. Matches traffic on 5-tuple + metadata and steers it to a
/// RoutingInstance (FIB), Gateway (route-to), or GatewayGroup (load-balance).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Unique rule identifier
    pub id: Uuid,
    /// Evaluation order — lower values are matched first
    pub priority: i64,
    /// Human-readable rule name
    pub name: String,
    /// Whether the rule is enforced
    pub status: String, // active | disabled
    /// IP family the rule applies to
    pub ip_version: String, // v4 | v6 | both
    /// Ingress interface to match; `None` = any interface
    pub iface_in: Option<String>,
    /// Source address/CIDR/alias to match ("any" for all)
    pub src_addr: String,
    /// Destination address/CIDR/alias to match ("any" for all)
    pub dst_addr: String,
    /// Source port or port range to match; `None` = any
    pub src_port: Option<String>,
    /// Destination port or port range to match; `None` = any
    pub dst_port: Option<String>,
    /// Transport protocol to match
    pub protocol: String, // any | tcp | udp | icmp
    /// Incoming DSCP value to match; `None` = any
    pub dscp_in: Option<u8>,
    /// Destination geo-IP country code to match; `None` = any
    pub geoip_country: Option<String>,
    /// Time schedule restricting when the rule is active; `None` = always
    pub schedule_id: Option<String>,
    /// What `target_id` refers to
    pub action_kind: String, // set_instance | set_gateway | set_group
    /// ID of the RoutingInstance, Gateway, or GatewayGroup traffic is steered to
    pub target_id: Uuid,
    /// Flow-affinity mode applied to steered traffic
    pub sticky: StickyMode,
    /// Alternative target used when the primary target is down; `None` = no fallback
    pub fallback_target_id: Option<Uuid>,
    /// Optional free-form description
    pub description: Option<String>,
    /// When the rule was created
    pub created_at: DateTime<Utc>,
    /// When the rule was last modified
    pub updated_at: DateTime<Utc>,
}

/// Cross-FIB leak: allows specified traffic from one RoutingInstance to reach
/// prefixes in another (Juniper rib-groups analogue).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteLeak {
    /// Unique leak identifier
    pub id: Uuid,
    /// Human-readable leak name
    pub name: String,
    /// Instance the traffic originates in
    pub src_instance_id: Uuid,
    /// Instance whose prefixes become reachable
    pub dst_instance_id: Uuid,
    /// Destination prefix (CIDR) allowed to cross instances
    pub prefix: String,
    /// Transport protocol allowed ("any", "tcp", "udp", ...)
    pub protocol: String,
    /// Port or port range restriction; `None` = all ports
    pub ports: Option<String>,
    /// Whether return traffic is also leaked
    pub direction: String, // bidirectional | one_way
    /// Whether the leak is compiled into pf rules
    pub enabled: bool,
    /// When the leak was created
    pub created_at: DateTime<Utc>,
    /// When the leak was last modified
    pub updated_at: DateTime<Utc>,
}
