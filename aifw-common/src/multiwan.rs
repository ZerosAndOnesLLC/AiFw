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
    /// Latency threshold (ms): RTT at or above this degrades the gateway to
    /// warning, even while probes succeed (#539)
    pub latency_ms_down: Option<u64>,
    /// Latency recovery threshold (ms): RTT must fall to this or below before
    /// the gateway can return to up; RTT between the two thresholds holds the
    /// current state (hysteresis). Defaults to `latency_ms_down` when unset
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

/// Whether a multiwan policy rule is enforced (serialized as lowercase)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum PolicyStatus {
    /// Rule is compiled into pf
    #[default]
    Active,
    /// Rule is stored but not compiled into pf
    Disabled,
}

impl PolicyStatus {
    /// Canonical lowercase string used in the DB and API ("active", "disabled")
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Disabled => "disabled",
        }
    }

    /// Case-insensitive parse of the canonical string; `None` for anything else
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "active" => Some(Self::Active),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }
}

impl std::fmt::Display for PolicyStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// IP family a multiwan policy rule matches (serialized as lowercase)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum MwIpVersion {
    /// IPv4 only (pf `inet`)
    V4,
    /// IPv6 only (pf `inet6`)
    V6,
    /// Both families — no address-family keyword is emitted
    #[default]
    Both,
}

impl MwIpVersion {
    /// Canonical lowercase string used in the DB and API ("v4", "v6", "both")
    pub fn as_str(self) -> &'static str {
        match self {
            Self::V4 => "v4",
            Self::V6 => "v6",
            Self::Both => "both",
        }
    }

    /// Case-insensitive parse of the canonical string; `None` for anything else
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "v4" => Some(Self::V4),
            "v6" => Some(Self::V6),
            "both" => Some(Self::Both),
            _ => None,
        }
    }
}

impl std::fmt::Display for MwIpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Transport protocol a multiwan policy rule or route leak matches
/// (serialized as lowercase)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum MwProtocol {
    /// Any protocol — no `proto` keyword is emitted
    #[default]
    Any,
    /// TCP
    Tcp,
    /// UDP
    Udp,
    /// ICMP
    Icmp,
}

impl MwProtocol {
    /// Canonical lowercase string used in the DB and API ("any", "tcp", "udp", "icmp")
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
        }
    }

    /// Case-insensitive parse of the canonical string; `None` for anything else
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "any" | "" => Some(Self::Any),
            "tcp" => Some(Self::Tcp),
            "udp" => Some(Self::Udp),
            "icmp" => Some(Self::Icmp),
            _ => None,
        }
    }
}

impl std::fmt::Display for MwProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a policy rule's `target_id` refers to (serialized as snake_case)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteAction {
    /// Steer matching traffic into a RoutingInstance (FIB)
    SetInstance,
    /// Route matching traffic out a specific Gateway (pf `route-to`)
    SetGateway,
    /// Load-balance matching traffic across a GatewayGroup
    SetGroup,
}

impl RouteAction {
    /// Canonical snake_case string used in the DB and API
    /// ("set_instance", "set_gateway", "set_group")
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SetInstance => "set_instance",
            Self::SetGateway => "set_gateway",
            Self::SetGroup => "set_group",
        }
    }

    /// Case-insensitive parse of the canonical string; `None` for anything else
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "set_instance" => Some(Self::SetInstance),
            "set_gateway" => Some(Self::SetGateway),
            "set_group" => Some(Self::SetGroup),
            _ => None,
        }
    }
}

impl std::fmt::Display for RouteAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a route leak also allows return traffic (serialized as snake_case)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum LeakDirection {
    /// Traffic is leaked in both directions
    #[default]
    Bidirectional,
    /// Only src-instance → dst-instance traffic is leaked
    OneWay,
}

impl LeakDirection {
    /// Canonical snake_case string used in the DB and API ("bidirectional", "one_way")
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bidirectional => "bidirectional",
            Self::OneWay => "one_way",
        }
    }

    /// Case-insensitive parse of the canonical string; `None` for anything else
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "bidirectional" => Some(Self::Bidirectional),
            "one_way" | "one-way" => Some(Self::OneWay),
            _ => None,
        }
    }
}

impl std::fmt::Display for LeakDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
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
    pub status: PolicyStatus,
    /// IP family the rule applies to
    pub ip_version: MwIpVersion,
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
    pub protocol: MwProtocol,
    /// Incoming DSCP value to match; `None` = any
    pub dscp_in: Option<u8>,
    /// Destination geo-IP country code to match; `None` = any
    pub geoip_country: Option<String>,
    /// Time schedule restricting when the rule is active; `None` = always
    pub schedule_id: Option<String>,
    /// What `target_id` refers to
    pub action_kind: RouteAction,
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
    /// Transport protocol allowed
    pub protocol: MwProtocol,
    /// Port or port range restriction; `None` = all ports
    pub ports: Option<String>,
    /// Whether return traffic is also leaked
    pub direction: LeakDirection,
    /// Whether the leak is compiled into pf rules
    pub enabled: bool,
    /// When the leak was created
    pub created_at: DateTime<Utc>,
    /// When the leak was last modified
    pub updated_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Guard for QUAL-H11 #431: the enum wire values must stay identical to
    /// the strings the DB rows, API clients, and UI already use. A serde
    /// rename or variant rename that changes them would silently break
    /// existing databases and the web UI.
    #[test]
    fn wire_values_are_stable() {
        let cases = [
            (
                serde_json::to_string(&PolicyStatus::Active).unwrap(),
                "\"active\"",
            ),
            (
                serde_json::to_string(&PolicyStatus::Disabled).unwrap(),
                "\"disabled\"",
            ),
            (serde_json::to_string(&MwIpVersion::V4).unwrap(), "\"v4\""),
            (serde_json::to_string(&MwIpVersion::V6).unwrap(), "\"v6\""),
            (
                serde_json::to_string(&MwIpVersion::Both).unwrap(),
                "\"both\"",
            ),
            (serde_json::to_string(&MwProtocol::Any).unwrap(), "\"any\""),
            (serde_json::to_string(&MwProtocol::Tcp).unwrap(), "\"tcp\""),
            (serde_json::to_string(&MwProtocol::Udp).unwrap(), "\"udp\""),
            (
                serde_json::to_string(&MwProtocol::Icmp).unwrap(),
                "\"icmp\"",
            ),
            (
                serde_json::to_string(&RouteAction::SetInstance).unwrap(),
                "\"set_instance\"",
            ),
            (
                serde_json::to_string(&RouteAction::SetGateway).unwrap(),
                "\"set_gateway\"",
            ),
            (
                serde_json::to_string(&RouteAction::SetGroup).unwrap(),
                "\"set_group\"",
            ),
            (
                serde_json::to_string(&LeakDirection::Bidirectional).unwrap(),
                "\"bidirectional\"",
            ),
            (
                serde_json::to_string(&LeakDirection::OneWay).unwrap(),
                "\"one_way\"",
            ),
        ];
        for (got, want) in cases {
            assert_eq!(got, want);
        }
    }

    /// The DB string identity (`as_str`) must match the serde wire value, and
    /// `parse` must round-trip both.
    #[test]
    fn as_str_parse_round_trip() {
        for s in [PolicyStatus::Active, PolicyStatus::Disabled] {
            assert_eq!(PolicyStatus::parse(s.as_str()), Some(s));
        }
        for v in [MwIpVersion::V4, MwIpVersion::V6, MwIpVersion::Both] {
            assert_eq!(MwIpVersion::parse(v.as_str()), Some(v));
        }
        for p in [
            MwProtocol::Any,
            MwProtocol::Tcp,
            MwProtocol::Udp,
            MwProtocol::Icmp,
        ] {
            assert_eq!(MwProtocol::parse(p.as_str()), Some(p));
        }
        for a in [
            RouteAction::SetInstance,
            RouteAction::SetGateway,
            RouteAction::SetGroup,
        ] {
            assert_eq!(RouteAction::parse(a.as_str()), Some(a));
        }
        for d in [LeakDirection::Bidirectional, LeakDirection::OneWay] {
            assert_eq!(LeakDirection::parse(d.as_str()), Some(d));
        }
        assert_eq!(PolicyStatus::parse("bogus"), None);
        assert_eq!(RouteAction::parse("set_nothing"), None);
    }
}
