use crate::types::{Address, Interface, PortRange};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Address family a rule applies to (wire values are lowercase)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum IpVersion {
    /// IPv4 only (pf `inet`)
    Inet,
    /// IPv6 only (pf `inet6`)
    Inet6,
    /// Both families — no address-family keyword is emitted, matching pf's default
    #[default]
    Both,
}

impl std::fmt::Display for IpVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpVersion::Inet => write!(f, "inet"),
            IpVersion::Inet6 => write!(f, "inet6"),
            IpVersion::Both => write!(f, "both"),
        }
    }
}

impl IpVersion {
    /// Parse an address family from a string, case-insensitively. Accepts
    /// aliases ("ipv4"/"4", "ipv6"/"6", "any"/"*"/""/"inet46" for both).
    /// Fails with a validation error on any other input.
    pub fn parse(s: &str) -> crate::Result<Self> {
        match s.to_lowercase().as_str() {
            "inet" | "ipv4" | "4" => Ok(IpVersion::Inet),
            "inet6" | "ipv6" | "6" => Ok(IpVersion::Inet6),
            // "inet46" is the legacy web-UI value for dual-family (#472)
            "both" | "any" | "*" | "" | "inet46" => Ok(IpVersion::Both),
            _ => Err(crate::AifwError::Validation(format!(
                "unknown ip version: {s}"
            ))),
        }
    }
}

/// IP protocol a rule matches (wire values are lowercase; TcpUdp is "tcp/udp")
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// TCP
    Tcp,
    /// UDP
    Udp,
    /// ICMP (IPv4)
    Icmp,
    /// ICMPv6
    Icmp6,
    /// TCP and UDP together — renders as pf `{ tcp udp }`
    #[serde(rename = "tcp/udp")]
    TcpUdp,
    /// IPsec ESP (Encapsulating Security Payload)
    Esp,
    /// IPsec AH (Authentication Header)
    Ah,
    /// GRE tunneling
    Gre,
    /// Any protocol — no `proto` keyword is emitted in the pf rule
    Any,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Icmp => write!(f, "icmp"),
            Protocol::Icmp6 => write!(f, "icmp6"),
            Protocol::TcpUdp => write!(f, "{{ tcp udp }}"),
            Protocol::Esp => write!(f, "esp"),
            Protocol::Ah => write!(f, "ah"),
            Protocol::Gre => write!(f, "gre"),
            Protocol::Any => write!(f, "any"),
        }
    }
}

impl Protocol {
    /// Parse a protocol from a string, case-insensitively. Accepts aliases
    /// for TcpUdp ("tcpudp", "tcp+udp", "{ tcp udp }") and Any ("*").
    /// Fails with a validation error on any other input.
    pub fn parse(s: &str) -> crate::Result<Self> {
        match s.to_lowercase().as_str() {
            "tcp" => Ok(Protocol::Tcp),
            "udp" => Ok(Protocol::Udp),
            "icmp" => Ok(Protocol::Icmp),
            "icmp6" => Ok(Protocol::Icmp6),
            "tcp/udp" | "tcpudp" | "tcp+udp" | "{ tcp udp }" | "{tcp udp}" => Ok(Protocol::TcpUdp),
            "esp" => Ok(Protocol::Esp),
            "ah" => Ok(Protocol::Ah),
            "gre" => Ok(Protocol::Gre),
            "any" | "*" => Ok(Protocol::Any),
            _ => Err(crate::AifwError::Validation(format!(
                "unknown protocol: {s}"
            ))),
        }
    }
}

/// What a rule does with matching traffic (wire values are lowercase)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    /// Allow the traffic
    Pass,
    /// Block the traffic (pf default block behavior); block rules always log
    Block,
    /// Block and silently drop the packet (pf `block drop`)
    BlockDrop,
    /// Block and send TCP RST / ICMP unreachable back (pf `block return`)
    BlockReturn,
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Action::Pass => write!(f, "pass"),
            Action::Block => write!(f, "block"),
            Action::BlockDrop => write!(f, "block drop"),
            Action::BlockReturn => write!(f, "block return"),
        }
    }
}

impl Action {
    /// Stable string identity used by the DB layer + config snapshots.
    /// Decoupled from `Display` (which produces pf-syntax with whitespace)
    /// and from `format!("{:?}")` (which depends on the Rust enum-variant
    /// name and would silently break on a rename).
    pub fn as_db_str(&self) -> &'static str {
        match self {
            Action::Pass => "pass",
            Action::Block => "block",
            Action::BlockDrop => "block_drop",
            Action::BlockReturn => "block_return",
        }
    }

    /// Parse the stable DB-string identity produced by `as_db_str`
    /// (plus legacy "blockdrop"/"blockreturn" spellings).
    /// Returns None for unrecognized values.
    pub fn parse_db(s: &str) -> Option<Self> {
        match s {
            "pass" => Some(Action::Pass),
            "block" => Some(Action::Block),
            "block_drop" | "blockdrop" => Some(Action::BlockDrop),
            "block_return" | "blockreturn" => Some(Action::BlockReturn),
            _ => None,
        }
    }
}

/// Traffic direction a rule matches (wire values are lowercase)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Inbound traffic only
    In,
    /// Outbound traffic only
    Out,
    /// Either direction — no direction keyword is emitted in the pf rule
    Any,
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Direction::In => write!(f, "in"),
            Direction::Out => write!(f, "out"),
            Direction::Any => write!(f, ""),
        }
    }
}

/// Whether a rule is applied to pf (wire values are lowercase)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleStatus {
    /// Rule is loaded into the pf anchor
    Active,
    /// Rule is stored but not loaded into pf
    Disabled,
}

/// pf state-tracking mode for a rule (wire values are snake_case)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum StateTracking {
    /// No state tracking
    None,
    /// Standard keep state
    #[default]
    KeepState,
    /// Modulate state (randomize ISN for TCP)
    ModulateState,
    /// SYN proxy state (proxy TCP handshake)
    SynproxyState,
}

impl std::fmt::Display for StateTracking {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StateTracking::None => write!(f, ""),
            StateTracking::KeepState => write!(f, "keep state"),
            StateTracking::ModulateState => write!(f, "modulate state"),
            StateTracking::SynproxyState => write!(f, "synproxy state"),
        }
    }
}

/// pf state-binding policy (wire values are snake_case)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StatePolicy {
    /// State is bound to the interface
    IfBound,
    /// State floats between interfaces
    Floating,
}

impl std::fmt::Display for StatePolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StatePolicy::IfBound => write!(f, "if-bound"),
            StatePolicy::Floating => write!(f, "floating"),
        }
    }
}

/// pf adaptive state-timeout thresholds (adaptive.start / adaptive.end):
/// state timeouts scale down linearly between the two counts
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdaptiveTimeouts {
    /// Start adapting when state count exceeds this
    pub start: u32,
    /// All timeouts become zero at this state count
    pub end: u32,
}

impl std::fmt::Display for AdaptiveTimeouts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "({}, {})", self.start, self.end)
    }
}

/// State-tracking options attached to a rule (only emitted for pass rules)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct StateOptions {
    /// State-tracking mode (defaults to keep state)
    pub tracking: StateTracking,
    /// State-binding policy; None uses the pf global default
    pub policy: Option<StatePolicy>,
    /// Adaptive timeout thresholds; None disables adaptive scaling
    pub adaptive_timeouts: Option<AdaptiveTimeouts>,
    /// TCP timeout in seconds
    pub timeout_tcp: Option<u32>,
    /// UDP timeout in seconds
    pub timeout_udp: Option<u32>,
    /// ICMP timeout in seconds
    pub timeout_icmp: Option<u32>,
}

/// Source/destination match criteria of a rule
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleMatch {
    /// Source address to match
    pub src_addr: Address,
    /// Source port or port range; None matches any source port
    pub src_port: Option<PortRange>,
    /// Destination address to match
    pub dst_addr: Address,
    /// Destination port or port range; None matches any destination port
    pub dst_port: Option<PortRange>,
}

/// A firewall filter rule, stored in the DB and rendered to pf syntax
/// via `to_pf_rule`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Unique identifier
    pub id: Uuid,
    /// Ordering within the anchor — lower values are evaluated first (default 100)
    pub priority: i32,
    /// Pass or block behavior for matching traffic
    pub action: Action,
    /// Traffic direction to match
    pub direction: Direction,
    /// Address family to match (defaults to both)
    #[serde(default)]
    pub ip_version: IpVersion,
    /// Interface the rule applies on; None applies to all interfaces
    pub interface: Option<Interface>,
    /// IP protocol to match
    pub protocol: Protocol,
    /// Source/destination address and port criteria
    pub rule_match: RuleMatch,
    /// Negate the source match (pf `!` prefix)
    #[serde(default)]
    pub src_invert: bool,
    /// Negate the destination match (pf `!` prefix)
    #[serde(default)]
    pub dst_invert: bool,
    /// Log matching packets to pflog; block rules log regardless of this flag
    pub log: bool,
    /// Stop rule evaluation on match (pf `quick`; default true)
    pub quick: bool,
    /// pf rule label used for per-rule counters and log correlation
    pub label: Option<String>,
    /// Free-form admin note; not emitted into the pf rule
    #[serde(default)]
    pub description: Option<String>,
    /// Multi-WAN gateway id for policy-based routing (#540). Persisted, and
    /// compiled into pf `route-to (iface next_hop)` by the rule engine after
    /// resolving the gateway record. `None` uses default routing. A deleted
    /// or down gateway falls back to default routing at compile time.
    #[serde(default)]
    pub gateway: Option<String>,
    /// State-tracking options (only emitted for pass rules)
    pub state_options: StateOptions,
    /// Active (loaded into pf) or disabled
    pub status: RuleStatus,
    /// Time schedule that enables/disables this rule; None means always on
    #[serde(default)]
    pub schedule_id: Option<String>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp
    pub updated_at: DateTime<Utc>,
}

impl Rule {
    /// Create an active rule with defaults: priority 100, both address
    /// families, all interfaces, quick on, no logging, keep-state tracking
    pub fn new(
        action: Action,
        direction: Direction,
        protocol: Protocol,
        rule_match: RuleMatch,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            priority: 100,
            action,
            direction,
            ip_version: IpVersion::default(),
            interface: None,
            protocol,
            rule_match,
            src_invert: false,
            dst_invert: false,
            log: false,
            quick: true,
            label: None,
            description: None,
            gateway: None,
            state_options: StateOptions::default(),
            status: RuleStatus::Active,
            schedule_id: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Render this rule as a single line of pf filter syntax.
    /// Block rules always get `log` so blocked traffic shows up in pflog;
    /// state options are only emitted for pass rules. The `anchor` argument
    /// is unused here — callers place the rendered rule into the anchor.
    pub fn to_pf_rule(&self, anchor: &str) -> String {
        self.to_pf_rule_routed(anchor, None)
    }

    /// Render with an optional resolved policy-routing gateway (#540):
    /// emits pf `route-to (iface next_hop)` after the interface clause.
    /// Only pass rules route — route-to is meaningless on block — and the
    /// caller (rule engine) is responsible for resolving/validating the
    /// gateway record before passing it here.
    pub fn to_pf_rule_routed(&self, anchor: &str, route_to: Option<(&str, &str)>) -> String {
        let _ = anchor;
        let mut parts = Vec::new();

        // action
        parts.push(self.action.to_string());

        // direction
        let dir = self.direction.to_string();
        if !dir.is_empty() {
            parts.push(dir);
        }

        // log (must come before quick in pf syntax)
        // Block rules always log so blocked traffic is visible in pflog
        if self.log || self.action == Action::Block {
            parts.push("log".to_string());
        }

        // quick
        if self.quick {
            parts.push("quick".to_string());
        }

        // interface
        if let Some(ref iface) = self.interface {
            parts.push(format!("on {iface}"));
        }

        // policy routing (#540) — pf grammar places route-to after the
        // interface clause and before the address family
        if let Some((gw_iface, next_hop)) = route_to
            && self.action == Action::Pass
        {
            parts.push(format!("route-to ({gw_iface} {next_hop})"));
        }

        // address family — must precede `proto` in pf grammar
        match self.ip_version {
            IpVersion::Inet => parts.push("inet".to_string()),
            IpVersion::Inet6 => parts.push("inet6".to_string()),
            IpVersion::Both => {} // pf default is to match both families
        }

        // protocol
        if self.protocol != Protocol::Any {
            parts.push(format!("proto {}", self.protocol));
        }

        // source — `!` prefix for invert per pf grammar
        let src = &self.rule_match.src_addr;
        let src_neg = if self.src_invert { "! " } else { "" };
        if *src != Address::Any {
            match &self.rule_match.src_port {
                Some(port) => parts.push(format!("from {src_neg}{src} port {port}")),
                None => parts.push(format!("from {src_neg}{src}")),
            }
        }

        // destination
        let dst = &self.rule_match.dst_addr;
        let dst_neg = if self.dst_invert { "! " } else { "" };
        if *dst != Address::Any {
            match &self.rule_match.dst_port {
                Some(port) => parts.push(format!("to {dst_neg}{dst} port {port}")),
                None => parts.push(format!("to {dst_neg}{dst}")),
            }
        } else if let Some(ref port) = self.rule_match.dst_port {
            parts.push(format!("to any port {port}"));
        }

        // state tracking (only valid for pass rules)
        let state_str = self.state_options.tracking.to_string();
        if !state_str.is_empty() && self.action == Action::Pass {
            let mut state_part = state_str;
            if let Some(ref policy) = self.state_options.policy {
                state_part.push_str(&format!(" ({policy})"));
            }
            if let Some(ref adaptive) = self.state_options.adaptive_timeouts {
                state_part.push_str(&format!(
                    " (adaptive.start {}, adaptive.end {})",
                    adaptive.start, adaptive.end
                ));
            }
            parts.push(state_part);
        }

        // label
        if let Some(ref label) = self.label {
            parts.push(format!("label \"{label}\""));
        }

        let _ = anchor; // anchor is used by the caller to place the rule
        parts.join(" ")
    }
}
