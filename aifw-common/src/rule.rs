use crate::types::{Address, Interface, PortRange};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum IpVersion {
    Inet,
    Inet6,
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
    pub fn parse(s: &str) -> crate::Result<Self> {
        match s.to_lowercase().as_str() {
            "inet" | "ipv4" | "4" => Ok(IpVersion::Inet),
            "inet6" | "ipv6" | "6" => Ok(IpVersion::Inet6),
            "both" | "any" | "*" | "" => Ok(IpVersion::Both),
            _ => Err(crate::AifwError::Validation(format!(
                "unknown ip version: {s}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmp6,
    #[serde(rename = "tcp/udp")]
    TcpUdp,
    Esp,
    Ah,
    Gre,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Pass,
    Block,
    BlockDrop,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    In,
    Out,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum RuleStatus {
    Active,
    Disabled,
}

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct StateOptions {
    pub tracking: StateTracking,
    pub policy: Option<StatePolicy>,
    pub adaptive_timeouts: Option<AdaptiveTimeouts>,
    /// TCP timeout in seconds
    pub timeout_tcp: Option<u32>,
    /// UDP timeout in seconds
    pub timeout_udp: Option<u32>,
    /// ICMP timeout in seconds
    pub timeout_icmp: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleMatch {
    pub src_addr: Address,
    pub src_port: Option<PortRange>,
    pub dst_addr: Address,
    pub dst_port: Option<PortRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: Uuid,
    pub priority: i32,
    pub action: Action,
    pub direction: Direction,
    #[serde(default)]
    pub ip_version: IpVersion,
    pub interface: Option<Interface>,
    pub protocol: Protocol,
    pub rule_match: RuleMatch,
    #[serde(default)]
    pub src_invert: bool,
    #[serde(default)]
    pub dst_invert: bool,
    pub log: bool,
    pub quick: bool,
    pub label: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub gateway: Option<String>,
    pub state_options: StateOptions,
    pub status: RuleStatus,
    #[serde(default)]
    pub schedule_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Rule {
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

    pub fn to_pf_rule(&self, anchor: &str) -> String {
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
