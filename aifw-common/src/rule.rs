use crate::types::{Address, Interface, PortRange};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Icmp6,
    Any,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
            Protocol::Icmp => write!(f, "icmp"),
            Protocol::Icmp6 => write!(f, "icmp6"),
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
    pub interface: Option<Interface>,
    pub protocol: Protocol,
    pub rule_match: RuleMatch,
    pub log: bool,
    pub quick: bool,
    pub label: Option<String>,
    pub status: RuleStatus,
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
            interface: None,
            protocol,
            rule_match,
            log: false,
            quick: true,
            label: None,
            status: RuleStatus::Active,
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

        // quick
        if self.quick {
            parts.push("quick".to_string());
        }

        // interface
        if let Some(ref iface) = self.interface {
            parts.push(format!("on {iface}"));
        }

        // protocol
        if self.protocol != Protocol::Any {
            parts.push(format!("proto {}", self.protocol));
        }

        // source
        let src = &self.rule_match.src_addr;
        if *src != Address::Any {
            match &self.rule_match.src_port {
                Some(port) => parts.push(format!("from {src} port {port}")),
                None => parts.push(format!("from {src}")),
            }
        }

        // destination
        let dst = &self.rule_match.dst_addr;
        if *dst != Address::Any {
            match &self.rule_match.dst_port {
                Some(port) => parts.push(format!("to {dst} port {port}")),
                None => parts.push(format!("to {dst}")),
            }
        } else if let Some(ref port) = self.rule_match.dst_port {
            parts.push(format!("to any port {port}"));
        }

        // log
        if self.log {
            parts.push("log".to_string());
        }

        // label
        if let Some(ref label) = self.label {
            parts.push(format!("label \"{label}\""));
        }

        let _ = anchor; // anchor is used by the caller to place the rule
        parts.join(" ")
    }
}
