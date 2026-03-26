use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Where in the firewall pipeline the hook fires
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookPoint {
    /// Before rule evaluation — can modify or short-circuit
    PreRule,
    /// After rule evaluation — observe the result
    PostRule,
    /// New connection established
    ConnectionNew,
    /// Connection state changed to established
    ConnectionEstablished,
    /// Connection closed/expired
    ConnectionClosed,
    /// Audit/log event emitted
    LogEvent,
    /// API request received (before handler)
    ApiRequest,
}

impl std::fmt::Display for HookPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HookPoint::PreRule => write!(f, "pre_rule"),
            HookPoint::PostRule => write!(f, "post_rule"),
            HookPoint::ConnectionNew => write!(f, "connection_new"),
            HookPoint::ConnectionEstablished => write!(f, "connection_established"),
            HookPoint::ConnectionClosed => write!(f, "connection_closed"),
            HookPoint::LogEvent => write!(f, "log_event"),
            HookPoint::ApiRequest => write!(f, "api_request"),
        }
    }
}

/// Event data passed to plugin hooks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HookEvent {
    pub hook: HookPoint,
    pub data: HookEventData,
}

/// The payload varies by hook type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum HookEventData {
    /// Rule evaluation event
    Rule {
        src_ip: Option<IpAddr>,
        dst_ip: Option<IpAddr>,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        protocol: String,
        action: String,
        rule_id: Option<String>,
    },
    /// Connection event
    Connection {
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
        protocol: String,
        state: String,
    },
    /// Log/audit event
    Log {
        action: String,
        details: String,
        source: String,
    },
    /// API request event
    Api {
        method: String,
        path: String,
        remote_addr: Option<String>,
    },
}

/// Action returned by a plugin to influence firewall behavior
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookAction {
    /// Continue normal processing
    Continue,
    /// Block/deny the packet or request
    Block,
    /// Allow/pass the packet or request (skip further checks)
    Allow,
    /// Log this event with extra context
    Log(String),
    /// Add an IP to a pf table (e.g., block list)
    AddToTable { table: String, ip: IpAddr },
    /// Multiple actions
    Multi(Vec<HookAction>),
}

impl Default for HookAction {
    fn default() -> Self {
        HookAction::Continue
    }
}
