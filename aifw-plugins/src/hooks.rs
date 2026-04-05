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
    /// DNS query received (rDNS integration)
    DnsQuery,
    /// DNS response sent
    DnsResponse,
    /// DHCP lease assigned (rDHCP integration)
    DhcpLease,
    /// VPN tunnel state change
    VpnEvent,
    /// Scheduled timer tick (cron-like)
    Timer,
    /// IDS alert fired (signature match, anomaly, etc.)
    IdsAlert,
    /// IPS mode dropped a packet
    IdsDrop,
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
            HookPoint::DnsQuery => write!(f, "dns_query"),
            HookPoint::DnsResponse => write!(f, "dns_response"),
            HookPoint::DhcpLease => write!(f, "dhcp_lease"),
            HookPoint::VpnEvent => write!(f, "vpn_event"),
            HookPoint::Timer => write!(f, "timer"),
            HookPoint::IdsAlert => write!(f, "ids_alert"),
            HookPoint::IdsDrop => write!(f, "ids_drop"),
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
    /// DNS query/response event
    Dns {
        query_name: String,
        query_type: String,
        src_ip: Option<IpAddr>,
        response_code: Option<String>,
    },
    /// DHCP lease event
    Dhcp {
        mac_address: String,
        ip_address: IpAddr,
        hostname: Option<String>,
        lease_action: String,  // "assign", "renew", "release"
    },
    /// VPN event
    Vpn {
        tunnel_name: String,
        peer: Option<String>,
        action: String,  // "up", "down", "handshake"
    },
    /// Timer tick
    Tick {
        timestamp: u64,
    },
    /// IDS alert event
    IdsAlertEvent {
        signature_id: Option<u32>,
        signature_msg: String,
        severity: u8,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: Option<u16>,
        dst_port: Option<u16>,
        protocol: String,
        action: String,
        rule_source: String,
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
    /// Remove an IP from a pf table
    RemoveFromTable { table: String, ip: IpAddr },
    /// Modify a value (e.g., rewrite DNS response)
    Modify(String),
    /// Multiple actions
    Multi(Vec<HookAction>),
}

impl Default for HookAction {
    fn default() -> Self {
        HookAction::Continue
    }
}
