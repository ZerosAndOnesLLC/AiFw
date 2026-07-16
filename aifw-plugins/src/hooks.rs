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
    /// Which hook point fired
    pub hook: HookPoint,
    /// Hook-specific payload
    pub data: HookEventData,
}

/// The payload varies by hook type
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum HookEventData {
    /// Rule evaluation event
    Rule {
        /// Source IP, if known
        src_ip: Option<IpAddr>,
        /// Destination IP, if known
        dst_ip: Option<IpAddr>,
        /// Source port, if known
        src_port: Option<u16>,
        /// Destination port, if known
        dst_port: Option<u16>,
        /// Protocol name (e.g. "tcp", "udp")
        protocol: String,
        /// Rule verdict (e.g. "pass", "block")
        action: String,
        /// ID of the matched rule, if known
        rule_id: Option<String>,
    },
    /// Connection event
    Connection {
        /// Source IP
        src_ip: IpAddr,
        /// Destination IP
        dst_ip: IpAddr,
        /// Source port
        src_port: u16,
        /// Destination port
        dst_port: u16,
        /// Protocol name (e.g. "tcp", "udp")
        protocol: String,
        /// Connection state (e.g. "new", "established", "closed")
        state: String,
    },
    /// Log/audit event
    Log {
        /// What happened (audit action name)
        action: String,
        /// Free-form event details
        details: String,
        /// Component that emitted the event
        source: String,
    },
    /// API request event
    Api {
        /// HTTP method
        method: String,
        /// Request path
        path: String,
        /// Client address, if known
        remote_addr: Option<String>,
    },
    /// DNS query/response event
    Dns {
        /// Queried domain name
        query_name: String,
        /// Record type (e.g. "A", "AAAA", "TXT")
        query_type: String,
        /// Client IP that sent the query, if known
        src_ip: Option<IpAddr>,
        /// Response code (e.g. "NOERROR", "NXDOMAIN"); `None` for queries
        response_code: Option<String>,
    },
    /// DHCP lease event
    Dhcp {
        /// Client MAC address
        mac_address: String,
        /// Leased IP address
        ip_address: IpAddr,
        /// Client-reported hostname, if any
        hostname: Option<String>,
        /// Lease lifecycle action
        lease_action: String, // "assign", "renew", "release"
    },
    /// VPN event
    Vpn {
        /// Tunnel/interface name
        tunnel_name: String,
        /// Peer identifier, if known
        peer: Option<String>,
        /// Tunnel state change
        action: String, // "up", "down", "handshake"
    },
    /// Timer tick
    Tick {
        /// Unix timestamp (seconds) of the tick
        timestamp: u64,
    },
    /// IDS alert event
    IdsAlertEvent {
        /// Matched signature ID (SID), if signature-based
        signature_id: Option<u32>,
        /// Signature/alert message text
        signature_msg: String,
        /// Alert severity (lower is more severe, Suricata convention)
        severity: u8,
        /// Source IP
        src_ip: IpAddr,
        /// Destination IP
        dst_ip: IpAddr,
        /// Source port, if applicable
        src_port: Option<u16>,
        /// Destination port, if applicable
        dst_port: Option<u16>,
        /// Protocol name (e.g. "tcp", "udp")
        protocol: String,
        /// What the IDS did (e.g. "alert", "drop")
        action: String,
        /// Ruleset/engine the rule came from
        rule_source: String,
    },
}

/// Action returned by a plugin to influence firewall behavior
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum HookAction {
    /// Continue normal processing
    #[default]
    Continue,
    /// Block/deny the packet or request
    Block,
    /// Allow/pass the packet or request (skip further checks)
    Allow,
    /// Log this event with extra context
    Log(String),
    /// Add an IP to a pf table (e.g., block list)
    AddToTable {
        /// Target pf table name
        table: String,
        /// Address to add
        ip: IpAddr,
    },
    /// Remove an IP from a pf table
    RemoveFromTable {
        /// Target pf table name
        table: String,
        /// Address to remove
        ip: IpAddr,
    },
    /// Modify a value (e.g., rewrite DNS response)
    Modify(String),
    /// Multiple actions
    Multi(Vec<HookAction>),
}
