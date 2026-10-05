use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Where in the firewall the hook fires. Every variant here is wired to a
/// real event source in aifw-api — hooks that nothing fires don't belong in
/// this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HookPoint {
    /// A packet was logged by pf (rules with `log`), read from pflog0
    PostRule,
    /// An audit-log entry was written (rule/NAT/config changes)
    LogEvent,
    /// An authenticated API request is about to reach its handler
    ApiRequest,
    /// A VPN tunnel or peer went up or down
    VpnEvent,
    /// Periodic tick, once a minute
    Timer,
    /// The IDS raised an alert
    IdsAlert,
}

impl HookPoint {
    /// Every hook point, in display order.
    pub const ALL: &'static [HookPoint] = &[
        HookPoint::PostRule,
        HookPoint::LogEvent,
        HookPoint::ApiRequest,
        HookPoint::VpnEvent,
        HookPoint::Timer,
        HookPoint::IdsAlert,
    ];

    /// Stable snake_case identifier (matches the serde form).
    pub fn as_str(self) -> &'static str {
        match self {
            HookPoint::PostRule => "post_rule",
            HookPoint::LogEvent => "log_event",
            HookPoint::ApiRequest => "api_request",
            HookPoint::VpnEvent => "vpn_event",
            HookPoint::Timer => "timer",
            HookPoint::IdsAlert => "ids_alert",
        }
    }
}

impl std::fmt::Display for HookPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
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
    /// A pflog-logged packet (`PostRule`)
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
    /// Audit-log entry (`LogEvent`)
    Log {
        /// What happened (audit action name)
        action: String,
        /// Free-form event details
        details: String,
        /// Component that emitted the event
        source: String,
    },
    /// Authenticated API request (`ApiRequest`)
    Api {
        /// HTTP method
        method: String,
        /// Request path
        path: String,
        /// Client address, if known
        remote_addr: Option<String>,
    },
    /// VPN state change (`VpnEvent`)
    Vpn {
        /// Tunnel/interface name
        tunnel_name: String,
        /// Peer identifier, if known
        peer: Option<String>,
        /// Tunnel state change: "up" or "down"
        action: String,
    },
    /// Timer tick (`Timer`)
    Tick {
        /// Unix timestamp (seconds) of the tick
        timestamp: u64,
    },
    /// IDS alert (`IdsAlert`)
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum HookAction {
    /// Continue normal processing
    #[default]
    Continue,
    /// Reject the request. Only honored for `ApiRequest` (→ 403).
    Block,
    /// Write a line to the plugin's activity log
    Log(String),
    /// Add an IP to a pf table (must be a `plugin_`-prefixed table)
    AddToTable {
        /// Target pf table name
        table: String,
        /// Address to add
        ip: IpAddr,
    },
    /// Remove an IP from a pf table (must be a `plugin_`-prefixed table)
    RemoveFromTable {
        /// Target pf table name
        table: String,
        /// Address to remove
        ip: IpAddr,
    },
    /// Multiple actions
    Multi(Vec<HookAction>),
}
