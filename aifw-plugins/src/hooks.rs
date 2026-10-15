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
    /// An authenticated API request is about to reach its handler. A
    /// plugin may answer `Block` (→ 403). The check fails open: if the
    /// plugin times out or panics the request goes through, so this hook
    /// is for policy hints and audit, not for authentication.
    ApiRequest,
    /// A VPN tunnel or peer went up or down
    VpnEvent,
    /// Periodic tick, once a minute
    Timer,
    /// The IDS raised an alert
    IdsAlert,
    /// A multi-WAN gateway changed health state (up / warning / down)
    GatewayEvent,
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
        HookPoint::GatewayEvent,
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
            HookPoint::GatewayEvent => "gateway_event",
        }
    }
}

impl HookPoint {
    /// What fires the hook, for operators reading the plugin page.
    pub fn description(self) -> &'static str {
        match self {
            HookPoint::PostRule => "A packet matched a pf rule with logging enabled (pflog)",
            HookPoint::LogEvent => "An audit-log entry was written (rule, NAT, or config change)",
            HookPoint::ApiRequest => "An authenticated API request arrived (plugins may reject it)",
            HookPoint::VpnEvent => "A WireGuard peer or IPsec tunnel went up or down",
            HookPoint::Timer => "Once a minute",
            HookPoint::IdsAlert => "The IDS raised an alert",
            HookPoint::GatewayEvent => "A multi-WAN gateway went up, degraded, or down",
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

/// The payload varies by hook type. Variant names match [`HookPoint`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HookEventData {
    /// A pflog-logged packet (`PostRule`)
    PostRule {
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
    LogEvent {
        /// What happened (audit action name)
        action: String,
        /// Free-form event details
        details: String,
        /// Component that emitted the event
        source: String,
    },
    /// Authenticated API request (`ApiRequest`)
    ApiRequest {
        /// HTTP method
        method: String,
        /// Request path
        path: String,
        /// Client address, if known
        remote_addr: Option<String>,
    },
    /// VPN state change (`VpnEvent`)
    VpnEvent {
        /// "wireguard" or "ipsec"
        kind: String,
        /// Tunnel name as configured in AiFw
        tunnel_name: String,
        /// Peer name (WireGuard), if the change is about one peer
        peer: Option<String>,
        /// "up" or "down"
        action: String,
        /// Extra context (interface, remote host, last handshake)
        detail: Option<String>,
    },
    /// Gateway health change (`GatewayEvent`)
    GatewayEvent {
        /// Gateway id
        gateway_id: String,
        /// Gateway name as configured in AiFw
        gateway_name: String,
        /// Interface the gateway sits on
        interface: String,
        /// Previous state ("up", "warning", "down", "unknown")
        from_state: Option<String>,
        /// New state
        to_state: String,
        /// Why (metric + threshold that tripped), if known
        reason: Option<String>,
    },
    /// Timer tick (`Timer`)
    Timer {
        /// Unix timestamp (seconds) of the tick
        timestamp: u64,
    },
    /// IDS alert (`IdsAlert`)
    IdsAlert {
        /// Alert id (matches `/api/v1/ids/alerts/{id}`)
        alert_id: String,
        /// When the IDS raised it (RFC 3339)
        timestamp: String,
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
    /// Reject the request. Only honored for `ApiRequest` (→ 403), and
    /// only when the plugin answers within its budget — see
    /// [`HookPoint::ApiRequest`].
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
