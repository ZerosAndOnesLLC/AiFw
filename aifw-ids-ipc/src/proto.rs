//! Wire types for the aifw-ids IPC protocol.

use serde::{Deserialize, Serialize};

/// A request sent from a client (aifw-api) to the aifw-ids service.
///
/// On the wire this is JSON tagged as `{"method": "<snake_case>", "params": ...}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum IpcRequest {
    /// Fetch the current IDS configuration
    GetConfig,
    /// Replace the IDS configuration
    SetConfig {
        /// The full configuration to apply
        config: aifw_common::ids::IdsConfig,
    },
    /// Reload configuration and rules from storage
    Reload,
    /// Fetch runtime engine statistics
    GetStats,
    /// List configured rulesets with rule counts
    ListRulesets,
    /// Look up a single rule
    GetRule {
        /// Rule id (the `ids_rules.id` UUID string)
        id: String,
    },
    /// Enable or disable a single rule
    SetRule {
        /// Rule id (the `ids_rules.id` UUID string)
        id: String,
        /// New enabled state
        enabled: bool,
    },
    /// Fetch the most recent alerts, newest first
    TailAlerts {
        /// Maximum number of alerts to return
        count: u32,
    },
}

/// A response sent from the aifw-ids service back to the client.
///
/// On the wire this is JSON tagged as `{"type": "<snake_case>", "data": ...}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum IpcResponse {
    /// The write request succeeded (SetConfig, Reload, SetRule)
    Ok,
    /// Current IDS configuration (answers GetConfig)
    Config(aifw_common::ids::IdsConfig),
    /// Runtime engine statistics (answers GetStats)
    Stats(IdsStats),
    /// Configured rulesets (answers ListRulesets)
    Rulesets(Vec<RulesetSummary>),
    /// The looked-up rule, `None` if no rule has that id (answers GetRule)
    Rule(Option<RuleSummary>),
    /// Most recent alerts, newest first (answers TailAlerts)
    Alerts(Vec<AlertSummary>),
    /// The request failed; human-readable reason
    Error(String),
}

/// Runtime engine statistics snapshot returned by `GetStats`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdsStats {
    /// Operating mode as a lowercase string ("ids", "ips", "disabled")
    pub mode: String,
    /// Whether the capture/detection engine is currently running
    pub running: bool,
    /// Number of rules loaded into the active ruleset
    pub rules_loaded: u32,
    /// Number of flows currently tracked in the flow table
    pub flow_count: u64,
    /// Total bytes held in stream-reassembly buffers across all flows
    pub flow_reassembly_bytes: u64,
    /// Total packets run through the detection pipeline since start
    pub packets_inspected: u64,
    /// Total alerts generated since start
    pub alerts_total: u64,
    /// Total packets dropped by IPS enforcement since start
    pub drops_total: u64,
    /// Average packets per second over the engine's uptime
    pub packets_per_sec: f64,
    /// Average bytes per second over the engine's uptime
    pub bytes_per_sec: f64,
    /// Seconds since the engine started
    pub uptime_secs: u64,
}

/// One configured ruleset as returned by `ListRulesets`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RulesetSummary {
    /// Ruleset id (UUID string)
    pub id: String,
    /// Human-readable ruleset name
    pub name: String,
    /// Whether the ruleset is enabled
    pub enabled: bool,
    /// Number of rules in the ruleset
    pub rule_count: u32,
}

/// One detection rule as returned by `GetRule`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleSummary {
    /// Rule id (the `ids_rules.id` UUID string)
    pub id: String,
    /// Suricata signature id (SID)
    pub sid: u32,
    /// Rule message / description from the signature
    pub msg: String,
    /// Rule action ("alert", "drop", "reject", "pass")
    pub action: String,
    /// Whether the rule is enabled
    pub enabled: bool,
    /// Raw rule text as loaded from the ruleset
    pub raw: String,
}

/// One IDS alert as returned by `TailAlerts`
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AlertSummary {
    /// Alert id (UUID string)
    pub id: String,
    /// When the alert fired (UTC)
    pub timestamp: chrono::DateTime<chrono::Utc>,
    /// Signature id (SID) of the rule that matched
    pub sid: u32,
    /// Rule message / description
    pub msg: String,
    /// Source IP of the triggering traffic
    pub src_ip: String,
    /// Destination IP of the triggering traffic
    pub dst_ip: String,
    /// Source port; `None` for protocols without ports (e.g. ICMP)
    pub src_port: Option<u16>,
    /// Destination port; `None` for protocols without ports (e.g. ICMP)
    pub dst_port: Option<u16>,
    /// Transport protocol name (e.g. "tcp", "udp", "icmp")
    pub protocol: String,
    /// Severity level (1 = critical .. 4 = info)
    pub severity: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_round_trips() {
        let r = IpcRequest::GetStats;
        let s = serde_json::to_string(&r).unwrap();
        let back: IpcRequest = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, IpcRequest::GetStats));
    }

    #[test]
    fn stats_round_trips() {
        let stats = IdsStats {
            mode: "alert".to_string(),
            running: true,
            rules_loaded: 47755,
            flow_count: 123,
            flow_reassembly_bytes: 4096,
            packets_inspected: 100,
            alerts_total: 5,
            drops_total: 2,
            packets_per_sec: 12.5,
            bytes_per_sec: 9000.0,
            uptime_secs: 600,
        };
        let s = serde_json::to_string(&stats).unwrap();
        let back: IdsStats = serde_json::from_str(&s).unwrap();
        assert_eq!(stats, back);
    }
}
