//! Wire types for the aifw-ids IPC protocol.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "method", content = "params", rename_all = "snake_case")]
pub enum IpcRequest {
    GetConfig,
    SetConfig { config: aifw_common::ids::IdsConfig },
    Reload,
    GetStats,
    ListRulesets,
    GetRule { id: String },
    SetRule { id: String, enabled: bool },
    TailAlerts { count: u32 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum IpcResponse {
    Ok,
    Config(aifw_common::ids::IdsConfig),
    Stats(IdsStats),
    Rulesets(Vec<RulesetSummary>),
    Rule(Option<RuleSummary>),
    Alerts(Vec<AlertSummary>),
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IdsStats {
    pub mode: String,
    pub running: bool,
    pub rules_loaded: u32,
    pub flow_count: u64,
    pub flow_reassembly_bytes: u64,
    pub packets_inspected: u64,
    pub alerts_total: u64,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RulesetSummary {
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub rule_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleSummary {
    pub id: String,
    pub sid: u32,
    pub msg: String,
    pub action: String,
    pub enabled: bool,
    pub raw: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AlertSummary {
    pub id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub sid: u32,
    pub msg: String,
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub protocol: String,
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
            uptime_secs: 600,
        };
        let s = serde_json::to_string(&stats).unwrap();
        let back: IdsStats = serde_json::from_str(&s).unwrap();
        assert_eq!(stats, back);
    }
}
