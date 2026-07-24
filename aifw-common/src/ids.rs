use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use uuid::Uuid;

/// IDS operating mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum IdsMode {
    /// Alert only — log detections, never block
    Ids,
    /// Reactive source blocking (#536): a drop/reject verdict adds the
    /// alert's source IP to the `aifw-ids-block` pf table, blocking
    /// subsequent packets from that source. The triggering packet is NOT
    /// stopped — this is not inline prevention (inline is tracked
    /// separately via divert/netmap). Wire value stays "ips" for API
    /// compatibility.
    Ips,
    /// Engine disabled
    #[default]
    Disabled,
}

impl std::fmt::Display for IdsMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ids => write!(f, "ids"),
            Self::Ips => write!(f, "ips"),
            Self::Disabled => write!(f, "disabled"),
        }
    }
}

/// Severity levels (1 = critical, 4 = informational)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IdsSeverity(pub u8);

impl IdsSeverity {
    /// Severity 1 — critical
    pub const CRITICAL: Self = Self(1);
    /// Severity 2 — high
    pub const HIGH: Self = Self(2);
    /// Severity 3 — medium (the default)
    pub const MEDIUM: Self = Self(3);
    /// Severity 4 — informational
    pub const INFO: Self = Self(4);

    /// Human-readable label for the severity; any value above 3 maps to "info"
    pub fn label(&self) -> &'static str {
        match self.0 {
            1 => "critical",
            2 => "high",
            3 => "medium",
            _ => "info",
        }
    }
}

impl Default for IdsSeverity {
    fn default() -> Self {
        Self::MEDIUM
    }
}

/// Source format of an IDS rule
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleFormat {
    /// Suricata signature syntax (alert/drop rules)
    Suricata,
    /// Sigma YAML detection rules
    Sigma,
    /// YARA pattern-matching rules
    Yara,
}

impl std::fmt::Display for RuleFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Suricata => write!(f, "suricata"),
            Self::Sigma => write!(f, "sigma"),
            Self::Yara => write!(f, "yara"),
        }
    }
}

impl RuleFormat {
    /// Parses the wire/DB string ("suricata", "sigma", "yara"); `None` for anything else
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "suricata" => Some(Self::Suricata),
            "sigma" => Some(Self::Sigma),
            "yara" => Some(Self::Yara),
            _ => None,
        }
    }
}

/// Where the rule originated
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleSource {
    /// Emerging Threats Open community ruleset
    EtOpen,
    /// Sigma community rules
    Sigma,
    /// YARA rules
    Yara,
    /// User-authored rule
    Custom,
}

impl std::fmt::Display for RuleSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EtOpen => write!(f, "et_open"),
            Self::Sigma => write!(f, "sigma"),
            Self::Yara => write!(f, "yara"),
            Self::Custom => write!(f, "custom"),
        }
    }
}

impl RuleSource {
    /// Parses the wire/DB string ("et_open", "sigma", "yara", "custom"); `None` for anything else
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "et_open" => Some(Self::EtOpen),
            "sigma" => Some(Self::Sigma),
            "yara" => Some(Self::Yara),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }
}

/// Action for an IDS rule verdict
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdsAction {
    /// Log the detection only (IDS mode)
    Alert,
    /// Block the source via the pf table (IPS reactive mode; the matching packet is not discarded)
    Drop,
    /// Block the source via the pf table, reject-style rules included (IPS reactive mode)
    Reject,
    /// Explicitly allow the traffic, skipping further rules
    Pass,
}

impl std::fmt::Display for IdsAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Alert => write!(f, "alert"),
            Self::Drop => write!(f, "drop"),
            Self::Reject => write!(f, "reject"),
            Self::Pass => write!(f, "pass"),
        }
    }
}

impl IdsAction {
    /// Parses the wire/DB string ("alert", "drop", "reject", "pass"); `None` for anything else
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "alert" => Some(Self::Alert),
            "drop" => Some(Self::Drop),
            "reject" => Some(Self::Reject),
            "pass" => Some(Self::Pass),
            _ => None,
        }
    }
}

/// An alert generated by the IDS engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsAlert {
    /// Unique alert identifier
    pub id: Uuid,
    /// When the detection fired
    pub timestamp: DateTime<Utc>,
    /// Suricata SID of the matching rule, if it has one
    pub signature_id: Option<u32>,
    /// Human-readable message from the matching rule
    pub signature_msg: String,
    /// Severity of the matching rule (1 = critical, 4 = info)
    pub severity: IdsSeverity,
    /// Source IP of the offending traffic
    pub src_ip: IpAddr,
    /// Source port, if the protocol has one
    pub src_port: Option<u16>,
    /// Destination IP of the offending traffic
    pub dst_ip: IpAddr,
    /// Destination port, if the protocol has one
    pub dst_port: Option<u16>,
    /// Transport/application protocol name. Deliberately a String, not an
    /// enum: the decoder emits arbitrary IP protocols ("proto-47") via
    /// `PacketProtocol::Other`, so the value set is open (QUAL-H11 #431)
    pub protocol: String,
    /// Action the engine took (alert/drop/reject/pass)
    pub action: IdsAction,
    /// Which ruleset family the matching rule came from
    pub rule_source: RuleSource,
    /// Identifier tying this alert to a tracked flow, if available
    pub flow_id: Option<String>,
    /// Short excerpt of the triggering payload, if captured
    pub payload_excerpt: Option<String>,
    /// Extra key/value context from the matching rule
    pub metadata: Option<HashMap<String, String>>,
    /// True once an operator has acknowledged the alert
    pub acknowledged: bool,
    /// Analyst triage state of the alert
    #[serde(default)]
    pub classification: AlertClassification,
    /// Free-form analyst notes
    pub analyst_notes: Option<String>,
}

/// Analyst triage state of an IDS alert (serialized as snake_case)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum AlertClassification {
    /// No analyst has looked at the alert yet
    #[default]
    Unreviewed,
    /// Confirmed as a real threat
    Confirmed,
    /// Determined to be a false positive
    FalsePositive,
    /// Under active investigation
    Investigating,
}

impl AlertClassification {
    /// Canonical snake_case string used in the DB and API
    /// ("unreviewed", "confirmed", "false_positive", "investigating")
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Unreviewed => "unreviewed",
            Self::Confirmed => "confirmed",
            Self::FalsePositive => "false_positive",
            Self::Investigating => "investigating",
        }
    }

    /// Case-insensitive parse of the canonical string; `None` for anything else
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "unreviewed" => Some(Self::Unreviewed),
            "confirmed" => Some(Self::Confirmed),
            "false_positive" => Some(Self::FalsePositive),
            "investigating" => Some(Self::Investigating),
            _ => None,
        }
    }
}

impl std::fmt::Display for AlertClassification {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl IdsAlert {
    /// Builds an alert with a fresh UUID, the current timestamp, "unreviewed"
    /// classification, and all optional fields (ports, flow, payload, metadata) unset
    pub fn new(
        signature_msg: String,
        severity: IdsSeverity,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        protocol: &str,
        action: IdsAction,
        rule_source: RuleSource,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            signature_id: None,
            signature_msg,
            severity,
            src_ip,
            src_port: None,
            dst_ip,
            dst_port: None,
            protocol: protocol.to_string(),
            action,
            rule_source,
            flow_id: None,
            payload_excerpt: None,
            metadata: None,
            acknowledged: false,
            classification: AlertClassification::Unreviewed,
            analyst_notes: None,
        }
    }
}

/// A configured ruleset (ET Open, Sigma community, YARA rules, etc.)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsRuleset {
    /// Unique ruleset identifier
    pub id: Uuid,
    /// Display name (e.g. "ET Open")
    pub name: String,
    /// URL the ruleset is downloaded from; `None` for locally-managed rules
    pub source_url: Option<String>,
    /// Rule syntax the set is written in
    pub rule_format: RuleFormat,
    /// Whether the ruleset's rules are loaded into the engine
    pub enabled: bool,
    /// Automatically re-download from `source_url` on a schedule
    pub auto_update: bool,
    /// Hours between automatic updates
    pub update_interval_hours: u32,
    /// When the ruleset was last downloaded/refreshed; `None` if never
    pub last_updated: Option<DateTime<Utc>>,
    /// Number of rules currently in the set
    pub rule_count: u32,
    /// When the ruleset was added
    pub created_at: DateTime<Utc>,
}

/// A single IDS rule from a ruleset
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsRule {
    /// Unique rule identifier
    pub id: Uuid,
    /// Ruleset this rule belongs to
    pub ruleset_id: Uuid,
    /// Suricata signature ID, if the rule declares one
    pub sid: Option<u32>,
    /// Raw rule source text as parsed from the ruleset
    pub rule_text: String,
    /// Message/title extracted from the rule, if present
    pub msg: Option<String>,
    /// Severity assigned to matches (1 = critical, 4 = info)
    pub severity: IdsSeverity,
    /// Whether the rule is active in the engine
    pub enabled: bool,
    /// Per-rule action replacing the rule's own action, if set
    pub action_override: Option<IdsAction>,
    /// Total number of times this rule has matched
    pub hit_count: u64,
    /// Timestamp of the most recent match; `None` if never hit
    pub last_hit: Option<DateTime<Utc>>,
    /// When the rule was imported
    pub created_at: DateTime<Utc>,
}

/// IDS engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsConfig {
    /// Operating mode: alert-only (ids), inline blocking (ips), or disabled
    pub mode: IdsMode,
    /// CIDRs considered the protected network ($HOME_NET); defaults to RFC 1918 ranges
    pub home_net: Vec<String>,
    /// CIDRs considered external ($EXTERNAL_NET); defaults to `!$HOME_NET`
    pub external_net: Vec<String>,
    /// Network interfaces to inspect; empty = none
    pub interfaces: Vec<String>,
    /// Days to keep alerts before pruning
    pub alert_retention_days: u32,
    /// Write EVE JSON event log
    pub eve_log_enabled: bool,
    /// Path for the EVE JSON log; `None` = engine default
    pub eve_log_path: Option<String>,
    /// Syslog host:port to forward alerts to; `None` = disabled
    pub syslog_target: Option<String>,
    /// Number of inspection worker threads; `None` = auto-sized
    pub worker_count: Option<u32>,
    /// Maximum tracked flows; `None` = built-in default
    pub flow_table_size: Option<u32>,
    /// Older stream depth knob in KB (clamped to 4 MB); the engine reads
    /// `flow_stream_depth_kb` instead — this is kept for config round-tripping
    pub stream_depth: Option<u32>,
    /// Per-direction stream reassembly depth, in KB. `None` = built-in default (64 KB).
    pub flow_stream_depth_kb: Option<u32>,
    /// Total memory budget for stream reassembly across all flows, in MB.
    /// `None` = built-in default (256 MB). Clamped to 4 GB upper bound.
    pub flow_reassembly_budget_mb: Option<u32>,
}

impl Default for IdsConfig {
    fn default() -> Self {
        Self {
            mode: IdsMode::Disabled,
            home_net: vec![
                "10.0.0.0/8".into(),
                "172.16.0.0/12".into(),
                "192.168.0.0/16".into(),
            ],
            external_net: vec!["!$HOME_NET".into()],
            interfaces: Vec::new(),
            alert_retention_days: 7,
            eve_log_enabled: false,
            eve_log_path: None,
            syslog_target: None,
            worker_count: None,
            flow_table_size: None,
            stream_depth: None,
            flow_stream_depth_kb: None,
            flow_reassembly_budget_mb: None,
        }
    }
}

/// Real-time IDS engine statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct IdsStats {
    /// Total packets inspected since engine start
    pub packets_inspected: u64,
    /// Total alerts raised since engine start
    pub alerts_total: u64,
    /// Total packets dropped/rejected since engine start
    pub drops_total: u64,
    /// Current inspection throughput in bytes per second
    pub bytes_per_sec: f64,
    /// Current inspection throughput in packets per second
    pub packets_per_sec: f64,
    /// Flows currently tracked in the flow table
    pub active_flows: u64,
    /// Seconds since the engine started
    pub uptime_secs: u64,
}

/// A suppression silences a specific rule for a given IP/subnet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsSuppression {
    /// Unique suppression identifier
    pub id: Uuid,
    /// Suricata signature ID being suppressed
    pub sid: u32,
    /// Which traffic direction the IP/CIDR filter applies to
    pub suppress_type: SuppressType,
    /// IP or CIDR the suppression is limited to; `None` = suppress everywhere
    pub ip_cidr: Option<String>,
    /// When the suppression was created
    pub created_at: DateTime<Utc>,
}

/// Which side of the connection a suppression's IP/CIDR filter matches
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressType {
    /// Match on source address only
    Src,
    /// Match on destination address only
    Dst,
    /// Match on either source or destination address
    Both,
}

impl std::fmt::Display for SuppressType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Src => write!(f, "src"),
            Self::Dst => write!(f, "dst"),
            Self::Both => write!(f, "both"),
        }
    }
}

impl SuppressType {
    /// Parses the wire/DB string ("src", "dst", "both"); `None` for anything else
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "src" => Some(Self::Src),
            "dst" => Some(Self::Dst),
            "both" => Some(Self::Both),
            _ => None,
        }
    }
}

/// Result of matching a rule against a packet/flow
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsRuleMatch {
    /// Identifier of the matching rule
    pub rule_id: String,
    /// Suricata signature ID, if the rule has one
    pub sid: Option<u32>,
    /// Message/title of the matching rule
    pub msg: String,
    /// Severity of the matching rule (1 = critical, 4 = info)
    pub severity: IdsSeverity,
    /// Ruleset family the rule came from
    pub source: RuleSource,
    /// Action the rule dictates for the traffic
    pub action: IdsAction,
    /// Extra key/value context carried by the rule
    pub metadata: HashMap<String, String>,
}
