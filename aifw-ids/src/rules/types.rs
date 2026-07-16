//! The compiled-rule data model: `CompiledRule` and its constituent
//! match/constraint types (content, PCRE, flow, threshold, flowbits).

use std::collections::HashMap;

use aifw_common::ids::{IdsAction, IdsSeverity, RuleSource};

/// A compiled rule ready for matching
#[derive(Debug, Clone)]
pub struct CompiledRule {
    /// Rule id (UUID string assigned at load time)
    pub id: String,
    /// Suricata signature id; `None` for formats without SIDs
    pub sid: Option<u32>,
    /// Rule message / description shown on alerts
    pub msg: String,
    /// Severity assigned to alerts this rule generates
    pub severity: IdsSeverity,
    /// Where the rule came from (ruleset, custom, etc.)
    pub source: RuleSource,
    /// Action on match (alert, drop, reject, pass)
    pub action: IdsAction,
    /// Protocol constraint (tcp, udp, icmp, ip, or app-layer)
    pub protocol: Option<String>,
    /// Source address constraint (CIDR or variable like $HOME_NET)
    pub src_addr: Option<String>,
    /// Source port constraint
    pub src_port: Option<String>,
    /// Destination address constraint
    pub dst_addr: Option<String>,
    /// Destination port constraint
    pub dst_port: Option<String>,
    /// Is bidirectional (<>)?
    pub bidirectional: bool,
    /// Content match patterns
    pub contents: Vec<ContentMatch>,
    /// PCRE patterns
    pub pcre_patterns: Vec<PcrePattern>,
    /// Flow constraints
    pub flow: Option<FlowConstraint>,
    /// Sticky buffer targets for content matches
    pub sticky_buffers: Vec<Option<String>>,
    /// Threshold configuration
    pub threshold: Option<ThresholdConfig>,
    /// Flowbits operations
    pub flowbits: Vec<FlowbitOp>,
    /// Metadata key-value pairs
    pub metadata: HashMap<String, String>,
    /// If true, this rule has no content/pcre — must be linearly scanned
    pub no_prefilter: bool,
}

/// A content match pattern with position constraints
#[derive(Debug, Clone)]
pub struct ContentMatch {
    /// The pattern bytes to match
    pub pattern: Vec<u8>,
    /// Case-insensitive match
    pub nocase: bool,
    /// Match must start within first N bytes
    pub depth: Option<usize>,
    /// Match must start at or after offset N
    pub offset: Option<usize>,
    /// Relative distance from previous match
    pub distance: Option<i32>,
    /// Match must occur within N bytes of previous match
    pub within: Option<usize>,
    /// This content is the fast_pattern prefilter candidate
    pub fast_pattern: bool,
    /// Negated match (!content)
    pub negated: bool,
    /// Sticky buffer target (e.g., "http.uri", "tls.sni")
    pub buffer: Option<String>,
}

/// A PCRE pattern
#[derive(Debug, Clone)]
pub struct PcrePattern {
    /// The regular expression source text
    pub pattern: String,
    /// Negated match (`!pcre`) — the rule matches when the regex does not
    pub negated: bool,
    /// Sticky buffer to match against (e.g. "http.uri"); `None` = raw payload
    pub buffer: Option<String>,
}

/// Flow direction/state constraint
#[derive(Debug, Clone)]
pub struct FlowConstraint {
    /// Only match on established connections
    pub established: bool,
    /// Required direction: `Some(true)` = to_server, `Some(false)` =
    /// to_client, `None` = either direction
    pub to_server: Option<bool>,
    /// Match regardless of flow state (`flow:stateless`)
    pub stateless: bool,
}

/// Threshold/rate-limiting configuration for a rule
#[derive(Debug, Clone)]
pub struct ThresholdConfig {
    /// How the count limits alerting (limit, threshold, or both)
    pub threshold_type: ThresholdType,
    /// Which endpoint's IP the counter is keyed on
    pub track: TrackBy,
    /// Hit count the threshold logic compares against
    pub count: u32,
    /// Length of the tracking window in seconds
    pub seconds: u32,
}

/// How a rule's threshold count limits alerting within the time window
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdType {
    /// Alert once per time window
    Limit,
    /// Alert after N hits
    Threshold,
    /// Alert once after N hits per window
    Both,
}

/// Which endpoint's IP a threshold counter is tracked by
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackBy {
    /// Track per source IP
    BySrc,
    /// Track per destination IP
    ByDst,
}

/// Flowbit operation
#[derive(Debug, Clone)]
pub enum FlowbitOp {
    /// Set the named flowbit on the flow
    Set(String),
    /// Only match if the named flowbit is set
    IsSet(String),
    /// Clear the named flowbit
    Unset(String),
    /// Flip the named flowbit
    Toggle(String),
    /// Perform the flowbit side effects but suppress the alert
    NoAlert,
}
