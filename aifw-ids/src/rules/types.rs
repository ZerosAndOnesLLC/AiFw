//! The compiled-rule data model: `CompiledRule` and its constituent
//! match/constraint types (content, PCRE, flow, threshold, flowbits).

use std::collections::HashMap;

use aifw_common::ids::{IdsAction, IdsSeverity, RuleSource};

/// A compiled rule ready for matching
#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub id: String,
    pub sid: Option<u32>,
    pub msg: String,
    pub severity: IdsSeverity,
    pub source: RuleSource,
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
    pub pattern: String,
    pub negated: bool,
    pub buffer: Option<String>,
}

/// Flow direction/state constraint
#[derive(Debug, Clone)]
pub struct FlowConstraint {
    pub established: bool,
    pub to_server: Option<bool>,
    pub stateless: bool,
}

/// Threshold/rate-limiting configuration for a rule
#[derive(Debug, Clone)]
pub struct ThresholdConfig {
    pub threshold_type: ThresholdType,
    pub track: TrackBy,
    pub count: u32,
    pub seconds: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThresholdType {
    /// Alert once per time window
    Limit,
    /// Alert after N hits
    Threshold,
    /// Alert once after N hits per window
    Both,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackBy {
    BySrc,
    ByDst,
}

/// Flowbit operation
#[derive(Debug, Clone)]
pub enum FlowbitOp {
    Set(String),
    IsSet(String),
    Unset(String),
    Toggle(String),
    NoAlert,
}
