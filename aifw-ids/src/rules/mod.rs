pub mod manager;
pub mod sigma;
pub mod suricata;
pub mod yara;

use std::collections::HashMap;
use std::sync::RwLock;

use aho_corasick::AhoCorasick;
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

/// A compiled ruleset with prefilter structures
pub struct CompiledRuleset {
    /// All compiled rules
    pub rules: Vec<CompiledRule>,
    /// Aho-Corasick automaton for all content patterns
    pub content_matcher: Option<AhoCorasick>,
    /// Maps AC match index → list of rule indices that contain that content
    pub content_to_rules: Vec<Vec<usize>>,
    /// All content patterns (parallel to content_to_rules indices)
    pub content_patterns: Vec<Vec<u8>>,
    /// Compiled regex patterns (using the regex crate)
    pub regex_patterns: Vec<(regex::Regex, Vec<usize>)>,
    /// Rules with no content/pcre — must be linearly evaluated
    pub no_content_rules: Vec<usize>,
}

impl CompiledRuleset {
    /// Build a compiled ruleset from a list of compiled rules.
    pub fn build(rules: Vec<CompiledRule>) -> Self {
        let mut all_patterns: Vec<Vec<u8>> = Vec::new();
        let mut content_to_rules: Vec<Vec<usize>> = Vec::new();
        let mut regex_patterns: Vec<(regex::Regex, Vec<usize>)> = Vec::new();
        let mut no_content_rules: Vec<usize> = Vec::new();

        // Collect all content patterns and map to rules
        for (rule_idx, rule) in rules.iter().enumerate() {
            if rule.no_prefilter {
                no_content_rules.push(rule_idx);
                continue;
            }

            let mut has_content = false;

            // Find the best prefilter pattern (fast_pattern, or longest)
            let best = rule
                .contents
                .iter()
                .enumerate()
                .filter(|(_, c)| !c.negated)
                .max_by_key(|(_, c)| {
                    if c.fast_pattern {
                        usize::MAX
                    } else {
                        c.pattern.len()
                    }
                });

            if let Some((_, content)) = best {
                let pattern = if content.nocase {
                    content.pattern.to_ascii_lowercase()
                } else {
                    content.pattern.clone()
                };

                // Check if this pattern already exists
                if let Some(idx) = all_patterns.iter().position(|p| p == &pattern) {
                    content_to_rules[idx].push(rule_idx);
                } else {
                    all_patterns.push(pattern);
                    content_to_rules.push(vec![rule_idx]);
                }
                has_content = true;
            }

            // Compile PCRE patterns
            for pcre in &rule.pcre_patterns {
                if let Ok(re) = regex::Regex::new(&pcre.pattern) {
                    // Check if we already have this regex
                    let existing = regex_patterns
                        .iter_mut()
                        .find(|(r, _)| r.as_str() == pcre.pattern);
                    if let Some((_, rule_list)) = existing {
                        rule_list.push(rule_idx);
                    } else {
                        regex_patterns.push((re, vec![rule_idx]));
                    }
                    has_content = true;
                }
            }

            if !has_content {
                no_content_rules.push(rule_idx);
            }
        }

        // Build Aho-Corasick automaton
        let content_matcher = if all_patterns.is_empty() {
            None
        } else {
            AhoCorasick::builder()
                .ascii_case_insensitive(true) // case-insensitive prefilter — most rules use nocase
                .build(&all_patterns)
                .ok()
        };

        Self {
            rules,
            content_matcher,
            content_to_rules,
            content_patterns: all_patterns,
            regex_patterns,
            no_content_rules,
        }
    }

    /// Get candidate rule indices for a payload using the prefilter.
    pub fn prefilter(&self, payload: &[u8]) -> Vec<usize> {
        let mut candidates = smallvec::SmallVec::<[usize; 64]>::new();

        // Aho-Corasick multi-pattern match
        if let Some(ref ac) = self.content_matcher {
            for mat in ac.find_overlapping_iter(payload) {
                let pattern_idx = mat.pattern().as_usize();
                if pattern_idx < self.content_to_rules.len() {
                    for &rule_idx in &self.content_to_rules[pattern_idx] {
                        if !candidates.contains(&rule_idx) {
                            candidates.push(rule_idx);
                        }
                    }
                }
            }
        }

        // Also add no-content rules (always candidates)
        for &idx in &self.no_content_rules {
            if !candidates.contains(&idx) {
                candidates.push(idx);
            }
        }

        candidates.to_vec()
    }
}

impl std::fmt::Debug for CompiledRuleset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompiledRuleset")
            .field("rules", &self.rules.len())
            .field("patterns", &self.content_patterns.len())
            .field("regex_patterns", &self.regex_patterns.len())
            .field("no_content_rules", &self.no_content_rules.len())
            .finish()
    }
}

/// The unified rule database managing all rule formats.
pub struct RuleDatabase {
    /// The active compiled ruleset (swapped atomically on reload)
    ruleset: RwLock<Option<CompiledRuleset>>,
    /// Raw parsed rules before compilation
    raw_rules: RwLock<Vec<CompiledRule>>,
}

impl RuleDatabase {
    pub fn new() -> Self {
        Self {
            ruleset: RwLock::new(None),
            raw_rules: RwLock::new(Vec::new()),
        }
    }

    /// Load and compile rules. Replaces the active ruleset.
    pub fn load_rules(&self, rules: Vec<CompiledRule>) {
        let compiled = CompiledRuleset::build(rules.clone());
        *self.raw_rules.write().unwrap() = rules;
        *self.ruleset.write().unwrap() = Some(compiled);
    }

    /// Add rules to the existing set and recompile.
    pub fn add_rules(&self, new_rules: Vec<CompiledRule>) {
        let mut raw = self.raw_rules.write().unwrap();
        raw.extend(new_rules);
        let compiled = CompiledRuleset::build(raw.clone());
        *self.ruleset.write().unwrap() = Some(compiled);
    }

    /// Get a read lock on the active ruleset.
    pub fn ruleset(&self) -> std::sync::RwLockReadGuard<'_, Option<CompiledRuleset>> {
        self.ruleset.read().unwrap()
    }

    /// Number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.raw_rules.read().unwrap().len()
    }

    /// Clear all rules.
    pub fn clear(&self) {
        *self.raw_rules.write().unwrap() = Vec::new();
        *self.ruleset.write().unwrap() = None;
    }
}

impl Default for RuleDatabase {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for RuleDatabase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RuleDatabase")
            .field("rule_count", &self.rule_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rule(sid: u32, content: &[u8], msg: &str) -> CompiledRule {
        CompiledRule {
            id: format!("rule-{sid}"),
            sid: Some(sid),
            msg: msg.to_string(),
            severity: IdsSeverity::MEDIUM,
            source: RuleSource::Custom,
            action: IdsAction::Alert,
            protocol: None,
            src_addr: None,
            src_port: None,
            dst_addr: None,
            dst_port: None,
            bidirectional: false,
            contents: vec![ContentMatch {
                pattern: content.to_vec(),
                nocase: false,
                depth: None,
                offset: None,
                distance: None,
                within: None,
                fast_pattern: false,
                negated: false,
                buffer: None,
            }],
            pcre_patterns: Vec::new(),
            flow: None,
            sticky_buffers: Vec::new(),
            threshold: None,
            flowbits: Vec::new(),
            metadata: HashMap::new(),
            no_prefilter: false,
        }
    }

    #[test]
    fn test_compiled_ruleset_build() {
        let rules = vec![
            make_rule(1, b"malware", "Test malware rule"),
            make_rule(2, b"exploit", "Test exploit rule"),
            make_rule(3, b"malware", "Another malware rule"),
        ];

        let ruleset = CompiledRuleset::build(rules);
        assert_eq!(ruleset.rules.len(), 3);
        assert!(ruleset.content_matcher.is_some());
        // "malware" pattern should map to rules 0 and 2
        assert_eq!(ruleset.content_to_rules[0], vec![0, 2]);
    }

    #[test]
    fn test_prefilter() {
        let rules = vec![
            make_rule(1, b"malware", "Malware detected"),
            make_rule(2, b"exploit", "Exploit detected"),
        ];

        let ruleset = CompiledRuleset::build(rules);

        let candidates = ruleset.prefilter(b"this contains malware string");
        assert!(candidates.contains(&0));
        assert!(!candidates.contains(&1));

        let candidates = ruleset.prefilter(b"this has exploit and malware");
        assert!(candidates.contains(&0));
        assert!(candidates.contains(&1));

        let candidates = ruleset.prefilter(b"nothing interesting");
        assert!(candidates.is_empty());
    }

    #[test]
    fn test_rule_database() {
        let db = RuleDatabase::new();
        assert_eq!(db.rule_count(), 0);

        db.load_rules(vec![make_rule(1, b"test", "test rule")]);
        assert_eq!(db.rule_count(), 1);

        db.add_rules(vec![make_rule(2, b"test2", "test rule 2")]);
        assert_eq!(db.rule_count(), 2);

        db.clear();
        assert_eq!(db.rule_count(), 0);
    }
}
