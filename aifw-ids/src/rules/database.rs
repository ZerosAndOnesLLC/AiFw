//! `RuleDatabase` — the lock-free rule store. Both the raw rule list and
//! the compiled ruleset live in `ArcSwap` slots so detection reads an
//! atomic snapshot while a reload swaps in a freshly built ruleset.

use std::sync::Arc;

use arc_swap::ArcSwapOption;

use super::ruleset::CompiledRuleset;
use super::types::CompiledRule;

/// The unified rule database managing all rule formats.
///
/// Both the raw rule list and the compiled ruleset are held in `ArcSwap`
/// slots. Readers (detection) load an atomic snapshot — no lock contention,
/// no clone. Writers (reload) build a new ruleset from the shared `Arc<Vec<_>>`
/// off-thread, then swap a pointer.
pub struct RuleDatabase {
    /// The active compiled ruleset (swapped atomically on reload)
    ruleset: ArcSwapOption<CompiledRuleset>,
    /// Raw parsed rules before compilation
    raw_rules: ArcSwapOption<Vec<CompiledRule>>,
}

impl RuleDatabase {
    pub fn new() -> Self {
        Self {
            ruleset: ArcSwapOption::const_empty(),
            raw_rules: ArcSwapOption::const_empty(),
        }
    }

    /// Load and compile rules. Replaces the active ruleset.
    pub fn load_rules(&self, rules: Vec<CompiledRule>) {
        let rules = Arc::new(rules);
        let compiled = Arc::new(CompiledRuleset::build(rules.clone()));
        self.raw_rules.store(Some(rules));
        self.ruleset.store(Some(compiled));
    }

    /// Add rules to the existing set and recompile.
    ///
    /// This still allocates a fresh Vec because the appended-to list needs
    /// exclusive ownership; existing readers continue with the previous Arc.
    pub fn add_rules(&self, new_rules: Vec<CompiledRule>) {
        let existing = self.raw_rules.load_full();
        let mut combined: Vec<CompiledRule> = existing.as_deref().cloned().unwrap_or_default();
        combined.extend(new_rules);
        let rules = Arc::new(combined);
        let compiled = Arc::new(CompiledRuleset::build(rules.clone()));
        self.raw_rules.store(Some(rules));
        self.ruleset.store(Some(compiled));
    }

    /// Atomic snapshot of the active ruleset.
    ///
    /// Returns `None` if no rules have been loaded yet. The returned Arc
    /// keeps the ruleset alive even if a concurrent reload swaps in a new
    /// one — readers see a consistent snapshot.
    pub fn ruleset(&self) -> Option<Arc<CompiledRuleset>> {
        self.ruleset.load_full()
    }

    /// Number of loaded rules.
    pub fn rule_count(&self) -> usize {
        self.raw_rules.load().as_ref().map_or(0, |v| v.len())
    }

    /// Clear all rules.
    pub fn clear(&self) {
        self.raw_rules.store(None);
        self.ruleset.store(None);
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
    use super::super::types::ContentMatch;
    use super::*;
    use aifw_common::ids::{IdsAction, IdsSeverity, RuleSource};
    use std::collections::HashMap;

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

        let ruleset = CompiledRuleset::build(Arc::new(rules));
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

        let ruleset = CompiledRuleset::build(Arc::new(rules));

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
