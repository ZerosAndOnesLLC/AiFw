//! `CompiledRuleset` — the prefilter-ready form of a rule list: an
//! Aho-Corasick content automaton, compiled regexes, and the no-content
//! fallback set, all built from a shared `Arc<Vec<CompiledRule>>`.

use std::sync::Arc;

use aho_corasick::AhoCorasick;

use super::types::CompiledRule;

/// A compiled ruleset with prefilter structures.
///
/// The rule list is stored as `Arc<Vec<CompiledRule>>` so swapping in a fresh
/// ruleset is O(1) — just a pointer + refcount bump. This is the hot path
/// for `RuleDatabase::load_rules` / `add_rules`, which previously cloned the
/// entire 47k-rule vector on every reload.
pub struct CompiledRuleset {
    /// All compiled rules — shared via Arc, never cloned.
    pub rules: Arc<Vec<CompiledRule>>,
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
    /// Build a compiled ruleset from a shared list of compiled rules.
    ///
    /// Iterates by reference so neither the rules Vec nor any CompiledRule
    /// is cloned; only the prefilter pattern bytes themselves are extracted.
    pub fn build(rules: Arc<Vec<CompiledRule>>) -> Self {
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
