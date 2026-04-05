/// Multi-pattern matching utilities built on Aho-Corasick.
///
/// The heavy lifting is done by `CompiledRuleset::prefilter()` in `rules/mod.rs`.
/// This module provides additional helpers for batch matching and case handling.

use aho_corasick::AhoCorasick;

/// Build an Aho-Corasick automaton from a list of patterns.
pub fn build_automaton(patterns: &[Vec<u8>]) -> Option<AhoCorasick> {
    if patterns.is_empty() {
        return None;
    }

    AhoCorasick::builder()
        .ascii_case_insensitive(false)
        .build(patterns)
        .ok()
}

/// Find all pattern matches in data, returning (pattern_index, position) pairs.
pub fn find_all_matches(ac: &AhoCorasick, data: &[u8]) -> Vec<(usize, usize)> {
    ac.find_overlapping_iter(data)
        .map(|m| (m.pattern().as_usize(), m.start()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_automaton() {
        let patterns = vec![
            b"hello".to_vec(),
            b"world".to_vec(),
        ];
        let ac = build_automaton(&patterns).unwrap();

        let matches = find_all_matches(&ac, b"hello world");
        assert_eq!(matches.len(), 2);
        assert_eq!(matches[0].0, 0); // "hello" pattern index
        assert_eq!(matches[1].0, 1); // "world" pattern index
    }

    #[test]
    fn test_overlapping_matches() {
        let patterns = vec![
            b"ab".to_vec(),
            b"bc".to_vec(),
        ];
        let ac = build_automaton(&patterns).unwrap();

        let matches = find_all_matches(&ac, b"abc");
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_empty_patterns() {
        assert!(build_automaton(&[]).is_none());
    }
}
