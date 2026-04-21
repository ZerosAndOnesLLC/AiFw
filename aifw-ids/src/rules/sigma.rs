use std::collections::HashMap;

use aifw_common::ids::{IdsAction, IdsSeverity, RuleSource};

use super::{CompiledRule, ContentMatch, PcrePattern};

/// A parsed Sigma rule detection condition
#[derive(Debug, Clone)]
pub enum SigmaCondition {
    /// Match a keyword in a specific field
    Keyword {
        field: String,
        values: Vec<String>,
        modifier: SigmaModifier,
    },
    /// AND all sub-conditions
    And(Vec<SigmaCondition>),
    /// OR any sub-condition
    Or(Vec<SigmaCondition>),
    /// NOT a sub-condition
    Not(Box<SigmaCondition>),
}

/// Sigma value matching modifiers
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigmaModifier {
    /// Exact match
    Exact,
    /// Contains
    Contains,
    /// Starts with
    StartsWith,
    /// Ends with
    EndsWith,
    /// Regular expression
    Regex,
    /// All values must match (AND)
    All,
}

/// Parse a Sigma YAML rule into a CompiledRule.
///
/// Sigma rules target log events, but we map them to network flow
/// metadata fields (protocol parsers' sticky buffers).
pub fn parse_sigma_rule(yaml_text: &str, source: RuleSource) -> Result<CompiledRule, String> {
    let doc: serde_yaml_ng::Value =
        serde_yaml_ng::from_str(yaml_text).map_err(|e| format!("YAML parse error: {e}"))?;

    let title = doc
        .get("title")
        .and_then(|v| v.as_str())
        .unwrap_or("Untitled Sigma Rule")
        .to_string();

    let id = doc
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| format!("sigma-{s}"))
        .unwrap_or_else(|| format!("sigma-{}", uuid::Uuid::new_v4()));

    let level = doc
        .get("level")
        .and_then(|v| v.as_str())
        .unwrap_or("medium");

    let severity = match level {
        "critical" => IdsSeverity::CRITICAL,
        "high" => IdsSeverity::HIGH,
        "medium" => IdsSeverity::MEDIUM,
        "low" | "informational" => IdsSeverity::INFO,
        _ => IdsSeverity::MEDIUM,
    };

    let status = doc
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("experimental");

    let description = doc
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Parse detection section
    let detection = doc
        .get("detection")
        .ok_or_else(|| "no detection section".to_string())?;

    let (contents, pcre_patterns) = parse_sigma_detection(detection)?;

    let mut metadata = HashMap::new();
    metadata.insert("sigma_status".into(), status.to_string());
    if !description.is_empty() {
        metadata.insert("description".into(), description.to_string());
    }
    if let Some(tags) = doc.get("tags").and_then(|v| v.as_sequence()) {
        let tags_str: Vec<String> = tags
            .iter()
            .filter_map(|t| t.as_str())
            .map(|s| s.to_string())
            .collect();
        metadata.insert("tags".into(), tags_str.join(","));
    }
    if let Some(author) = doc.get("author").and_then(|v| v.as_str()) {
        metadata.insert("author".into(), author.to_string());
    }

    let no_prefilter = contents.is_empty() && pcre_patterns.is_empty();

    Ok(CompiledRule {
        id,
        sid: None,
        msg: title,
        severity,
        source,
        action: IdsAction::Alert, // Sigma rules always alert
        protocol: None,
        src_addr: None,
        src_port: None,
        dst_addr: None,
        dst_port: None,
        bidirectional: true,
        contents,
        pcre_patterns,
        flow: None,
        sticky_buffers: Vec::new(),
        threshold: None,
        flowbits: Vec::new(),
        metadata,
        no_prefilter,
    })
}

/// Parse the detection section of a Sigma rule.
fn parse_sigma_detection(
    detection: &serde_yaml_ng::Value,
) -> Result<(Vec<ContentMatch>, Vec<PcrePattern>), String> {
    let mut contents = Vec::new();
    let mut pcre_patterns = Vec::new();

    let map = detection
        .as_mapping()
        .ok_or_else(|| "detection must be a mapping".to_string())?;

    for (key, value) in map {
        let key_str = key.as_str().unwrap_or("");

        // Skip the "condition" key — it's the logic combinator
        if key_str == "condition" {
            continue;
        }

        // Each named selection contains field: value pairs
        if let Some(mapping) = value.as_mapping() {
            for (field, val) in mapping {
                let field_name = field.as_str().unwrap_or("").to_string();
                let (modifier, base_field) = extract_sigma_modifier(&field_name);

                let values = extract_values(val);
                for v in values {
                    match modifier {
                        SigmaModifier::Regex => {
                            pcre_patterns.push(PcrePattern {
                                pattern: v,
                                negated: false,
                                buffer: if base_field.is_empty() {
                                    None
                                } else {
                                    Some(base_field.clone())
                                },
                            });
                        }
                        SigmaModifier::Contains => {
                            contents.push(ContentMatch {
                                pattern: v.into_bytes(),
                                nocase: true,
                                depth: None,
                                offset: None,
                                distance: None,
                                within: None,
                                fast_pattern: false,
                                negated: false,
                                buffer: if base_field.is_empty() {
                                    None
                                } else {
                                    Some(base_field.clone())
                                },
                            });
                        }
                        SigmaModifier::StartsWith => {
                            contents.push(ContentMatch {
                                pattern: v.into_bytes(),
                                nocase: true,
                                depth: None,
                                offset: Some(0),
                                distance: None,
                                within: None,
                                fast_pattern: false,
                                negated: false,
                                buffer: if base_field.is_empty() {
                                    None
                                } else {
                                    Some(base_field.clone())
                                },
                            });
                        }
                        _ => {
                            // Exact or EndsWith — use content match
                            contents.push(ContentMatch {
                                pattern: v.into_bytes(),
                                nocase: true,
                                depth: None,
                                offset: None,
                                distance: None,
                                within: None,
                                fast_pattern: false,
                                negated: false,
                                buffer: if base_field.is_empty() {
                                    None
                                } else {
                                    Some(base_field.clone())
                                },
                            });
                        }
                    }
                }
            }
        } else if let Some(seq) = value.as_sequence() {
            // List of values (keywords)
            for val in seq {
                if let Some(s) = val.as_str() {
                    contents.push(ContentMatch {
                        pattern: s.as_bytes().to_vec(),
                        nocase: true,
                        depth: None,
                        offset: None,
                        distance: None,
                        within: None,
                        fast_pattern: false,
                        negated: false,
                        buffer: None,
                    });
                }
            }
        }
    }

    Ok((contents, pcre_patterns))
}

/// Extract Sigma modifier from field name (e.g., "CommandLine|contains" → (Contains, "CommandLine"))
fn extract_sigma_modifier(field: &str) -> (SigmaModifier, String) {
    if let Some((base, modifier)) = field.rsplit_once('|') {
        let m = match modifier {
            "contains" => SigmaModifier::Contains,
            "startswith" => SigmaModifier::StartsWith,
            "endswith" => SigmaModifier::EndsWith,
            "re" => SigmaModifier::Regex,
            "all" => SigmaModifier::All,
            _ => SigmaModifier::Exact,
        };
        (m, base.to_string())
    } else {
        (SigmaModifier::Exact, field.to_string())
    }
}

/// Extract string values from a YAML value (scalar or sequence)
fn extract_values(val: &serde_yaml_ng::Value) -> Vec<String> {
    match val {
        serde_yaml_ng::Value::String(s) => vec![s.clone()],
        serde_yaml_ng::Value::Number(n) => vec![n.to_string()],
        serde_yaml_ng::Value::Bool(b) => vec![b.to_string()],
        serde_yaml_ng::Value::Sequence(seq) => seq
            .iter()
            .filter_map(|v| match v {
                serde_yaml_ng::Value::String(s) => Some(s.clone()),
                serde_yaml_ng::Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// Parse multiple Sigma rules from YAML text (handles multi-document YAML).
pub fn parse_sigma_rules(yaml_text: &str, source: RuleSource) -> Vec<CompiledRule> {
    let mut rules = Vec::new();

    // Split on YAML document separator
    for doc in yaml_text.split("\n---") {
        let doc = doc.trim();
        if doc.is_empty() || doc.starts_with('#') {
            continue;
        }
        match parse_sigma_rule(doc, source) {
            Ok(rule) => rules.push(rule),
            Err(e) => {
                tracing::trace!("skipping Sigma rule: {e}");
            }
        }
    }

    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sigma_rule() {
        let yaml = r#"
title: Suspicious DNS Query
id: abc12345-def6-7890-abcd-ef1234567890
status: stable
level: high
description: Detects suspicious DNS queries
author: Test Author
tags:
    - attack.c2
detection:
    selection:
        dns.query|contains:
            - "evil.com"
            - "malware.net"
    condition: selection
"#;

        let rule = parse_sigma_rule(yaml, RuleSource::Sigma).unwrap();
        assert_eq!(rule.msg, "Suspicious DNS Query");
        assert_eq!(rule.severity, IdsSeverity::HIGH);
        assert_eq!(rule.action, IdsAction::Alert);
        assert_eq!(rule.contents.len(), 2);
        assert_eq!(rule.contents[0].pattern, b"evil.com");
        assert!(rule.contents[0].nocase);
        assert_eq!(rule.contents[0].buffer, Some("dns.query".to_string()));
    }

    #[test]
    fn test_parse_sigma_with_regex() {
        let yaml = r#"
title: Regex Test
id: test-regex-id
level: medium
detection:
    selection:
        http.uri|re: ".*\\.exe$"
    condition: selection
"#;

        let rule = parse_sigma_rule(yaml, RuleSource::Sigma).unwrap();
        assert_eq!(rule.pcre_patterns.len(), 1);
        assert_eq!(rule.pcre_patterns[0].pattern, r".*\.exe$");
    }

    #[test]
    fn test_extract_modifier() {
        assert_eq!(
            extract_sigma_modifier("CommandLine|contains"),
            (SigmaModifier::Contains, "CommandLine".into())
        );
        assert_eq!(
            extract_sigma_modifier("dns.query|re"),
            (SigmaModifier::Regex, "dns.query".into())
        );
        assert_eq!(
            extract_sigma_modifier("field"),
            (SigmaModifier::Exact, "field".into())
        );
    }

    #[test]
    fn test_parse_multiple_sigma() {
        let yaml = r#"
title: Rule 1
id: rule-1
level: high
detection:
    keywords:
        - "test1"
    condition: keywords
---
title: Rule 2
id: rule-2
level: low
detection:
    keywords:
        - "test2"
    condition: keywords
"#;
        let rules = parse_sigma_rules(yaml, RuleSource::Sigma);
        assert_eq!(rules.len(), 2);
    }
}
