use std::collections::HashMap;

use aifw_common::ids::{IdsAction, IdsSeverity, RuleSource};

use super::{CompiledRule, ContentMatch, PcrePattern};

/// Parse YARA rules from text.
///
/// Since we don't link libyara directly (avoiding the C dependency for portability),
/// we parse the YARA rule format ourselves and convert to our internal representation.
/// This handles the most common YARA patterns:
/// - Text strings
/// - Hex strings
/// - Regular expressions
/// - Basic conditions (any of them, all of them, N of them)
pub fn parse_yara_rules(text: &str, source: RuleSource) -> Vec<CompiledRule> {
    let mut rules = Vec::new();

    let mut pos = 0;
    let chars: Vec<char> = text.chars().collect();

    while pos < chars.len() {
        // Skip whitespace and comments
        while pos < chars.len() && chars[pos].is_whitespace() {
            pos += 1;
        }
        if pos >= chars.len() {
            break;
        }

        // Skip single-line comments
        if pos + 1 < chars.len() && chars[pos] == '/' && chars[pos + 1] == '/' {
            while pos < chars.len() && chars[pos] != '\n' {
                pos += 1;
            }
            continue;
        }

        // Skip multi-line comments
        if pos + 1 < chars.len() && chars[pos] == '/' && chars[pos + 1] == '*' {
            while pos + 1 < chars.len() && !(chars[pos] == '*' && chars[pos + 1] == '/') {
                pos += 1;
            }
            pos += 2;
            continue;
        }

        // Look for "rule name {"
        let word_start = pos;
        while pos < chars.len() && chars[pos].is_alphanumeric() || (pos < chars.len() && chars[pos] == '_') {
            pos += 1;
        }
        let word: String = chars[word_start..pos].iter().collect();

        if word == "rule" || word == "private" || word == "global" {
            // Skip modifiers
            let is_private = word == "private";
            if word != "rule" {
                // skip to "rule" keyword
                while pos < chars.len() && chars[pos].is_whitespace() {
                    pos += 1;
                }
                let next_start = pos;
                while pos < chars.len() && (chars[pos].is_alphanumeric() || chars[pos] == '_') {
                    pos += 1;
                }
                let next: String = chars[next_start..pos].iter().collect();
                if next != "rule" {
                    continue;
                }
            }

            // Get rule name
            while pos < chars.len() && chars[pos].is_whitespace() {
                pos += 1;
            }
            let name_start = pos;
            while pos < chars.len() && (chars[pos].is_alphanumeric() || chars[pos] == '_') {
                pos += 1;
            }
            let rule_name: String = chars[name_start..pos].iter().collect();

            // Skip tags and colon
            while pos < chars.len() && chars[pos] != '{' {
                pos += 1;
            }
            if pos >= chars.len() {
                break;
            }
            pos += 1; // skip '{'

            // Find matching '}'
            let body_start = pos;
            let mut depth = 1;
            while pos < chars.len() && depth > 0 {
                if chars[pos] == '{' {
                    depth += 1;
                }
                if chars[pos] == '}' {
                    depth -= 1;
                }
                if depth > 0 {
                    pos += 1;
                }
            }
            let body: String = chars[body_start..pos].iter().collect();
            pos += 1; // skip '}'

            if !is_private {
                if let Ok(rule) = parse_yara_body(&rule_name, &body, source) {
                    rules.push(rule);
                }
            }
        }
    }

    rules
}

fn parse_yara_body(name: &str, body: &str, source: RuleSource) -> Result<CompiledRule, String> {
    let mut contents = Vec::new();
    let mut pcre_patterns = Vec::new();
    let mut metadata = HashMap::new();

    // Split body into sections
    let sections = split_yara_sections(body);

    // Parse meta section
    if let Some(meta_text) = sections.get("meta") {
        for line in meta_text.lines() {
            let line = line.trim();
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim().trim_matches('"');
                metadata.insert(key.to_string(), value.to_string());
            }
        }
    }

    // Parse strings section
    if let Some(strings_text) = sections.get("strings") {
        for line in strings_text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with("//") {
                continue;
            }

            // Format: $name = "text" or $name = { hex } or $name = /regex/
            if let Some(eq_pos) = line.find('=') {
                let value = line[eq_pos + 1..].trim();

                if value.starts_with('"') {
                    // Text string
                    let end = value[1..].find('"').map(|i| i + 1).unwrap_or(value.len());
                    let text = &value[1..end];
                    let nocase = value[end..].contains("nocase");

                    contents.push(ContentMatch {
                        pattern: unescape_yara_string(text),
                        nocase,
                        depth: None,
                        offset: None,
                        distance: None,
                        within: None,
                        fast_pattern: false,
                        negated: false,
                        buffer: None,
                    });
                } else if value.starts_with('{') {
                    // Hex string
                    let end = value.find('}').unwrap_or(value.len());
                    let hex = &value[1..end];
                    if let Some(bytes) = parse_yara_hex(hex) {
                        contents.push(ContentMatch {
                            pattern: bytes,
                            nocase: false,
                            depth: None,
                            offset: None,
                            distance: None,
                            within: None,
                            fast_pattern: false,
                            negated: false,
                            buffer: None,
                        });
                    }
                } else if value.starts_with('/') {
                    // Regex
                    let end = value[1..].find('/').map(|i| i + 1).unwrap_or(value.len());
                    let pattern = &value[1..end];
                    let flags = &value[end + 1..];
                    let mut re_str = String::new();
                    if flags.contains('i') {
                        re_str.push_str("(?i)");
                    }
                    if flags.contains('s') {
                        re_str.push_str("(?s)");
                    }
                    re_str.push_str(pattern);
                    pcre_patterns.push(PcrePattern {
                        pattern: re_str,
                        negated: false,
                        buffer: None,
                    });
                }
            }
        }
    }

    let severity = match metadata.get("severity").map(|s| s.as_str()) {
        Some("critical") => IdsSeverity::CRITICAL,
        Some("high") => IdsSeverity::HIGH,
        Some("medium") => IdsSeverity::MEDIUM,
        Some("low") | Some("info") => IdsSeverity::INFO,
        _ => IdsSeverity::MEDIUM,
    };

    let description = metadata
        .get("description")
        .cloned()
        .unwrap_or_else(|| format!("YARA rule: {name}"));

    let no_prefilter = contents.is_empty() && pcre_patterns.is_empty();

    Ok(CompiledRule {
        id: format!("yara-{name}"),
        sid: None,
        msg: description,
        severity,
        source,
        action: IdsAction::Alert,
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

fn split_yara_sections(body: &str) -> HashMap<String, String> {
    let mut sections = HashMap::new();
    let mut current_section = String::new();
    let mut current_content = String::new();

    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with(':')
            && (trimmed == "meta:" || trimmed == "strings:" || trimmed == "condition:")
        {
            if !current_section.is_empty() {
                sections.insert(current_section.clone(), current_content.trim().to_string());
            }
            current_section = trimmed.trim_end_matches(':').to_string();
            current_content.clear();
        } else {
            current_content.push_str(line);
            current_content.push('\n');
        }
    }

    if !current_section.is_empty() {
        sections.insert(current_section, current_content.trim().to_string());
    }

    sections
}

fn unescape_yara_string(s: &str) -> Vec<u8> {
    let mut result = Vec::new();
    let mut chars = s.chars();

    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                Some('n') => result.push(b'\n'),
                Some('r') => result.push(b'\r'),
                Some('t') => result.push(b'\t'),
                Some('\\') => result.push(b'\\'),
                Some('"') => result.push(b'"'),
                Some('x') => {
                    let h1 = chars.next().unwrap_or('0');
                    let h2 = chars.next().unwrap_or('0');
                    let hex: String = [h1, h2].iter().collect();
                    result.push(u8::from_str_radix(&hex, 16).unwrap_or(0));
                }
                Some(c) => {
                    result.push(b'\\');
                    result.push(c as u8);
                }
                None => result.push(b'\\'),
            }
        } else {
            result.push(ch as u8);
        }
    }

    result
}

fn parse_yara_hex(hex: &str) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let hex = hex.trim();

    let mut i = 0;
    let chars: Vec<char> = hex.chars().collect();

    while i < chars.len() {
        if chars[i].is_whitespace() {
            i += 1;
            continue;
        }

        // Skip wildcards (??) — they break the pattern into segments
        if chars[i] == '?' {
            // For now, stop at wildcards (partial match handled by the detection engine)
            break;
        }

        // Skip jump operators [N-M]
        if chars[i] == '[' {
            break; // Stop at jumps — variable-length gaps aren't representable as fixed content
        }

        // Regular hex byte
        if i + 1 < chars.len() && chars[i].is_ascii_hexdigit() && chars[i + 1].is_ascii_hexdigit()
        {
            let hex_str: String = [chars[i], chars[i + 1]].iter().collect();
            bytes.push(u8::from_str_radix(&hex_str, 16).ok()?);
            i += 2;
        } else {
            i += 1;
        }
    }

    if bytes.is_empty() {
        None
    } else {
        Some(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_yara_text_string() {
        let yara = r#"
rule test_rule {
    meta:
        description = "Test YARA rule"
        severity = "high"
    strings:
        $s1 = "malware_payload" nocase
        $s2 = "evil_function"
    condition:
        any of them
}
"#;

        let rules = parse_yara_rules(yara, RuleSource::Yara);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].msg, "Test YARA rule");
        assert_eq!(rules[0].severity, IdsSeverity::HIGH);
        assert_eq!(rules[0].contents.len(), 2);
        assert!(rules[0].contents[0].nocase);
        assert_eq!(rules[0].contents[0].pattern, b"malware_payload");
        assert!(!rules[0].contents[1].nocase);
    }

    #[test]
    fn test_parse_yara_hex_string() {
        let yara = r#"
rule hex_test {
    strings:
        $hex = { DE AD BE EF }
    condition:
        $hex
}
"#;

        let rules = parse_yara_rules(yara, RuleSource::Yara);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].contents[0].pattern, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_parse_yara_regex() {
        let yara = r#"
rule regex_test {
    strings:
        $re = /evil[0-9]+\.exe/i
    condition:
        $re
}
"#;

        let rules = parse_yara_rules(yara, RuleSource::Yara);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].pcre_patterns.len(), 1);
        assert!(rules[0].pcre_patterns[0].pattern.starts_with("(?i)"));
    }

    #[test]
    fn test_parse_multiple_yara_rules() {
        let yara = r#"
rule rule_one {
    strings:
        $a = "payload_one"
    condition:
        $a
}

rule rule_two {
    strings:
        $b = "payload_two"
    condition:
        $b
}
"#;

        let rules = parse_yara_rules(yara, RuleSource::Yara);
        assert_eq!(rules.len(), 2);
    }

    #[test]
    fn test_unescape() {
        assert_eq!(unescape_yara_string(r"hello\nworld"), b"hello\nworld");
        assert_eq!(unescape_yara_string(r"\x41\x42"), b"AB");
    }
}
