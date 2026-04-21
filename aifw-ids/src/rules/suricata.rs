use std::collections::HashMap;

use aifw_common::ids::{IdsAction, IdsSeverity, RuleSource};

use super::{
    CompiledRule, ContentMatch, FlowConstraint, FlowbitOp, PcrePattern, ThresholdConfig,
    ThresholdType, TrackBy,
};

/// Parse a single Suricata-format rule line into a CompiledRule.
///
/// Format: `action proto src_addr src_port -> dst_addr dst_port (options;)`
pub fn parse_rule(line: &str, source: RuleSource) -> Result<CompiledRule, String> {
    let line = line.trim();

    // Skip comments and empty lines
    if line.is_empty() || line.starts_with('#') {
        return Err("comment or empty".into());
    }

    // Find the options section in parentheses
    let paren_start = line.find('(').ok_or_else(|| {
        format!(
            "no options section in rule: {}",
            &line[..line.len().min(80)]
        )
    })?;
    let paren_end = line
        .rfind(')')
        .ok_or_else(|| "no closing paren".to_string())?;

    let header = &line[..paren_start].trim();
    let options_str = &line[paren_start + 1..paren_end];

    // Parse header: action proto src_addr src_port direction dst_addr dst_port
    let parts: Vec<&str> = header.split_whitespace().collect();
    if parts.len() < 7 {
        return Err(format!("incomplete rule header: {header}"));
    }

    let action = match parts[0] {
        "alert" => IdsAction::Alert,
        "drop" => IdsAction::Drop,
        "reject" => IdsAction::Reject,
        "pass" => IdsAction::Pass,
        _ => return Err(format!("unknown action: {}", parts[0])),
    };

    let protocol = Some(parts[1].to_string());
    let src_addr = normalize_addr(parts[2]);
    let src_port = normalize_port(parts[3]);
    let bidirectional = parts[4] == "<>";
    let dst_addr = normalize_addr(parts[5]);
    let dst_port = normalize_port(parts[6]);

    // Parse options
    let options = parse_options(options_str)?;

    let mut sid: Option<u32> = None;
    let mut msg = String::new();
    let mut severity = IdsSeverity::MEDIUM;
    let mut contents: Vec<ContentMatch> = Vec::new();
    let mut pcre_patterns: Vec<PcrePattern> = Vec::new();
    let mut flow: Option<FlowConstraint> = None;
    let mut threshold: Option<ThresholdConfig> = None;
    let mut flowbits: Vec<FlowbitOp> = Vec::new();
    let mut metadata: HashMap<String, String> = HashMap::new();

    for (key, value) in &options {
        match key.as_str() {
            "sid" => sid = value.parse().ok(),
            "msg" => msg = unquote(value),
            "priority" => {
                severity = IdsSeverity(value.parse().unwrap_or(3));
            }
            "classtype" => {
                metadata.insert("classtype".into(), value.to_string());
                // Infer severity from classtype
                if severity == IdsSeverity::MEDIUM {
                    severity = classtype_severity(value);
                }
            }
            "reference" => {
                metadata.insert("reference".into(), value.to_string());
            }
            "rev" => {
                metadata.insert("rev".into(), value.to_string());
            }
            "metadata" => {
                for pair in value.split(',') {
                    let pair = pair.trim();
                    if let Some((k, v)) = pair.split_once(' ') {
                        metadata.insert(k.trim().to_string(), v.trim().to_string());
                    }
                }
            }
            "content" => {
                let (pattern, negated) = parse_content_value(value)?;
                contents.push(ContentMatch {
                    pattern,
                    nocase: false,
                    depth: None,
                    offset: None,
                    distance: None,
                    within: None,
                    fast_pattern: false,
                    negated,
                    buffer: None,
                });
            }
            "nocase" => {
                if let Some(last) = contents.last_mut() {
                    last.nocase = true;
                }
            }
            "depth" => {
                if let Some(last) = contents.last_mut() {
                    last.depth = value.parse().ok();
                }
            }
            "offset" => {
                if let Some(last) = contents.last_mut() {
                    last.offset = value.parse().ok();
                }
            }
            "distance" => {
                if let Some(last) = contents.last_mut() {
                    last.distance = value.parse().ok();
                }
            }
            "within" => {
                if let Some(last) = contents.last_mut() {
                    last.within = value.parse().ok();
                }
            }
            "fast_pattern" => {
                if let Some(last) = contents.last_mut() {
                    last.fast_pattern = true;
                }
            }
            "pcre" => {
                let pattern = unquote(value);
                // Suricata PCRE: "/pattern/flags"
                if let Some(re) = parse_pcre_pattern(&pattern) {
                    pcre_patterns.push(PcrePattern {
                        pattern: re,
                        negated: pattern.starts_with('!'),
                        buffer: None,
                    });
                }
            }
            "flow" => {
                flow = Some(parse_flow_constraint(value));
            }
            "threshold" | "detection_filter" => {
                threshold = parse_threshold(value);
            }
            "flowbits" => {
                if let Some(op) = parse_flowbits(value) {
                    flowbits.push(op);
                }
            }
            // Sticky buffer keywords — apply to the PRECEDING content match
            // In Suricata, "content:X; http_uri;" means X targets http.uri
            "http_method" | "http.method" => set_last_buffer(&mut contents, "http.method"),
            "http_uri" | "http.uri" | "http_raw_uri" | "http.uri.raw" => {
                set_last_buffer(&mut contents, "http.uri")
            }
            "http_host" | "http.host" => set_last_buffer(&mut contents, "http.host"),
            "http_user_agent" | "http.user_agent" => {
                set_last_buffer(&mut contents, "http.user_agent")
            }
            "http_header" | "http.header" => set_last_buffer(&mut contents, "http.request_header"),
            "http_cookie" | "http.cookie" => set_last_buffer(&mut contents, "http.cookie"),
            "http_content_type" | "http.content_type" => {
                set_last_buffer(&mut contents, "http.content_type")
            }
            "http_response_body" | "http.response_body" | "file_data" | "file.data" => {
                set_last_buffer(&mut contents, "http.response_body")
            }
            "http_stat_code" | "http.stat_code" => set_last_buffer(&mut contents, "http.stat_code"),
            "http_stat_msg" | "http.stat_msg" => set_last_buffer(&mut contents, "http.stat_msg"),
            "tls_sni" | "tls.sni" => set_last_buffer(&mut contents, "tls.sni"),
            "ja3_hash" | "ja3.hash" | "tls.ja3" => set_last_buffer(&mut contents, "tls.ja3"),
            "dns_query" | "dns.query" => set_last_buffer(&mut contents, "dns.query"),
            "ssh.software" => set_last_buffer(&mut contents, "ssh.software"),
            _ => {
                // Unknown keyword — store in metadata
                if !value.is_empty() {
                    metadata.insert(key.to_string(), value.to_string());
                }
            }
        }
    }

    let no_prefilter = contents.is_empty() && pcre_patterns.is_empty();

    Ok(CompiledRule {
        id: sid
            .map(|s| format!("suricata-{s}"))
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        sid,
        msg,
        severity,
        source,
        action,
        protocol,
        src_addr,
        src_port,
        dst_addr,
        dst_port,
        bidirectional,
        contents,
        pcre_patterns,
        flow,
        sticky_buffers: Vec::new(),
        threshold,
        flowbits,
        metadata,
        no_prefilter,
    })
}

/// Parse multiple rules from text (one per line).
pub fn parse_rules(text: &str, source: RuleSource) -> Vec<CompiledRule> {
    let mut rules = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match parse_rule(line, source) {
            Ok(rule) => rules.push(rule),
            Err(e) => {
                tracing::trace!("skipping rule: {e}");
            }
        }
    }
    rules
}

/// Set the buffer on the last content match.
fn set_last_buffer(contents: &mut [ContentMatch], buffer: &str) {
    if let Some(last) = contents.last_mut() {
        last.buffer = Some(buffer.to_string());
    }
}

fn normalize_addr(s: &str) -> Option<String> {
    if s == "any" {
        None
    } else {
        Some(s.to_string())
    }
}

fn normalize_port(s: &str) -> Option<String> {
    if s == "any" {
        None
    } else {
        Some(s.to_string())
    }
}

/// Parse the semicolon-separated options string.
fn parse_options(opts: &str) -> Result<Vec<(String, String)>, String> {
    let mut result = Vec::new();
    let mut current_key = String::new();
    let mut current_value = String::new();
    let mut in_value = false;
    let mut in_quotes = false;
    let mut escaped = false;
    let mut depth = 0; // track nested parens

    for ch in opts.chars() {
        if escaped {
            if in_value {
                current_value.push(ch);
            } else {
                current_key.push(ch);
            }
            escaped = false;
            continue;
        }

        if ch == '\\' {
            escaped = true;
            if in_value {
                current_value.push(ch);
            }
            continue;
        }

        if ch == '"' {
            in_quotes = !in_quotes;
            if in_value {
                current_value.push(ch);
            }
            continue;
        }

        if in_quotes {
            if in_value {
                current_value.push(ch);
            } else {
                current_key.push(ch);
            }
            continue;
        }

        match ch {
            ':' if !in_value && depth == 0 => {
                in_value = true;
            }
            ';' if depth == 0 => {
                let key = current_key.trim().to_string();
                let value = current_value.trim().to_string();
                if !key.is_empty() {
                    result.push((key, value));
                }
                current_key.clear();
                current_value.clear();
                in_value = false;
            }
            '(' => {
                depth += 1;
                if in_value {
                    current_value.push(ch);
                }
            }
            ')' => {
                depth -= 1;
                if in_value {
                    current_value.push(ch);
                }
            }
            _ => {
                if in_value {
                    current_value.push(ch);
                } else {
                    current_key.push(ch);
                }
            }
        }
    }

    // Handle last option (might not have trailing semicolon)
    let key = current_key.trim().to_string();
    let value = current_value.trim().to_string();
    if !key.is_empty() {
        result.push((key, value));
    }

    Ok(result)
}

/// Parse a content value, handling pipe-encoded hex and negation.
/// `"|DE AD|"` → hex bytes, `"text"` → text bytes, `!"text"` → negated
fn parse_content_value(s: &str) -> Result<(Vec<u8>, bool), String> {
    let s = s.trim();
    let (s, negated) = if let Some(stripped) = s.strip_prefix('!') {
        (stripped.trim(), true)
    } else {
        (s, false)
    };

    let s = unquote(s);
    let mut bytes = Vec::new();
    let mut in_hex = false;

    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        if chars[i] == '|' {
            in_hex = !in_hex;
            i += 1;
            continue;
        }

        if in_hex {
            // Skip whitespace in hex mode
            if chars[i].is_whitespace() {
                i += 1;
                continue;
            }
            // Read two hex digits
            if i + 1 < chars.len() {
                let hex_str: String = chars[i..=i + 1].iter().collect();
                if let Ok(byte) = u8::from_str_radix(&hex_str, 16) {
                    bytes.push(byte);
                    i += 2;
                } else {
                    return Err(format!("invalid hex: {hex_str}"));
                }
            } else {
                i += 1;
            }
        } else {
            // Handle escape sequences
            if chars[i] == '\\' && i + 1 < chars.len() {
                match chars[i + 1] {
                    'n' => bytes.push(b'\n'),
                    'r' => bytes.push(b'\r'),
                    't' => bytes.push(b'\t'),
                    '\\' => bytes.push(b'\\'),
                    '"' => bytes.push(b'"'),
                    ';' => bytes.push(b';'),
                    _ => {
                        bytes.push(b'\\');
                        bytes.push(chars[i + 1] as u8);
                    }
                }
                i += 2;
            } else {
                bytes.push(chars[i] as u8);
                i += 1;
            }
        }
    }

    Ok((bytes, negated))
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

fn parse_pcre_pattern(s: &str) -> Option<String> {
    let s = s.trim().trim_start_matches('!');
    // Format: "/pattern/flags" — extract the pattern
    if s.starts_with('/')
        && let Some(last_slash) = s[1..].rfind('/')
    {
        let pattern = &s[1..last_slash + 1];
        let flags = &s[last_slash + 2..];
        // Build regex string with flags
        let mut regex = String::new();
        if flags.contains('i') {
            regex.push_str("(?i)");
        }
        if flags.contains('s') {
            regex.push_str("(?s)");
        }
        if flags.contains('m') {
            regex.push_str("(?m)");
        }
        regex.push_str(pattern);
        return Some(regex);
    }
    None
}

fn parse_flow_constraint(s: &str) -> FlowConstraint {
    let parts: Vec<&str> = s.split(',').map(|p| p.trim()).collect();
    let mut fc = FlowConstraint {
        established: false,
        to_server: None,
        stateless: false,
    };

    for part in parts {
        match part {
            "established" => fc.established = true,
            "to_server" | "from_client" => fc.to_server = Some(true),
            "to_client" | "from_server" => fc.to_server = Some(false),
            "stateless" => fc.stateless = true,
            _ => {}
        }
    }

    fc
}

fn parse_threshold(s: &str) -> Option<ThresholdConfig> {
    let parts: Vec<&str> = s.split(',').map(|p| p.trim()).collect();
    let mut threshold_type = ThresholdType::Limit;
    let mut track = TrackBy::BySrc;
    let mut count = 1;
    let mut seconds = 60;

    for part in parts {
        if let Some((key, value)) = part.split_once(' ') {
            let key = key.trim();
            let value = value.trim();
            match key {
                "type" => {
                    threshold_type = match value {
                        "limit" => ThresholdType::Limit,
                        "threshold" => ThresholdType::Threshold,
                        "both" => ThresholdType::Both,
                        _ => ThresholdType::Limit,
                    };
                }
                "track" => {
                    track = match value {
                        "by_dst" => TrackBy::ByDst,
                        _ => TrackBy::BySrc,
                    };
                }
                "count" => count = value.parse().unwrap_or(1),
                "seconds" => seconds = value.parse().unwrap_or(60),
                _ => {}
            }
        }
    }

    Some(ThresholdConfig {
        threshold_type,
        track,
        count,
        seconds,
    })
}

fn parse_flowbits(s: &str) -> Option<FlowbitOp> {
    let parts: Vec<&str> = s.splitn(2, ',').map(|p| p.trim()).collect();
    if parts.is_empty() {
        return None;
    }

    match parts[0] {
        "set" => parts.get(1).map(|name| FlowbitOp::Set(name.to_string())),
        "isset" => parts.get(1).map(|name| FlowbitOp::IsSet(name.to_string())),
        "unset" => parts.get(1).map(|name| FlowbitOp::Unset(name.to_string())),
        "toggle" => parts.get(1).map(|name| FlowbitOp::Toggle(name.to_string())),
        "noalert" => Some(FlowbitOp::NoAlert),
        _ => None,
    }
}

fn classtype_severity(classtype: &str) -> IdsSeverity {
    match classtype {
        "trojan-activity" | "exploit-kit" | "attempted-admin" | "successful-admin"
        | "shellcode-detect" => IdsSeverity::CRITICAL,
        "attempted-user"
        | "successful-user"
        | "web-application-attack"
        | "web-application-activity"
        | "attempted-dos"
        | "successful-dos" => IdsSeverity::HIGH,
        "bad-unknown"
        | "attempted-recon"
        | "successful-recon-limited"
        | "suspicious-filename-detect"
        | "suspicious-login"
        | "policy-violation" => IdsSeverity::MEDIUM,
        _ => IdsSeverity::INFO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_rule() {
        let rule = r#"alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET MALWARE Test Rule"; content:"malicious"; nocase; sid:1000001; rev:1;)"#;
        let compiled = parse_rule(rule, RuleSource::EtOpen).unwrap();

        assert_eq!(compiled.action, IdsAction::Alert);
        assert_eq!(compiled.protocol, Some("tcp".into()));
        assert_eq!(compiled.src_addr, Some("$HOME_NET".into()));
        assert_eq!(compiled.dst_addr, Some("$EXTERNAL_NET".into()));
        assert_eq!(compiled.msg, "ET MALWARE Test Rule");
        assert_eq!(compiled.sid, Some(1000001));
        assert_eq!(compiled.contents.len(), 1);
        assert!(compiled.contents[0].nocase);
        assert_eq!(compiled.contents[0].pattern, b"malicious");
    }

    #[test]
    fn test_parse_hex_content() {
        let rule =
            r#"alert tcp any any -> any any (msg:"Hex test"; content:"|DE AD BE EF|"; sid:2;)"#;
        let compiled = parse_rule(rule, RuleSource::Custom).unwrap();

        assert_eq!(compiled.contents[0].pattern, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_parse_mixed_content() {
        let rule = r#"alert tcp any any -> any any (msg:"Mixed"; content:"GET |20|/"; sid:3;)"#;
        let compiled = parse_rule(rule, RuleSource::Custom).unwrap();

        assert_eq!(compiled.contents[0].pattern, b"GET \x20/");
    }

    #[test]
    fn test_parse_content_modifiers() {
        let rule = r#"alert http any any -> any any (msg:"Test"; content:"admin"; http_uri; depth:20; offset:0; nocase; fast_pattern; sid:4;)"#;
        let compiled = parse_rule(rule, RuleSource::Custom).unwrap();

        let c = &compiled.contents[0];
        assert_eq!(c.pattern, b"admin");
        assert!(c.nocase);
        assert!(c.fast_pattern);
        assert_eq!(c.depth, Some(20));
        assert_eq!(c.offset, Some(0));
        assert_eq!(c.buffer, Some("http.uri".into()));
    }

    #[test]
    fn test_parse_flow() {
        let rule = r#"alert tcp any any -> any any (msg:"Flow test"; flow:established,to_server; content:"test"; sid:5;)"#;
        let compiled = parse_rule(rule, RuleSource::Custom).unwrap();

        let flow = compiled.flow.unwrap();
        assert!(flow.established);
        assert_eq!(flow.to_server, Some(true));
    }

    #[test]
    fn test_parse_flowbits() {
        let rule = r#"alert tcp any any -> any any (msg:"Flowbits"; flowbits:set,http.detected; content:"HTTP"; sid:6;)"#;
        let compiled = parse_rule(rule, RuleSource::Custom).unwrap();

        assert_eq!(compiled.flowbits.len(), 1);
        assert!(matches!(&compiled.flowbits[0], FlowbitOp::Set(name) if name == "http.detected"));
    }

    #[test]
    fn test_parse_threshold() {
        let rule = r#"alert tcp any any -> any any (msg:"Threshold"; content:"scan"; threshold:type limit, track by_src, count 5, seconds 60; sid:7;)"#;
        let compiled = parse_rule(rule, RuleSource::Custom).unwrap();

        let t = compiled.threshold.unwrap();
        assert_eq!(t.threshold_type, ThresholdType::Limit);
        assert_eq!(t.track, TrackBy::BySrc);
        assert_eq!(t.count, 5);
        assert_eq!(t.seconds, 60);
    }

    #[test]
    fn test_parse_drop_rule() {
        let rule = r#"drop tcp any any -> any any (msg:"Drop test"; content:"bad"; sid:8;)"#;
        let compiled = parse_rule(rule, RuleSource::Custom).unwrap();
        assert_eq!(compiled.action, IdsAction::Drop);
    }

    #[test]
    fn test_parse_bidirectional() {
        let rule = r#"alert tcp any any <> any any (msg:"Bidir"; content:"test"; sid:9;)"#;
        let compiled = parse_rule(rule, RuleSource::Custom).unwrap();
        assert!(compiled.bidirectional);
    }

    #[test]
    fn test_parse_negated_content() {
        let rule = r#"alert tcp any any -> any any (msg:"Negated"; content:!"safe"; sid:10;)"#;
        let compiled = parse_rule(rule, RuleSource::Custom).unwrap();
        assert!(compiled.contents[0].negated);
    }

    #[test]
    fn test_parse_multiple_rules() {
        let text = r#"
# This is a comment
alert tcp any any -> any any (msg:"Rule 1"; content:"test1"; sid:1;)
alert udp any any -> any any (msg:"Rule 2"; content:"test2"; sid:2;)
# Another comment
drop tcp any any -> any any (msg:"Rule 3"; content:"test3"; sid:3;)
"#;
        let rules = parse_rules(text, RuleSource::EtOpen);
        assert_eq!(rules.len(), 3);
        assert_eq!(rules[0].sid, Some(1));
        assert_eq!(rules[2].action, IdsAction::Drop);
    }

    #[test]
    fn test_classtype_severity() {
        assert_eq!(classtype_severity("trojan-activity"), IdsSeverity::CRITICAL);
        assert_eq!(
            classtype_severity("web-application-attack"),
            IdsSeverity::HIGH
        );
        assert_eq!(classtype_severity("attempted-recon"), IdsSeverity::MEDIUM);
        assert_eq!(classtype_severity("unknown-type"), IdsSeverity::INFO);
    }
}
