//! Parser for `swanctl --list-sas --raw` output (#530).
//!
//! `--raw` prints the vici `list-sa` message as an indented tree of
//! `name {` sections, `key = value` pairs and `key = [ ... ]` lists.
//! This module parses that tree generically and extracts
//! [`IpsecLiveStatus`] for AiFw-managed conns (`aifw-*`). The parser is
//! deliberately tolerant: unknown keys are ignored, stray atoms are
//! skipped, and a malformed document yields whatever entries were
//! recovered — status reporting must degrade, not error, when charon
//! adds fields.

use std::collections::HashMap;

use aifw_common::{ChildSaStatus, IpsecLiveStatus};
use uuid::Uuid;

/// One parsed node: a nested section, a scalar, or a list.
#[derive(Debug, Clone)]
enum Node {
    Section(Vec<(String, Node)>),
    Value(String),
    List(Vec<String>),
}

/// Tokenize: whitespace-separated atoms, with `{ } [ ]` split off token
/// edges. The real appliance emits the compact form `key=value` with no
/// spaces (verified on FreeBSD 15 / strongSwan 5.9), so a fragment
/// containing `=` splits at the FIRST `=` into key / `=` / value —
/// later `=` chars stay in the value (DN identities like `C=US`). The
/// indented `key = value` form tokenizes naturally via the standalone
/// `=` word.
fn tokenize(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let push_fragment = |frag: &str, tokens: &mut Vec<String>| {
        if frag.is_empty() {
            return;
        }
        if frag == "=" {
            tokens.push("=".to_string());
            return;
        }
        match frag.split_once('=') {
            Some((key, value)) if !key.is_empty() => {
                tokens.push(key.to_string());
                tokens.push("=".to_string());
                if !value.is_empty() {
                    tokens.push(value.to_string());
                }
            }
            _ => tokens.push(frag.to_string()),
        }
    };
    for word in input.split_whitespace() {
        let mut rest = word;
        loop {
            let Some(pos) = rest.find(['{', '}', '[', ']']) else {
                push_fragment(rest, &mut tokens);
                break;
            };
            push_fragment(&rest[..pos], &mut tokens);
            tokens.push(rest[pos..pos + 1].to_string());
            rest = &rest[pos + 1..];
        }
    }
    tokens
}

/// Parse a token stream into entries until the matching `}` (or end).
fn parse_entries(tokens: &[String], pos: &mut usize) -> Vec<(String, Node)> {
    let mut entries = Vec::new();
    let mut pending: Option<String> = None;
    while *pos < tokens.len() {
        let tok = tokens[*pos].as_str();
        *pos += 1;
        match tok {
            "{" => {
                let name = pending.take().unwrap_or_default();
                entries.push((name, Node::Section(parse_entries(tokens, pos))));
            }
            "}" => break,
            "=" => {
                let Some(key) = pending.take() else { continue };
                if *pos < tokens.len() && tokens[*pos] == "[" {
                    *pos += 1;
                    let mut items = Vec::new();
                    while *pos < tokens.len() && tokens[*pos] != "]" {
                        items.push(tokens[*pos].clone());
                        *pos += 1;
                    }
                    *pos += 1; // consume "]"
                    entries.push((key, Node::List(items)));
                } else if *pos < tokens.len() && tokens[*pos] != "{" && tokens[*pos] != "}" {
                    entries.push((key, Node::Value(tokens[*pos].clone())));
                    *pos += 1;
                }
            }
            atom => {
                // A new atom displaces any stray previous one (e.g. the
                // "list-sa event" preamble atoms before the first brace).
                pending = Some(atom.to_string());
            }
        }
    }
    entries
}

fn get<'a>(entries: &'a [(String, Node)], key: &str) -> Option<&'a Node> {
    entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

fn get_value(entries: &[(String, Node)], key: &str) -> Option<String> {
    match get(entries, key) {
        Some(Node::Value(v)) => Some(v.clone()),
        _ => None,
    }
}

fn get_u64(entries: &[(String, Node)], key: &str) -> Option<u64> {
    get_value(entries, key).and_then(|v| v.parse().ok())
}

fn get_list(entries: &[(String, Node)], key: &str) -> Vec<String> {
    match get(entries, key) {
        Some(Node::List(items)) => items.clone(),
        // Single-element lists sometimes render as plain values.
        Some(Node::Value(v)) => vec![v.clone()],
        _ => Vec::new(),
    }
}

/// Recursively collect every section whose name starts with `aifw-`,
/// skipping `child-sas` containers (children are handled per-conn).
fn collect_aifw_sections<'a>(
    entries: &'a [(String, Node)],
    out: &mut Vec<(&'a str, &'a [(String, Node)])>,
) {
    for (name, node) in entries {
        if let Node::Section(inner) = node {
            if name.starts_with("aifw-") {
                out.push((name.as_str(), inner));
            } else {
                collect_aifw_sections(inner, out);
            }
        }
    }
}

fn parse_child(section_key: &str, entries: &[(String, Node)]) -> ChildSaStatus {
    let enc_alg =
        get_value(entries, "enc-alg").map(|alg| match get_value(entries, "enc-keysize") {
            Some(bits) => format!("{alg}-{bits}"),
            None => alg,
        });
    ChildSaStatus {
        // vici keys child sections by "<name>-<uniqueid>"; the inner
        // `name` field is the configured child name.
        name: get_value(entries, "name").unwrap_or_else(|| section_key.to_string()),
        state: get_value(entries, "state").unwrap_or_else(|| "UNKNOWN".to_string()),
        local_ts: get_list(entries, "local-ts"),
        remote_ts: get_list(entries, "remote-ts"),
        bytes_in: get_u64(entries, "bytes-in").unwrap_or(0),
        bytes_out: get_u64(entries, "bytes-out").unwrap_or(0),
        rekey_in_secs: get_u64(entries, "rekey-time"),
        enc_alg,
    }
}

/// Parse raw `--list-sas` output into per-conn live statuses, keyed by
/// conn name (`aifw-<id>`). Conns absent from the output are simply not
/// in the map — callers report those as down.
pub fn parse_list_sas(raw: &str) -> HashMap<String, IpsecLiveStatus> {
    let tokens = tokenize(raw);
    let mut pos = 0;
    let root = parse_entries(&tokens, &mut pos);

    let mut sections = Vec::new();
    collect_aifw_sections(&root, &mut sections);

    let mut result = HashMap::new();
    for (conn_name, entries) in sections {
        // Child sections also start with aifw- — only IKE SA sections
        // have a `state` at this level AND a parseable tunnel id.
        let Some(tunnel_id) = conn_name
            .strip_prefix("aifw-")
            .and_then(|rest| Uuid::parse_str(rest).ok())
        else {
            continue;
        };
        let mut child_sas = Vec::new();
        if let Some(Node::Section(children)) = get(entries, "child-sas") {
            for (key, node) in children {
                if let Node::Section(child_entries) = node {
                    child_sas.push(parse_child(key, child_entries));
                }
            }
        }
        let status = IpsecLiveStatus {
            tunnel_id,
            conn_name: conn_name.to_string(),
            ike_state: get_value(entries, "state").unwrap_or_else(|| "UNKNOWN".to_string()),
            established_secs: get_u64(entries, "established"),
            remote_host: get_value(entries, "remote-host"),
            ike_version: get_value(entries, "version").and_then(|v| v.parse().ok()),
            child_sas,
        };
        result.insert(conn_name.to_string(), status);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // Shaped like vici_dump output from `swanctl --list-sas --raw`
    // (indented sections, key = value, lists in brackets). Phase 6
    // replaces this with a fixture captured from the real appliance.
    const RAW: &str = r#"list-sa event {
  aifw-11111111-2222-3333-4444-555555555555 {
    uniqueid = 4
    version = 2
    state = ESTABLISHED
    local-host = 198.51.100.1
    local-port = 4500
    local-id = 198.51.100.1
    remote-host = 203.0.113.10
    remote-port = 4500
    remote-id = C=US, O=AiFw, CN=site-b
    initiator = yes
    nat-remote = yes
    encr-alg = AES_GCM_16
    encr-keysize = 256
    established = 773
    rekey-time = 13627
    child-sas {
      aifw-11111111-2222-3333-4444-555555555555-1-4 {
        name = aifw-11111111-2222-3333-4444-555555555555-1
        uniqueid = 4
        reqid = 1
        state = INSTALLED
        mode = TUNNEL
        protocol = ESP
        encap = yes
        spi-in = c9a21f0c
        spi-out = cbdec299
        enc-alg = AES_GCM_16
        enc-keysize = 256
        bytes-in = 1234
        packets-in = 5
        bytes-out = 5678
        packets-out = 6
        rekey-time = 3229
        life-time = 3922
        install-time = 38
        local-ts = [
          10.0.0.0/24
        ]
        remote-ts = [
          10.1.0.0/24
          10.2.0.0/24
        ]
      }
    }
  }
}
"#;

    #[test]
    fn parses_established_sa() {
        let map = parse_list_sas(RAW);
        assert_eq!(map.len(), 1);
        let sa = map
            .get("aifw-11111111-2222-3333-4444-555555555555")
            .unwrap();
        assert_eq!(sa.ike_state, "ESTABLISHED");
        assert_eq!(sa.established_secs, Some(773));
        assert_eq!(sa.remote_host.as_deref(), Some("203.0.113.10"));
        assert_eq!(sa.ike_version, Some(2));
        assert_eq!(
            sa.tunnel_id.to_string(),
            "11111111-2222-3333-4444-555555555555"
        );

        assert_eq!(sa.child_sas.len(), 1);
        let child = &sa.child_sas[0];
        assert_eq!(child.name, "aifw-11111111-2222-3333-4444-555555555555-1");
        assert_eq!(child.state, "INSTALLED");
        assert_eq!(child.bytes_in, 1234);
        assert_eq!(child.bytes_out, 5678);
        assert_eq!(child.rekey_in_secs, Some(3229));
        assert_eq!(child.enc_alg.as_deref(), Some("AES_GCM_16-256"));
        assert_eq!(child.local_ts, vec!["10.0.0.0/24"]);
        assert_eq!(child.remote_ts, vec!["10.1.0.0/24", "10.2.0.0/24"]);
    }

    #[test]
    fn dn_identities_with_equals_do_not_break_structure() {
        // The DN `remote-id = C=US, O=AiFw, CN=site-b` contains atoms
        // with embedded `=`; the parser must not lose the section tree.
        let map = parse_list_sas(RAW);
        let sa = map
            .get("aifw-11111111-2222-3333-4444-555555555555")
            .unwrap();
        assert_eq!(sa.ike_state, "ESTABLISHED");
    }

    #[test]
    fn empty_and_garbage_inputs_yield_empty() {
        assert!(parse_list_sas("").is_empty());
        assert!(parse_list_sas("no sas found").is_empty());
        assert!(parse_list_sas("}{ ] [ = = {").is_empty());
        // non-aifw conns are ignored
        let other = "list-sa event {\n  corporate {\n    state = ESTABLISHED\n  }\n}\n";
        assert!(parse_list_sas(other).is_empty());
        // aifw- prefixed but not a uuid (not ours) is ignored
        let bad = "list-sa event {\n  aifw-notauuid {\n    state = ESTABLISHED\n  }\n}\n";
        assert!(parse_list_sas(bad).is_empty());
    }

    #[test]
    fn compact_single_line_form_parses_too() {
        let compact = "list-sa event {aifw-11111111-2222-3333-4444-555555555555 {version = 2 state = CONNECTING child-sas {}}}";
        let map = parse_list_sas(compact);
        let sa = map
            .get("aifw-11111111-2222-3333-4444-555555555555")
            .unwrap();
        assert_eq!(sa.ike_state, "CONNECTING");
        assert!(sa.child_sas.is_empty());
    }

    // Captured verbatim from FreeBSD 15.0 / strongSwan 5.9.14
    // (`aifw-sudo-swanctl --list-sas --raw`, tunnel initiating toward an
    // unreachable peer). The real compact form has NO spaces around `=`.
    const RAW_REAL: &str = "list-sa event {aifw-2034aa9d-ef08-4c9f-a4c4-f6d80c888823 {uniqueid=1 version=2 state=CONNECTING local-host=172.29.50.220 local-port=500 local-id=%any remote-host=203.0.113.10 remote-port=500 remote-id=%any initiator=yes initiator-spi=00f1cbca60dae3e7 responder-spi=0000000000000000 tasks-active=[IKE_VENDOR IKE_INIT IKE_NATD IKE_CERT_PRE IKE_AUTH IKE_CERT_POST IKE_CONFIG IKE_AUTH_LIFETIME IKE_MOBIKE IKE_ESTABLISH CHILD_CREATE] child-sas {}}}\nlist-sas reply {}\n";

    #[test]
    fn real_freebsd_compact_output_parses() {
        let map = parse_list_sas(RAW_REAL);
        assert_eq!(map.len(), 1);
        let sa = map
            .get("aifw-2034aa9d-ef08-4c9f-a4c4-f6d80c888823")
            .unwrap();
        assert_eq!(sa.ike_state, "CONNECTING");
        assert_eq!(sa.ike_version, Some(2));
        assert_eq!(sa.remote_host.as_deref(), Some("203.0.113.10"));
        assert_eq!(sa.established_secs, None);
        assert!(sa.child_sas.is_empty());
    }
}
