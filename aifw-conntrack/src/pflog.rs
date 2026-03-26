use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

/// Parsed pflog entry representing a single logged packet event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PfLogEntry {
    pub timestamp: DateTime<Utc>,
    pub rule_number: u32,
    pub action: PfLogAction,
    pub direction: PfLogDirection,
    pub interface: String,
    pub protocol: String,
    pub src_addr: IpAddr,
    pub src_port: u16,
    pub dst_addr: IpAddr,
    pub dst_port: u16,
    pub reason: String,
    pub length: u32,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PfLogAction {
    Pass,
    Block,
    Match,
}

impl std::fmt::Display for PfLogAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PfLogAction::Pass => write!(f, "pass"),
            PfLogAction::Block => write!(f, "block"),
            PfLogAction::Match => write!(f, "match"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PfLogDirection {
    In,
    Out,
}

impl std::fmt::Display for PfLogDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PfLogDirection::In => write!(f, "in"),
            PfLogDirection::Out => write!(f, "out"),
        }
    }
}

/// Parser for pflog text output (as produced by tcpdump -n -e -ttt -i pflog0)
pub struct PfLogParser;

impl PfLogParser {
    /// Parse a single pflog line from tcpdump output.
    ///
    /// Expected format (tcpdump -n -e -ttt -i pflog0):
    /// `rule 0/(match) block in on em0: 192.168.1.100.12345 > 10.0.0.1.80: tcp 0`
    pub fn parse_line(line: &str, timestamp: DateTime<Utc>) -> Option<PfLogEntry> {
        let line = line.trim();
        if line.is_empty() {
            return None;
        }

        // Parse: rule <num>/(<sub>) <action> <direction> on <iface>: <src> > <dst>: <proto> <len>
        let rest = line.strip_prefix("rule ")?;

        // rule number
        let (rule_num_str, rest) = rest.split_once('/')?;
        let rule_number: u32 = rule_num_str.parse().ok()?;

        // skip subrule in parens
        let rest = if let Some(idx) = rest.find(')') {
            &rest[idx + 1..]
        } else {
            rest
        };
        let rest = rest.trim_start();

        // action
        let (action_str, rest) = rest.split_once(' ')?;
        let action = match action_str {
            "pass" => PfLogAction::Pass,
            "block" => PfLogAction::Block,
            "match" => PfLogAction::Match,
            _ => return None,
        };

        // direction
        let (dir_str, rest) = rest.split_once(' ')?;
        let direction = match dir_str {
            "in" => PfLogDirection::In,
            "out" => PfLogDirection::Out,
            _ => return None,
        };

        // "on <iface>:"
        let rest = rest.strip_prefix("on ")?;
        let (interface, rest) = rest.split_once(':')?;
        let interface = interface.trim().to_string();
        let rest = rest.trim();

        // src > dst : proto len
        let (src_str, rest) = rest.split_once(" > ")?;
        let (dst_str, rest) = rest.split_once(':')?;
        let rest = rest.trim();

        let (src_addr, src_port) = parse_addr_port(src_str.trim())?;
        let (dst_addr, dst_port) = parse_addr_port(dst_str.trim())?;

        // protocol and length
        let parts: Vec<&str> = rest.split_whitespace().collect();
        let protocol = parts.first().unwrap_or(&"unknown").to_string();
        let length: u32 = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(0);

        Some(PfLogEntry {
            timestamp,
            rule_number,
            action,
            direction,
            interface,
            protocol,
            src_addr,
            src_port,
            dst_addr,
            dst_port,
            reason: String::new(),
            length,
        })
    }
}

/// Parse "1.2.3.4.port" or "[::1].port" into (IpAddr, port)
fn parse_addr_port(s: &str) -> Option<(IpAddr, u16)> {
    // IPv6: [addr].port
    if s.starts_with('[') {
        let end_bracket = s.find(']')?;
        let addr: IpAddr = s[1..end_bracket].parse().ok()?;
        let port_str = &s[end_bracket + 1..];
        let port: u16 = port_str.strip_prefix('.').and_then(|p| p.parse().ok()).unwrap_or(0);
        return Some((addr, port));
    }
    // IPv4: last dot-separated component is port
    if let Some(last_dot) = s.rfind('.') {
        if let Ok(port) = s[last_dot + 1..].parse::<u16>() {
            if let Ok(addr) = s[..last_dot].parse::<IpAddr>() {
                return Some((addr, port));
            }
        }
    }
    // No port
    let addr: IpAddr = s.parse().ok()?;
    Some((addr, 0))
}
