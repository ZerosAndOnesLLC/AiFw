//! Feed body parsing.

use std::net::IpAddr;

use super::feeds::Format;
use crate::schema::parse_cidr;

/// Normalize `ip/len` to its network address.
pub fn network(ip: IpAddr, len: u8) -> (IpAddr, u8) {
    let (first, _) = aifw_common::net_safety::prefix_range(ip, len);
    let ip = match ip {
        IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::from(first as u32)),
        IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::from(first)),
    };
    (ip, len)
}

/// Parsed feed body.
#[derive(Debug, Default, PartialEq)]
pub struct Parsed {
    /// Networks found (normalized to their network address)
    pub entries: Vec<(IpAddr, u8)>,
    /// Non-empty, non-comment lines that didn't parse
    pub skipped: usize,
}

fn strip_comment(line: &str) -> &str {
    let cut = line.find(['#', ';']).unwrap_or(line.len());
    line[..cut].trim()
}

fn parse_line(line: &str) -> Option<(IpAddr, u8)> {
    if line.starts_with('{') {
        // JSON lines (Spamhaus): {"cidr":"1.10.16.0/20",...}; the trailing
        // metadata record has no cidr and is ignored.
        let v: serde_json::Value = serde_json::from_str(line).ok()?;
        let s = v.get("cidr").or_else(|| v.get("ip"))?.as_str()?;
        return parse_cidr(s);
    }
    let token = line.split([' ', '\t', ',']).find(|t| !t.is_empty())?;
    parse_cidr(token)
}

/// Parse a feed body.
pub fn parse(format: Format, body: &str) -> Parsed {
    let mut out = Parsed::default();
    for raw in body.lines() {
        let line = match format {
            // JSON lines may legitimately contain '#'/';' inside strings.
            Format::Lines if raw.trim_start().starts_with('{') => raw.trim(),
            _ => strip_comment(raw),
        };
        if line.is_empty() {
            continue;
        }
        let parsed = match format {
            Format::Lines => parse_line(line),
            Format::DShield => {
                let cols: Vec<&str> = line.split_whitespace().collect();
                match (cols.first(), cols.get(2)) {
                    (Some(start), Some(len)) => parse_cidr(&format!("{start}/{len}")),
                    _ => None,
                }
            }
        };
        match parsed {
            Some((ip, len)) => out.entries.push(network(ip, len)),
            None => {
                // The Spamhaus metadata trailer and the DShield column header
                // aren't data errors.
                if !line.contains("\"type\":\"metadata\"") && !line.starts_with("Start") {
                    out.skipped += 1;
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(entries: &[(IpAddr, u8)]) -> Vec<String> {
        entries.iter().map(|(ip, l)| format!("{ip}/{l}")).collect()
    }

    #[test]
    fn spamhaus_json_lines() {
        let body = r#"{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
{"cidr":"2001:678:254::/48","sblid":"SBL697648","rir":"ripencc"}
{"type":"metadata","timestamp":1728000000,"size":2,"records":2,"copyright":"(c) 2024 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}
"#;
        let p = parse(Format::Lines, body);
        assert_eq!(s(&p.entries), ["1.10.16.0/20", "2001:678:254::/48"]);
        assert_eq!(p.skipped, 0);
    }

    #[test]
    fn plain_lists_with_comments() {
        let body = "# Feodo\n#\n50.16.16.211\n1.2.3.4 ; note\n10.0.0.0/8\n\ngarbage\n5.6.7.9/24\n";
        let p = parse(Format::Lines, body);
        assert_eq!(
            s(&p.entries),
            ["50.16.16.211/32", "1.2.3.4/32", "10.0.0.0/8", "5.6.7.0/24"]
        );
        assert_eq!(p.skipped, 1);
    }

    #[test]
    fn dshield_block_txt() {
        let body = "# comment\nStart\tEnd\tNetblock\tAttacks\tName\tCountry\temail\n\
                    45.198.224.0\t45.198.224.255\t24\t347\tOWS\tUS\tCSOC@ontario.ca\n";
        let p = parse(Format::DShield, body);
        assert_eq!(s(&p.entries), ["45.198.224.0/24"]);
        assert_eq!(p.skipped, 0);
    }
}
