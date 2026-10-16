//! Turn raw feed entries into a safe pf table: third-party lists must
//! never black-hole the LAN or half the internet.

use std::net::IpAddr;

use aifw_common::net_safety::{is_public_prefix, prefix_range};
use serde::Serialize;

/// Shortest IPv4 prefix accepted from a feed.
pub const MIN_V4_PREFIX: u8 = 8;
/// Shortest IPv6 prefix accepted from a feed.
pub const MIN_V6_PREFIX: u8 = 12;

/// What sanitizing removed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Dropped {
    /// Overlapped private, loopback, bogon or other non-public space
    pub non_public: usize,
    /// Broader than /8 (IPv4) or /12 (IPv6)
    pub too_broad: usize,
    /// Overlapped the operator's allowlist
    pub allowlisted: usize,
    /// Duplicates or covered by a broader entry
    pub redundant: usize,
    /// Cut to stay under the entry cap
    pub over_cap: usize,
}

fn overlaps(a: (IpAddr, u8), b: (IpAddr, u8)) -> bool {
    if a.0.is_ipv4() != b.0.is_ipv4() {
        return false;
    }
    let (a0, a1) = prefix_range(a.0, a.1);
    let (b0, b1) = prefix_range(b.0, b.1);
    a0 <= b1 && b0 <= a1
}

/// Filter, de-duplicate and cap `entries`. Allowlisted space can't be
/// carved out of a pf table entry, so a feed entry that overlaps the
/// allowlist at all is skipped whole.
pub fn sanitize(
    entries: Vec<(IpAddr, u8)>,
    allowlist: &[(IpAddr, u8)],
    max_entries: usize,
) -> (Vec<(IpAddr, u8)>, Dropped) {
    let mut dropped = Dropped::default();
    let mut kept: Vec<(bool, u128, u128, IpAddr, u8)> = Vec::with_capacity(entries.len());
    for (ip, len) in entries {
        let min = if ip.is_ipv4() {
            MIN_V4_PREFIX
        } else {
            MIN_V6_PREFIX
        };
        if len < min {
            dropped.too_broad += 1;
        } else if !is_public_prefix(ip, len) {
            dropped.non_public += 1;
        } else if allowlist.iter().any(|a| overlaps(*a, (ip, len))) {
            dropped.allowlisted += 1;
        } else {
            let (first, last) = prefix_range(ip, len);
            kept.push((ip.is_ipv6(), first, last, ip, len));
        }
    }

    // Sort by family, start address, broadest first; then sweep once,
    // dropping anything inside the range of an entry already kept.
    kept.sort_by_key(|k| (k.0, k.1, k.4));
    let mut out: Vec<(IpAddr, u8)> = Vec::with_capacity(kept.len());
    let mut cover: Option<(bool, u128)> = None;
    for (v6, first, last, ip, len) in kept {
        if let Some((cv6, cend)) = cover
            && cv6 == v6
            && last <= cend
            && first <= cend
        {
            dropped.redundant += 1;
            continue;
        }
        cover = Some((v6, last));
        out.push((ip, len));
    }

    if out.len() > max_entries {
        dropped.over_cap = out.len() - max_entries;
        out.truncate(max_entries);
    }
    (out, dropped)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(s: &str) -> (IpAddr, u8) {
        crate::schema::parse_cidr(s).unwrap()
    }

    #[test]
    fn drops_private_broad_allowlisted_and_redundant() {
        let entries = vec![
            n("0.0.0.0/8"),      // bogon
            n("10.0.0.0/8"),     // RFC1918
            n("192.168.1.5"),    // RFC1918 host
            n("1.0.0.0/7"),      // too broad
            n("5.0.0.0/16"),     // keep
            n("5.0.1.7"),        // inside 5.0.0.0/16
            n("5.0.0.0/16"),     // duplicate
            n("9.9.9.0/24"),     // overlaps allowlist
            n("2a00:1450::/32"), // keep
            n("fd00::1"),        // ULA
        ];
        let (out, d) = sanitize(entries, &[n("9.9.9.9")], 100);
        let got: Vec<String> = out.iter().map(|(i, l)| format!("{i}/{l}")).collect();
        assert_eq!(got, ["5.0.0.0/16", "2a00:1450::/32"]);
        assert_eq!(
            d,
            Dropped {
                non_public: 4,
                too_broad: 1,
                allowlisted: 1,
                redundant: 2,
                over_cap: 0
            }
        );
    }

    #[test]
    fn caps_entry_count() {
        let entries: Vec<_> = (1..=10u8).map(|i| n(&format!("44.0.{i}.0/24"))).collect();
        let (out, d) = sanitize(entries, &[], 4);
        assert_eq!(out.len(), 4);
        assert_eq!(d.over_cap, 6);
    }

    #[test]
    fn families_do_not_cover_each_other() {
        let (out, _) = sanitize(vec![n("2a00::/12"), n("44.1.2.3")], &[], 10);
        assert_eq!(out.len(), 2);
    }
}
