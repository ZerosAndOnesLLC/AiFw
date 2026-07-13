//! Low-level match primitives shared by the detection engine: content
//! (byte-pattern) matching with offset/depth/nocase, and CIDR membership.

use std::net::IpAddr;

use crate::rules::ContentMatch;

/// Check if a content pattern matches data with position constraints.
pub(super) fn content_match(content: &ContentMatch, data: &[u8]) -> bool {
    let pattern = if content.nocase {
        content.pattern.to_ascii_lowercase()
    } else {
        content.pattern.clone()
    };

    let search_data = if content.nocase {
        data.to_ascii_lowercase()
    } else {
        data.to_vec()
    };

    let start = content.offset.unwrap_or(0);
    let end = content
        .depth
        .map(|d| (start + d).min(search_data.len()))
        .unwrap_or(search_data.len());

    if start >= search_data.len() || end <= start {
        return false;
    }

    let search_range = &search_data[start..end];

    // Use memchr for single-byte patterns, otherwise search
    if pattern.len() == 1 {
        memchr::memchr(pattern[0], search_range).is_some()
    } else if !pattern.is_empty() {
        search_range
            .windows(pattern.len())
            .any(|window| window == pattern.as_slice())
    } else {
        true // empty pattern always matches
    }
}

pub(super) fn ip_in_cidr(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let mask = if prefix >= 32 {
                u32::MAX
            } else {
                u32::MAX << (32 - prefix)
            };
            (u32::from(ip) & mask) == (u32::from(net) & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let ip_bits = u128::from(ip);
            let net_bits = u128::from(net);
            let mask = if prefix >= 128 {
                u128::MAX
            } else {
                u128::MAX << (128 - prefix)
            };
            (ip_bits & mask) == (net_bits & mask)
        }
        _ => false,
    }
}
