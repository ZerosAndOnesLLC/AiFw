//! SSRF guards for outbound HTTP from the daemon.
//!
//! Several classes of outbound request are operator-configurable and therefore
//! reachable by anyone with admin API access: DDNS IP-echo URLs, ACME export
//! webhooks, IDS ruleset feeds, alias URL-tables, and DNS blocklists. Without
//! these checks, a compromised admin account can steer the daemon at
//! 127.0.0.1, RFC1918, cloud metadata endpoints, or `file://` local paths.
//!
//! DNS rebinding is partially mitigated: we resolve up front and check
//! every returned address. For complete protection the caller would need
//! a connect-time hook; this is a best-effort pre-flight.
//!
//! Usage: call [`validate_outbound_url`] before constructing the request.

use std::net::IpAddr;

/// Validate that `url_str` is safe to send an outbound HTTPS request to.
///
/// Enforced:
/// - scheme must be `https`
/// - host must resolve to one or more globally-routable addresses
/// - loopback, private (RFC1918), link-local, CGNAT, ULA, multicast,
///   reserved, unspecified, and IPv4-mapped-private addresses are refused
pub async fn validate_outbound_url(url_str: &str) -> Result<(), String> {
    let url = url::Url::parse(url_str).map_err(|e| format!("invalid URL: {e}"))?;
    if url.scheme() != "https" {
        return Err(format!(
            "only https:// URLs are allowed (got {})",
            url.scheme()
        ));
    }
    let host = url
        .host_str()
        .ok_or_else(|| "URL has no host".to_string())?;

    if let Ok(ip) = host.parse::<IpAddr>() {
        return ensure_public(ip);
    }

    let port = url.port_or_known_default().unwrap_or(443);
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|e| format!("DNS lookup {host}: {e}"))?;
    let mut any = false;
    for sa in addrs {
        ensure_public(sa.ip())?;
        any = true;
    }
    if !any {
        return Err(format!("{host} did not resolve"));
    }
    Ok(())
}

/// True if `ip` is a globally routable address (the inverse of the
/// SSRF block list used by [`validate_outbound_url`]).
pub fn is_public(ip: IpAddr) -> bool {
    !is_blocked(ip)
}

/// Non-public IPv4 space: unspecified, RFC1918, CGNAT, loopback,
/// link-local, IETF protocol assignments, documentation, benchmarking,
/// multicast, reserved + broadcast.
const NON_PUBLIC_V4: &[([u8; 4], u8)] = &[
    ([0, 0, 0, 0], 8),
    ([10, 0, 0, 0], 8),
    ([100, 64, 0, 0], 10),
    ([127, 0, 0, 0], 8),
    ([169, 254, 0, 0], 16),
    ([172, 16, 0, 0], 12),
    ([192, 0, 0, 0], 24),
    ([192, 0, 2, 0], 24),
    ([192, 168, 0, 0], 16),
    ([198, 18, 0, 0], 15),
    ([198, 51, 100, 0], 24),
    ([203, 0, 113, 0], 24),
    ([224, 0, 0, 0], 4),
    ([240, 0, 0, 0], 4),
];

/// Non-public IPv6 space: unspecified, loopback, IPv4-mapped, NAT64,
/// discard, documentation, ULA, link-local, multicast.
const NON_PUBLIC_V6: &[([u16; 8], u8)] = &[
    ([0, 0, 0, 0, 0, 0, 0, 0], 128),
    ([0, 0, 0, 0, 0, 0, 0, 1], 128),
    ([0, 0, 0, 0, 0, 0xffff, 0, 0], 96),
    ([0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 96),
    ([0x100, 0, 0, 0, 0, 0, 0, 0], 64),
    ([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32),
    ([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
    ([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
    ([0xff00, 0, 0, 0, 0, 0, 0, 0], 8),
];

/// `(first, last)` address of `ip/len` as integers (IPv4 widened to u128).
pub fn prefix_range(ip: IpAddr, len: u8) -> (u128, u128) {
    let (bits, value) = match ip {
        IpAddr::V4(v4) => (32u32, u128::from(u32::from(v4))),
        IpAddr::V6(v6) => (128u32, u128::from(v6)),
    };
    let len = u32::from(len).min(bits);
    let host_bits = bits - len;
    let host_mask: u128 = if host_bits == 0 {
        0
    } else if host_bits == 128 {
        u128::MAX
    } else {
        (1u128 << host_bits) - 1
    };
    let first = value & !host_mask;
    (first, first | host_mask)
}

/// True if no address in `ip/len` falls in non-public space — i.e. the
/// whole prefix is globally routable. Used to keep third-party blocklists
/// from black-holing LAN, loopback or bogon ranges.
pub fn is_public_prefix(ip: IpAddr, len: u8) -> bool {
    let (first, last) = prefix_range(ip, len);
    let overlaps = |r: (u128, u128)| first <= r.1 && r.0 <= last;
    match ip {
        IpAddr::V4(_) => !NON_PUBLIC_V4
            .iter()
            .any(|(o, l)| overlaps(prefix_range(IpAddr::from(*o), *l))),
        IpAddr::V6(_) => !NON_PUBLIC_V6
            .iter()
            .any(|(s, l)| overlaps(prefix_range(IpAddr::V6(std::net::Ipv6Addr::from(*s)), *l))),
    }
}

fn ensure_public(ip: IpAddr) -> Result<(), String> {
    if is_blocked(ip) {
        Err(format!("blocked: {ip} is not a public address"))
    } else {
        Ok(())
    }
}

fn is_blocked(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4.is_documentation()
                // Carrier-grade NAT 100.64.0.0/10
                || (o[0] == 100 && (o[1] & 0xc0) == 0x40)
                // Benchmark 198.18.0.0/15
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                // Reserved 240.0.0.0/4
                || o[0] >= 240
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_multicast() || v6.is_unspecified() {
                return true;
            }
            let s = v6.segments();
            // Link-local fe80::/10
            if (s[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // Unique local fc00::/7
            if (s[0] & 0xfe00) == 0xfc00 {
                return true;
            }
            // IPv4-mapped / 4-in-6 tunnel addresses — fold back to v4 check.
            if let Some(v4) = v6.to_ipv4() {
                return is_blocked(IpAddr::V4(v4));
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn public_prefix_rejects_any_overlap_with_private_space() {
        let p = |s: &str, l: u8| is_public_prefix(s.parse().unwrap(), l);
        assert!(p("1.10.16.0", 20));
        assert!(p("8.8.8.8", 32));
        assert!(!p("10.1.0.0", 16));
        assert!(!p("0.0.0.0", 8));
        // 100.0.0.0/8 is mostly public but contains CGNAT 100.64/10.
        assert!(!p("100.0.0.0", 8));
        assert!(!p("192.168.1.7", 32));
        assert!(p("2a00:1450::", 32));
        assert!(!p("fd00::", 8));
        assert!(!p("2001:db8::1", 128));
        assert!(!p("::ffff:10.0.0.1", 128));
    }

    #[test]
    fn prefix_range_masks_host_bits() {
        let (a, b) = prefix_range("10.1.2.3".parse().unwrap(), 24);
        assert_eq!(a, u128::from(u32::from(Ipv4Addr::new(10, 1, 2, 0))));
        assert_eq!(b, u128::from(u32::from(Ipv4Addr::new(10, 1, 2, 255))));
        let (a, b) = prefix_range("::".parse().unwrap(), 0);
        assert_eq!((a, b), (0, u128::MAX));
    }

    #[test]
    fn blocks_loopback_v4() {
        assert!(is_blocked(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn blocks_rfc1918() {
        for ip in [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
        ] {
            assert!(is_blocked(IpAddr::V4(ip)), "should block {ip}");
        }
    }

    #[test]
    fn blocks_link_local_v4() {
        assert!(is_blocked(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
    }

    #[test]
    fn blocks_cgnat() {
        assert!(is_blocked(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(is_blocked(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 255))));
        assert!(!is_blocked(IpAddr::V4(Ipv4Addr::new(100, 63, 255, 255))));
        assert!(!is_blocked(IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1))));
    }

    #[test]
    fn blocks_ipv6_loopback_and_ula() {
        assert!(is_blocked(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_blocked(IpAddr::V6("fc00::1".parse().unwrap())));
        assert!(is_blocked(IpAddr::V6("fd12:3456::1".parse().unwrap())));
    }

    #[test]
    fn blocks_link_local_v6() {
        assert!(is_blocked(IpAddr::V6("fe80::1".parse().unwrap())));
    }

    #[test]
    fn blocks_ipv4_mapped_rfc1918() {
        let v6: Ipv6Addr = "::ffff:10.0.0.1".parse().unwrap();
        assert!(is_blocked(IpAddr::V6(v6)));
    }

    #[test]
    fn allows_public_v4() {
        assert!(!is_blocked(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!is_blocked(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn allows_public_v6() {
        assert!(!is_blocked(IpAddr::V6(
            "2606:4700:4700::1111".parse().unwrap()
        )));
    }

    #[tokio::test]
    async fn rejects_http_scheme() {
        let err = validate_outbound_url("http://example.com/")
            .await
            .unwrap_err();
        assert!(err.contains("https"));
    }

    #[tokio::test]
    async fn rejects_file_scheme() {
        let err = validate_outbound_url("file:///etc/passwd")
            .await
            .unwrap_err();
        assert!(err.contains("https"));
    }

    #[tokio::test]
    async fn rejects_literal_loopback() {
        let err = validate_outbound_url("https://127.0.0.1/")
            .await
            .unwrap_err();
        assert!(err.contains("not a public"));
    }

    #[tokio::test]
    async fn rejects_literal_metadata_ip() {
        let err = validate_outbound_url("https://169.254.169.254/latest/meta-data/")
            .await
            .unwrap_err();
        assert!(err.contains("not a public"));
    }
}
