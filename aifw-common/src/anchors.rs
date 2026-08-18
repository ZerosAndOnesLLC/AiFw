//! pf anchor names AiFw owns (#198).
//!
//! Every engine loads into its own anchor so AiFw never touches the system
//! ruleset outside these hooks; `aifw-setup` writes the matching `anchor`/
//! `nat-anchor`/`rdr-anchor` lines into `pf.conf`, and the API/daemon heal
//! them if missing. Convention: `aifw` for the base filter ruleset,
//! `aifw-<domain>` for everything else. New engines take their anchor from
//! here (constructor default) and expose `with_anchor()` only for tests.

/// Base filter ruleset (`RuleEngine`); traffic-shaping queues attach here too.
pub const FILTER: &str = "aifw";
/// NAT / rdr / binat / `af-to` rules (`NatEngine`).
pub const NAT: &str = "aifw-nat";
/// WireGuard / IPsec pass rules (`VpnEngine`).
pub const VPN: &str = "aifw-vpn";
/// Geo-IP allow/block rules + tables (`GeoIpEngine`).
pub const GEOIP: &str = "aifw-geoip";
/// CARP / pfsync pass rules (`ClusterEngine`).
pub const HA: &str = "aifw-ha";
/// TLS inspection redirect rules (`TlsEngine`).
pub const TLS: &str = "aifw-tls";
/// Multi-WAN policy-based routing (`PolicyEngine`).
pub const PBR: &str = "aifw-pbr";
/// Multi-WAN reply-to rules (`PolicyEngine`).
pub const MWAN_REPLY: &str = "aifw-mwan-reply";
/// Multi-WAN leak-detection block rules (`LeakEngine`).
pub const MWAN_LEAK: &str = "aifw-mwan-leak";
/// Suffix appended to the filter anchor for connection rate-limit rules
/// (`ShapingEngine`): `aifw-ratelimit`.
pub const RATELIMIT_SUFFIX: &str = "-ratelimit";
/// Connection rate-limit rules under the default filter anchor.
pub const RATELIMIT: &str = "aifw-ratelimit";

/// Filter-class anchors `pf.conf` must hook (`anchor "…"`), in evaluation
/// order: multi-WAN first so route-to / rtable decisions exist before general
/// filtering, then the base ruleset and the per-domain anchors. `NAT`
/// additionally needs `nat-anchor`/`rdr-anchor` hooks. `aifw-setup` writes
/// this list; the API/daemon heal missing hooks from it.
pub const FILTER_HOOKS: &[&str] = &[
    PBR, MWAN_LEAK, MWAN_REPLY, FILTER, NAT, RATELIMIT, VPN, GEOIP, TLS, HA,
];

/// Rate-limit anchor derived from a filter anchor.
pub fn ratelimit_anchor(filter_anchor: &str) -> String {
    format!("{filter_anchor}{RATELIMIT_SUFFIX}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn convention_holds() {
        assert_eq!(FILTER, "aifw");
        for a in FILTER_HOOKS {
            assert!(
                *a == FILTER || a.starts_with("aifw-"),
                "{a} breaks the aifw-<domain> convention"
            );
        }
        assert_eq!(ratelimit_anchor(FILTER), RATELIMIT);
        let mut all: Vec<&str> = FILTER_HOOKS.to_vec();
        all.sort();
        all.dedup();
        assert_eq!(all.len(), FILTER_HOOKS.len(), "duplicate anchor names");
    }
}
