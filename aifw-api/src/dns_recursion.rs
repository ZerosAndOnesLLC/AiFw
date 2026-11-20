//! Who may use the rDNS resolver recursively (#721).
//!
//! rDNS only takes an allow-list (`[security] allow_recursion`) and treats
//! an empty list as "open to everyone", so AiFw must always render one:
//! loopback, plus the `allow` / `allow_snoop` entries of the DNS access
//! list, or — when that list allows nothing — the networks on the
//! firewall's non-WAN interfaces.

use std::net::IpAddr;

use ip_network::IpNetwork;
use sqlx::SqlitePool;

const LOOPBACK: [&str; 2] = ["127.0.0.0/8", "::1/128"];

/// The `allow_recursion` CIDRs for rdns.toml.
pub(crate) async fn allow_list(pool: &SqlitePool) -> Vec<String> {
    let acls = sqlx::query_as::<_, (String, String)>(
        "SELECT network, action FROM dns_access_lists ORDER BY rowid ASC",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_else(|e| {
        tracing::warn!(error = %e, "dns: could not read access lists; recursion limited to local networks");
        Vec::new()
    });
    let wan: Vec<String> =
        sqlx::query_scalar("SELECT interface_name FROM interface_roles WHERE upper(role) = 'WAN'")
            .fetch_all(pool)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "dns: could not read interface roles");
                Vec::new()
            });
    build(&acls, || local_networks(&wan))
}

/// Pure part: ACL entries → allow-list, falling back to `local()` when the
/// access list allows nothing. Invalid entries are dropped (they come from
/// the DB and end up in a root-read TOML file).
fn build(acls: &[(String, String)], local: impl FnOnce() -> Vec<IpNetwork>) -> Vec<String> {
    let mut out: Vec<String> = LOOPBACK.iter().map(|s| s.to_string()).collect();
    let mut allowed = false;
    for (network, action) in acls {
        if !matches!(action.as_str(), "allow" | "allow_snoop") {
            continue;
        }
        match parse_net(network) {
            Some(net) => {
                allowed = true;
                push_unique(&mut out, net.to_string());
            }
            None => tracing::warn!(%network, "dns: ignoring invalid access-list network"),
        }
    }
    if !allowed {
        for net in local() {
            push_unique(&mut out, net.to_string());
        }
    }
    out
}

fn push_unique(out: &mut Vec<String>, v: String) {
    if !out.contains(&v) {
        out.push(v);
    }
}

fn parse_net(s: &str) -> Option<IpNetwork> {
    let s = s.trim();
    let (ip, prefix) = match s.split_once('/') {
        Some((ip, p)) => (ip.parse::<IpAddr>().ok()?, p.parse::<u8>().ok()?),
        None => {
            let ip = s.parse::<IpAddr>().ok()?;
            (ip, if ip.is_ipv4() { 32 } else { 128 })
        }
    };
    IpNetwork::new_truncate(ip, prefix).ok()
}

/// Networks configured on this box's interfaces, except loopback, WAN
/// interfaces and IPv6 link-local.
fn local_networks(wan: &[String]) -> Vec<IpNetwork> {
    let addrs = match nix::ifaddrs::getifaddrs() {
        Ok(a) => a,
        Err(e) => {
            tracing::warn!(error = %e, "dns: could not list interface addresses");
            return Vec::new();
        }
    };
    let mut nets = Vec::new();
    for ifa in addrs {
        if ifa.interface_name.starts_with("lo") || wan.contains(&ifa.interface_name) {
            continue;
        }
        let (Some(addr), Some(mask)) = (ifa.address, ifa.netmask) else {
            continue;
        };
        let pair = if let (Some(a), Some(m)) = (addr.as_sockaddr_in(), mask.as_sockaddr_in()) {
            Some((IpAddr::V4(a.ip()), u32::from(m.ip()).count_ones()))
        } else if let (Some(a), Some(m)) = (addr.as_sockaddr_in6(), mask.as_sockaddr_in6()) {
            let ip = a.ip();
            (!ip.is_unicast_link_local()).then(|| (IpAddr::V6(ip), u128::from(m.ip()).count_ones()))
        } else {
            None
        };
        if let Some((ip, prefix)) = pair
            && let Ok(prefix) = u8::try_from(prefix)
            && let Ok(net) = IpNetwork::new_truncate(ip, prefix)
            && !nets.contains(&net)
        {
            nets.push(net);
        }
    }
    nets
}

#[cfg(test)]
mod tests {
    use super::*;

    fn acl(n: &str, a: &str) -> (String, String) {
        (n.to_string(), a.to_string())
    }

    #[test]
    fn allow_entries_become_the_list() {
        let acls = [
            acl("127.0.0.0/8", "allow"),
            acl("172.29.0.0/16", "allow"),
            acl("10.9.9.9/32", "deny"),
            acl("2001:db8:1::/48", "allow_snoop"),
            acl("192.168.1.7", "allow"),
            acl("bogus\"]\nx", "allow"),
        ];
        let list = build(&acls, || {
            panic!("no fallback when the ACL allows something")
        });
        assert_eq!(
            list,
            [
                "127.0.0.0/8",
                "::1/128",
                "172.29.0.0/16",
                "2001:db8:1::/48",
                "192.168.1.7/32"
            ]
        );
    }

    #[test]
    fn without_allow_entries_local_networks_are_used() {
        let acls = [acl("10.0.0.0/8", "refuse")];
        let lan = parse_net("192.168.10.0/24").unwrap();
        let list = build(&acls, || vec![lan]);
        assert_eq!(list, ["127.0.0.0/8", "::1/128", "192.168.10.0/24"]);
    }

    #[test]
    fn never_empty() {
        assert_eq!(build(&[], Vec::new), ["127.0.0.0/8", "::1/128"]);
    }

    #[test]
    fn host_bits_are_truncated() {
        assert_eq!(
            parse_net("172.29.69.1/24").unwrap().to_string(),
            "172.29.69.0/24"
        );
    }
}
