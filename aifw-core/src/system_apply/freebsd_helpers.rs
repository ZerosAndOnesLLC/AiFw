//! Pure string helpers for the FreeBSD apply layer — unit-testable
//! on any host OS.
#![allow(dead_code)]

/// Rewrite (or append) the `127.0.1.1` line in `/etc/hosts` to reflect
/// the new hostname + domain. Matches only lines whose first
/// whitespace-separated token is exactly `127.0.1.1` — avoids
/// false-positives on 127.0.1.10, 127.0.1.100, etc.
pub fn rewrite_hosts_loopback(existing: &str, hostname: &str, domain: &str) -> String {
    let fqdn_line = if domain.is_empty() {
        hostname.to_string()
    } else {
        format!("{}.{} {}", hostname, domain, hostname)
    };
    let want = format!("127.0.1.1\t{}", fqdn_line);
    let mut out = String::with_capacity(existing.len() + want.len() + 1);
    let mut replaced = false;
    for line in existing.lines() {
        if line.split_whitespace().next() == Some("127.0.1.1") {
            out.push_str(&want);
            out.push('\n');
            replaced = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !replaced {
        out.push_str(&want);
        out.push('\n');
    }
    out
}

/// Rewrite the `search` / `domain` lines in `/etc/resolv.conf` to
/// reflect the new domain. Drops any existing `search` or `domain`
/// lines; if the new domain is non-empty, prepends a single
/// `search <domain>` line.
pub fn rewrite_resolv_conf_search(existing: &str, domain: &str) -> String {
    let mut out = String::with_capacity(existing.len() + 32);
    let mut wrote_search = false;
    for line in existing.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("search ") || trimmed.starts_with("domain ") {
            if !domain.is_empty() && !wrote_search {
                out.push_str(&format!("search {}\n", domain));
                wrote_search = true;
            }
            // else: drop this line
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !domain.is_empty() && !wrote_search {
        let body = out;
        out = format!("search {}\n{}", domain, body);
    }
    out
}
