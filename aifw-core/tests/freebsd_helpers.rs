use aifw_core::system_apply::freebsd_helpers::{
    rewrite_hosts_loopback, rewrite_resolv_conf_search,
};

#[test]
fn hosts_loopback_replaces_exact_match() {
    let input = "127.0.0.1\tlocalhost\n127.0.1.1\told.example old\n::1\tlocalhost\n";
    let out = rewrite_hosts_loopback(input, "newhost", "example.com");
    assert!(out.contains("127.0.1.1\tnewhost.example.com newhost"));
    assert!(!out.contains("old.example old"));
    assert!(out.contains("127.0.0.1\tlocalhost"));
    assert!(out.contains("::1\tlocalhost"));
}

#[test]
fn hosts_loopback_does_not_match_127_0_1_100() {
    let input = "127.0.1.100\tsomething\n";
    let out = rewrite_hosts_loopback(input, "newhost", "");
    // The 127.0.1.100 line must be preserved
    assert!(out.contains("127.0.1.100\tsomething"));
    // And a new 127.0.1.1 line appended
    assert!(out.contains("127.0.1.1\tnewhost"));
}

#[test]
fn hosts_loopback_appends_when_missing() {
    let out = rewrite_hosts_loopback("127.0.0.1\tlocalhost\n", "fw", "lan");
    assert!(out.contains("127.0.0.1\tlocalhost"));
    assert!(out.contains("127.0.1.1\tfw.lan fw"));
}

#[test]
fn hosts_loopback_empty_domain() {
    let out = rewrite_hosts_loopback("", "fw", "");
    assert!(out.contains("127.0.1.1\tfw"));
    assert!(!out.contains("127.0.1.1\tfw."));
}

#[test]
fn resolv_conf_search_adds_when_absent() {
    let input = "nameserver 1.1.1.1\nnameserver 8.8.8.8\n";
    let out = rewrite_resolv_conf_search(input, "home.lan");
    assert!(out.starts_with("search home.lan\n"));
    assert!(out.contains("nameserver 1.1.1.1"));
    assert!(out.contains("nameserver 8.8.8.8"));
}

#[test]
fn resolv_conf_search_replaces_existing_search() {
    let input = "search old.example\nnameserver 1.1.1.1\n";
    let out = rewrite_resolv_conf_search(input, "new.example");
    assert!(out.contains("search new.example"));
    assert!(!out.contains("old.example"));
    assert!(out.contains("nameserver 1.1.1.1"));
}

#[test]
fn resolv_conf_search_replaces_existing_domain_directive() {
    let input = "domain old.example\nnameserver 1.1.1.1\n";
    let out = rewrite_resolv_conf_search(input, "new.example");
    assert!(out.contains("search new.example"));
    assert!(!out.contains("domain old.example"));
}

#[test]
fn resolv_conf_search_empty_domain_drops_existing() {
    let input = "search old.example\nnameserver 1.1.1.1\n";
    let out = rewrite_resolv_conf_search(input, "");
    assert!(!out.contains("old.example"));
    assert!(!out.contains("search"));
    assert!(out.contains("nameserver 1.1.1.1"));
}
