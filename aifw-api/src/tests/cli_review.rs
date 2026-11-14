//! Regression tests for the PR #714 review findings (CLI side).

use super::cli_harness::Cli;
use super::*;

fn write(cli: &Cli, name: &str, text: &str) -> String {
    let p = cli.dir.join(name);
    std::fs::write(&p, text).unwrap();
    p.to_str().unwrap().to_string()
}

/// H2: --disabled creates a disabled rule / NAT rule.
#[tokio::test]
async fn disabled_on_create() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let r = cli
        .run(&[
            "rules",
            "add",
            "--action",
            "pass",
            "--disabled",
            "-o",
            "json",
        ])
        .await
        .json();
    assert_eq!(r["data"]["status"], "disabled");
    let n = cli
        .run(&[
            "nat",
            "add",
            "--type",
            "masquerade",
            "--interface",
            "em0",
            "--disabled",
            "-o",
            "json",
        ])
        .await
        .json();
    assert_eq!(n["data"]["status"], "disabled");
}

/// H3: editing a subnet that inherits the global DNS keeps it inherited;
/// per-subnet NTP survives an edit.
#[tokio::test]
async fn dhcp_subnet_edit_round_trips() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let f = write(
        &cli,
        "s.json",
        r#"{"network":"192.168.60.0/24","pool_start":"192.168.60.10","pool_end":"192.168.60.99","gateway":"192.168.60.1","ntp_servers":["192.168.60.1"]}"#,
    );
    cli.run(&[
        "dhcp",
        "subnet-add",
        "--network",
        "x",
        "--pool-start",
        "x",
        "--pool-end",
        "x",
        "--gateway",
        "x",
        "-f",
        &f,
    ])
    .await
    .code(6); // flags win over the file, and "x" isn't a network
    let token = cli.admin_token().await;
    let body: Value = serde_json::from_str(&std::fs::read_to_string(&f).unwrap()).unwrap();
    let resp = cli
        .http()
        .post(cli.url("/dhcp/v4/subnets"))
        .bearer_auth(&token)
        .json(&body)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());
    let sid = cli.run(&["dhcp", "subnets", "-o", "json"]).await.json()["data"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();

    cli.run(&["dhcp", "subnet-edit", &sid, "--lease-time", "7200"])
        .await
        .ok();
    let s = cli.run(&["dhcp", "subnets", "-o", "json"]).await.json()["data"][0].clone();
    assert_eq!(s["lease_time"], 7200);
    assert!(
        s["dns_servers"].is_null(),
        "still inherits the global DNS: {s}"
    );
    assert_eq!(s["ntp_servers"], "192.168.60.1");
}

/// H4 + unknown keys: pf-tuning takes exactly max_states; patch sections
/// refuse keys the API would ignore.
#[tokio::test]
async fn settings_pf_tuning_and_unknown_keys() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    cli.run(&[
        "settings",
        "set",
        "pf-tuning",
        "configured_max_states=200000",
    ])
    .await
    .code(2);
    // Off FreeBSD the API stores the limit but can't write pf.conf.aifw
    // (and says so); what matters is the value sent, not 4,000,000.
    let r = cli
        .run(&["settings", "set", "pf-tuning", "max_states=200000"])
        .await;
    assert!(r.code == 0 || r.err.contains("stored in DB"), "{}", r.err);
    assert_eq!(
        cli.run(&["settings", "get", "pf-tuning"]).await.json()["configured_max_states"],
        200000
    );
    let e = cli
        .run(&["settings", "set", "tls", "min_versoin=tls13"])
        .await;
    e.code(2);
    assert!(
        e.err.contains("min_version"),
        "lists the known keys: {}",
        e.err
    );
}

/// M8: --from … --restart is non-interactive, as before.
#[tokio::test]
async fn install_from_with_restart_does_not_prompt() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let tarball = cli.dir.join("aifw.tar.xz");
    std::fs::write(&tarball, b"x").unwrap();
    let r = cli
        .run(&[
            "update",
            "install",
            "--from",
            tarball.to_str().unwrap(),
            "--skip-checksum",
            "--restart",
        ])
        .await;
    assert!(
        !r.out.contains("Aborted") && !r.err.contains("Proceed?"),
        "{} {}",
        r.out,
        r.err
    );
    assert!(r.out.contains("Uploading"), "{}", r.out);
}

/// M10, M11, M12.
#[tokio::test]
async fn preview_syslog_test_and_diff() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let f = write(&cli, "pol.json", "[]");
    cli.run(&["multiwan", "preview", "-f", &f]).await.ok();

    let t = cli.run(&["syslog", "test"]).await;
    assert!(!t.err.contains("missing field"), "{}", t.err);
    assert_ne!(t.code, 6);

    cli.run(&["config", "save"]).await.ok();
    cli.run(&["rules", "add", "--action", "pass"]).await.ok();
    cli.run(&["config", "save"]).await.ok();
    let h = cli.run(&["config", "history", "-o", "json"]).await.json();
    let (v2, v1) = (
        h["data"][0]["version"].to_string(),
        h["data"][1]["version"].to_string(),
    );
    let d = cli.run(&["config", "diff", &v1, &v2]).await;
    d.ok();
    assert!(!d.out.contains("null"), "{}", d.out);
    assert!(d.out.contains("rules: 0 → 1 (+1 −0)"), "{}", d.out);
}

/// M13: the peer config is a WireGuard config, full or split tunnel.
#[tokio::test]
async fn wireguard_peer_config_is_a_config() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let t = cli
        .run(&[
            "vpn",
            "wg",
            "add",
            "--name",
            "r",
            "--address",
            "10.9.0.1/24",
            "-o",
            "json",
        ])
        .await
        .json();
    let tid = t["data"]["id"].as_str().unwrap().to_string();
    let p = cli
        .run(&[
            "vpn",
            "wg",
            "peers",
            "add",
            &tid,
            "--name",
            "l",
            "--generate-key",
            "-o",
            "json",
        ])
        .await
        .json();
    let pid = p["data"]["id"].as_str().unwrap().to_string();
    let full = cli.run(&["vpn", "wg", "peers", "config", &tid, &pid]).await;
    full.ok();
    assert!(full.out.starts_with("[Interface]"), "{}", full.out);
    assert!(
        full.out.contains("0.0.0.0/0"),
        "full tunnel routes everything"
    );
    let split = cli
        .run(&["vpn", "wg", "peers", "config", &tid, &pid, "--split"])
        .await;
    assert!(!split.out.contains("0.0.0.0/0"), "{}", split.out);
}

/// M14, M16: unsupported generic verbs and no-op flags are refused.
#[tokio::test]
async fn unsupported_verbs_are_refused() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let f = write(
        &cli,
        "acl.json",
        r#"{"network":"10.0.0.0/8","action":"allow"}"#,
    );
    cli.run(&["dns", "acls", "add", "-f", &f]).await.ok();
    let id = cli.run(&["dns", "acls", "list", "-o", "json"]).await.json()["data"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    cli.run(&["dns", "acls", "edit", &id, "-f", &f])
        .await
        .code(2);
    cli.run(&["dns", "acls", "disable", &id]).await.code(2);
    cli.run(&["reverse-proxy", "tls-certs", "enable", "x"])
        .await
        .code(2);
    cli.run(&[
        "interfaces",
        "configure",
        "em0",
        "--ipv4-address",
        "10.0.0.1/24",
        "--yes",
    ])
    .await
    .code(2);
}

/// M15: a failure reported in a 200 response still fails the command.
#[tokio::test]
async fn soft_failures_exit_non_zero() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let r = cli.run(&["dhcp", "release", "10.250.0.9", "--yes"]).await;
    if r.out.contains("Failed") {
        assert_ne!(r.code, 0);
    }
}

/// M17 + small fixes: verify reports its scope; history, logs, hostname.
#[tokio::test]
async fn verify_scope_and_small_fixes() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let v: Value =
        serde_json::from_str(&cli.run(&["cluster", "verify", "--json"]).await.out).unwrap();
    assert_eq!(v["scope"], "local", "127.0.0.1 is this machine");
    cli.run(&["update", "history"]).await.ok();
    cli.run(&["dns", "logs", "--lines", "5"]).await.ok();
    cli.run(&["syslog", "set", "--hostname", "fw1"]).await.ok();
    cli.run(&["syslog", "set", "--hostname", ""]).await.ok();
    assert_eq!(
        cli.run(&["syslog", "show", "-o", "json"]).await.json()["hostname_override"],
        ""
    );
}
