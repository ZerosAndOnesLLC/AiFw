//! Cluster, multi-WAN, reverse proxy, DHCP and update commands.

use super::cli_harness::Cli;
use super::*;

/// `cluster verify --json` is parsed by scripts/ha-verify.sh: one JSON
/// document on stdout with `ok`, `failures` and `status`, non-zero exit on
/// any failure. Off FreeBSD the kernel checks always fail, which makes the
/// failure path testable here.
#[tokio::test]
async fn cluster_verify_json_contract() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let r = cli.run(&["cluster", "verify", "--json"]).await;
    assert_ne!(r.code, 0, "kernel checks can't pass off FreeBSD");
    let v: Value = serde_json::from_str(&r.out).expect("stdout is exactly one JSON document");
    assert_eq!(v["ok"], false);
    assert!(
        v["failures"].as_array().unwrap().iter().any(|f| f
            .as_str()
            .unwrap()
            .contains("not running on FreeBSD")
            || f.as_str().unwrap().contains("CARP"))
    );
    assert!(
        v["status"].is_object(),
        "API status included: {}",
        v["status"]
    );
    // Text mode reports FAIL lines on stderr.
    let t = cli.run(&["cluster", "verify"]).await;
    assert_ne!(t.code, 0);
    assert!(t.err.contains("FAIL:"));
}

#[tokio::test]
async fn cluster_objects() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let s = cli.run(&["cluster", "status"]).await;
    s.ok();
    assert!(s.out.contains("Role:"), "{}", s.out);
    assert!(
        cli.run(&["cluster", "status", "--json"])
            .await
            .json()
            .get("role")
            .is_some()
    );

    cli.run_stdin(
        &[
            "cluster",
            "carp",
            "add",
            "--vhid",
            "7",
            "--interface",
            "em0",
            "--vip",
            "192.0.2.1/24",
            "--password-stdin",
        ],
        "s3cret\n",
    )
    .await
    .ok();
    let l = cli.run(&["cluster", "carp", "list"]).await;
    assert!(l.out.contains("192.0.2.1/24"), "{}", l.out);
    cli.run(&[
        "cluster",
        "carp",
        "add",
        "--vhid",
        "8",
        "--interface",
        "em0",
        "--vip",
        "192.0.2.2",
        "--password",
        "x",
    ])
    .await
    .code(2);
    let id = cli
        .run(&["cluster", "carp", "list", "-o", "json"])
        .await
        .json()[0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    cli.run(&["cluster", "carp", "rm", &id, "--yes"]).await.ok();

    cli.run(&[
        "cluster",
        "nodes",
        "add",
        "--name",
        "peer",
        "--address",
        "192.0.2.9",
    ])
    .await
    .ok();
    let nid = cli
        .run(&["cluster", "nodes", "list", "-o", "json"])
        .await
        .json()[0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    let fp = "ab".repeat(32);
    let rp = cli
        .run(&["cluster", "nodes", "repin", &nid, "--fingerprint", &fp])
        .await;
    rp.ok();
    assert!(rp.out.contains(&fp), "{}", rp.out);
    cli.run(&["cluster", "nodes", "repin", &nid, "--fingerprint", "zz"])
        .await
        .code(2);
    cli.run(&["cluster", "nodes", "rm", &nid, "--yes"])
        .await
        .ok();

    cli.run(&[
        "cluster",
        "health",
        "add",
        "--name",
        "gw",
        "--check-type",
        "pf_status",
        "--target",
        "local",
    ])
    .await
    .ok();
    assert!(
        cli.run(&["cluster", "health", "ls"])
            .await
            .out
            .contains("pf_status")
    );
    cli.run(&["cluster", "maintenance", "sideways"])
        .await
        .code(2);
}

#[tokio::test]
async fn multiwan_lists_and_import_export() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    for sub in [
        "instances",
        "gateways",
        "groups",
        "policies",
        "leaks",
        "fib-info",
    ] {
        cli.run(&["multiwan", sub]).await.ok();
    }
    // (Creating an instance needs a spare FIB, which a dev host lacks.)
    let export = cli.run(&["multiwan", "export"]).await;
    export.ok();
    let cfg: Value = serde_json::from_str(&export.out).unwrap();
    for k in ["instances", "gateways", "groups", "policies", "leaks"] {
        assert!(cfg[k].is_array(), "{k} in {cfg}");
    }
    // A partial file (missing sections) is accepted.
    let f = cli.dir.join("mw.yaml");
    std::fs::write(&f, "instances: []\n").unwrap();
    cli.run(&["multiwan", "import", f.to_str().unwrap()])
        .await
        .ok();
}

#[tokio::test]
async fn reverse_proxy_collections() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let f = cli.dir.join("ep.json");
    std::fs::write(&f, r#"{"name":"web","address":":8443"}"#).unwrap();
    cli.run(&[
        "reverse-proxy",
        "entrypoints",
        "add",
        "-f",
        f.to_str().unwrap(),
    ])
    .await
    .ok();
    let l = cli.run(&["reverse-proxy", "entrypoints"]).await;
    l.ok();
    assert!(
        l.out.contains("web") && l.out.contains(":8443"),
        "{}",
        l.out
    );
    // Legacy --json list still works.
    let j = cli
        .run(&["reverse-proxy", "entrypoints", "--json"])
        .await
        .json();
    assert_eq!(j[0]["name"], "web");

    let patch = cli.dir.join("patch.json");
    std::fs::write(&patch, r#"{"address":":9443"}"#).unwrap();
    cli.run(&[
        "reverse-proxy",
        "entrypoints",
        "edit",
        "web",
        "-f",
        patch.to_str().unwrap(),
    ])
    .await
    .ok();
    assert_eq!(
        cli.run(&["reverse-proxy", "entrypoints", "show", "web", "-o", "json"])
            .await
            .json()["address"],
        ":9443"
    );
    cli.run(&["reverse-proxy", "entrypoints", "disable", "web"])
        .await
        .ok();
    assert_eq!(
        cli.run(&["reverse-proxy", "entrypoints", "show", "web", "-o", "json"])
            .await
            .json()["enabled"],
        false
    );
    cli.run(&["reverse-proxy", "entrypoints", "rm", "web", "--yes"])
        .await
        .ok();
    cli.run(&["reverse-proxy", "entrypoints", "show", "web"])
        .await
        .code(5);
    cli.run(&["reverse-proxy", "status"]).await.ok();
    cli.run(&["reverse-proxy", "config", "-o", "json"])
        .await
        .ok();
}

#[tokio::test]
async fn dhcp_subnets_reservations_and_soft_failures() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    cli.run(&[
        "dhcp",
        "subnet-add",
        "--network",
        "192.168.50.0/24",
        "--pool-start",
        "192.168.50.100",
        "--pool-end",
        "192.168.50.200",
        "--gateway",
        "192.168.50.1",
        "--dns",
        "1.1.1.1,9.9.9.9",
    ])
    .await
    .ok();
    let subs = cli.run(&["dhcp", "subnets", "--json"]).await.json();
    assert!(subs[0].get("dns_servers").is_none(), "legacy 6-key shape");
    let sid = subs[0]["id"].as_str().unwrap().to_string();
    cli.run(&["dhcp", "subnet-edit", &sid, "--lease-time", "7200"])
        .await
        .ok();
    let s = &cli.run(&["dhcp", "subnets", "-o", "json"]).await.json()["data"][0];
    assert_eq!(s["lease_time"], 7200);
    assert!(
        s["dns_servers"].as_str().unwrap().contains("9.9.9.9"),
        "kept: {s}"
    );

    cli.run(&[
        "dhcp",
        "reservation-add",
        "--mac",
        "aa:bb:cc:dd:ee:ff",
        "--ip",
        "192.168.50.10",
        "--hostname",
        "printer",
    ])
    .await
    .ok();
    assert!(
        cli.run(&["dhcp", "reservations"])
            .await
            .out
            .contains("printer")
    );
    let legacy = cli.run(&["dhcp", "reservations", "--json"]).await.json();
    assert_eq!(legacy[0]["mac"], "aa:bb:cc:dd:ee:ff", "legacy keys");
    let rid = legacy[0]["id"].to_string().trim_matches('"').to_string();
    cli.run(&["dhcp", "reservation-remove", &rid, "--yes"])
        .await
        .ok();
    cli.run(&["dhcp", "subnet-remove", &sid, "--yes"])
        .await
        .ok();

    // Starting the service can't work here; the API answers 200 with a
    // failure message, which must become a non-zero exit.
    let st = cli.run(&["dhcp", "start"]).await;
    if !st.out.to_ascii_lowercase().contains("started") {
        assert_ne!(st.code, 0, "soft failure must fail: {}", st.out);
    }
}

#[tokio::test]
async fn update_commands_offline() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    cli.run(&["update", "prerelease", "on"]).await.ok();
    cli.run(&["update", "prerelease", "off"]).await.ok();
    cli.run(&["update", "os-upgrade"]).await.ok();
    cli.run(&[
        "update",
        "install",
        "--from",
        "/nonexistent/aifw.tar.xz",
        "--yes",
    ])
    .await
    .code(2);
    cli.run(&["update", "install", "--from", "/etc/hostname", "--yes"])
        .await
        .code(2);
    cli.run(&["update", "install", "--skip-checksum"])
        .await
        .code(2);
    // --from without --yes asks first; EOF declines, which isn't an error.
    let tarball = cli.dir.join("aifw-test.tar.xz");
    std::fs::write(&tarball, b"not really").unwrap();
    let r = cli
        .run(&["update", "install", "--from", tarball.to_str().unwrap()])
        .await;
    r.ok();
    assert!(r.out.contains("Aborted."));
}
