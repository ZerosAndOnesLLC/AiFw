//! VPN, IDS, plugins, syslog and log rotation through the CLI.

use super::cli_harness::Cli;
use super::*;

#[tokio::test]
async fn wireguard_tunnels_and_peers() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let r = cli
        .run(&[
            "vpn",
            "wg",
            "add",
            "--name",
            "road",
            "--address",
            "10.8.0.1/24",
            "-o",
            "json",
        ])
        .await;
    r.ok();
    let t = &r.json()["data"];
    let tid = t["id"].as_str().unwrap().to_string();
    assert!(t["interface"].as_str().unwrap().starts_with("wg"));
    assert_ne!(t["private_key"], json!(null).to_string().as_str());

    let l = cli.run(&["vpn", "wg", "ls"]).await;
    assert!(
        l.out.contains("road") && l.out.contains("10.8.0.1/24"),
        "{}",
        l.out
    );
    cli.run(&["vpn", "wg", "edit", &tid, "--mtu", "1380"])
        .await
        .ok();
    let all = cli.run(&["vpn", "wg", "list", "-o", "json"]).await.json();
    assert_eq!(all["data"][0]["mtu"], 1380);
    assert_eq!(all["data"][0]["name"], "road", "kept");

    // Peer with a generated key and an auto-assigned address.
    let p = cli
        .run(&[
            "vpn",
            "wg",
            "peers",
            "add",
            &tid,
            "--name",
            "laptop",
            "--generate-key",
            "-o",
            "json",
        ])
        .await;
    p.ok();
    let pid = p.json()["data"]["id"].as_str().unwrap().to_string();
    let peers = cli.run(&["vpn", "wg", "peers", "list", &tid]).await;
    assert!(peers.out.contains("laptop"), "{}", peers.out);
    let conf = cli.dir.join("laptop.conf");
    cli.run(&[
        "vpn",
        "wg",
        "peers",
        "config",
        &tid,
        &pid,
        "-O",
        conf.to_str().unwrap(),
    ])
    .await
    .ok();
    let text = std::fs::read_to_string(&conf).unwrap();
    assert!(
        text.contains("[Interface]") && text.contains("[Peer]"),
        "{text}"
    );
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&conf).unwrap().permissions().mode() & 0o777,
        0o600
    );
    cli.run(&[
        "vpn",
        "wg",
        "peers",
        "edit",
        &tid,
        &pid,
        "--keepalive",
        "25",
    ])
    .await
    .ok();
    cli.run(&["vpn", "wg", "peers", "edit", &tid, &pid])
        .await
        .code(2);

    // Legacy spelling still works.
    cli.run(&[
        "vpn",
        "wg-peer-add",
        "--tunnel",
        &tid,
        "--name",
        "old",
        "--pubkey",
        "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=",
    ])
    .await
    .ok();
    let everything = cli.run(&["vpn", "list", "--json"]).await.json();
    assert_eq!(
        everything["wireguard"][0]["peers"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    // Generic remove finds the peer.
    cli.run(&["vpn", "rm", &pid, "--yes"]).await.ok();
    cli.run(&["vpn", "wg", "rm", &tid, "--yes"]).await.ok();
    cli.run(&["vpn", "rm", &tid, "--yes"]).await.code(5);
}

#[tokio::test]
async fn ipsec_tunnels() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let r = cli
        .run_stdin(
            &[
                "vpn",
                "ipsec",
                "add",
                "--name",
                "branch",
                "--remote",
                "198.51.100.7",
                "--local-ts",
                "10.0.0.0/24",
                "--remote-ts",
                "10.1.0.0/24",
                "--psk-stdin",
                "-o",
                "json",
            ],
            "a-long-shared-secret-123\n",
        )
        .await;
    r.ok();
    let id = r.json()["data"]["id"].as_str().unwrap().to_string();
    let l = cli.run(&["vpn", "ipsec", "ls"]).await;
    assert!(
        l.out.contains("branch") && l.out.contains("198.51.100.7"),
        "{}",
        l.out
    );
    let shown = cli.run(&["vpn", "ipsec", "show", &id]).await;
    assert!(
        !shown.out.contains("a-long-shared-secret"),
        "secret never shown"
    );
    // Edit keeps the stored PSK (sent back as the redaction marker).
    cli.run(&[
        "vpn",
        "ipsec",
        "edit",
        &id,
        "--remote-ts",
        "10.1.0.0/24,10.2.0.0/24",
    ])
    .await
    .ok();
    let v = cli
        .run(&["vpn", "ipsec", "show", &id, "-o", "json"])
        .await
        .json();
    assert_eq!(v["remote_ts"].as_array().unwrap().len(), 2);
    // Required fields.
    cli.run(&["vpn", "ipsec", "add", "--name", "x"])
        .await
        .code(2);
    cli.run(&["vpn", "ipsec", "rm", &id, "--yes"]).await.ok();
}

#[tokio::test]
async fn ids_alerts_suppressions_and_retention() {
    let cli = Cli::start().await;
    // The aifw-ids service owns these tables in production.
    aifw_ids::IdsEngine::migrate(&cli.pool).await.unwrap();
    cli.login_admin().await;
    let a = cli.run(&["ids", "alerts", "list"]).await;
    a.ok();
    cli.run(&["ids", "retention", "0"]).await.code(2);
    cli.run(&["ids", "retention", "400"]).await.code(2);
    cli.run(&[
        "ids",
        "suppressions",
        "add",
        "--sid",
        "2100498",
        "--type",
        "src",
        "--ip",
        "192.0.2.0/24",
    ])
    .await
    .ok();
    cli.run(&[
        "ids",
        "suppressions",
        "add",
        "--sid",
        "1",
        "--type",
        "everywhere",
    ])
    .await
    .code(2);
    let s = cli
        .run(&["ids", "suppressions", "list", "-o", "json"])
        .await
        .json();
    let sid = s["data"][0]["id"].to_string().trim_matches('"').to_string();
    let sl = cli.run(&["ids", "suppressions", "ls"]).await;
    assert!(
        sl.out.contains("2100498"),
        "out={} err={} json={s}",
        sl.out,
        sl.err
    );
    cli.run(&["ids", "suppressions", "rm", &sid, "--yes"])
        .await
        .ok();
    // Purge needs confirmation.
    cli.run(&["ids", "purge-alerts"]).await.code(1);
    cli.run(&["ids", "purge-alerts", "--yes"]).await.ok();
}

#[tokio::test]
async fn plugins_settings_lifecycle() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let l = cli.run(&["plugins", "list"]).await;
    l.ok();
    assert!(
        l.out.contains("threat-feeds") && l.out.contains("notifier"),
        "{}",
        l.out
    );

    let s = cli.run(&["plugins", "show", "threat-feeds"]).await;
    s.ok();
    assert!(s.out.contains("refresh_hours"), "{}", s.out);

    cli.run(&["plugins", "set", "threat-feeds", "refresh_hours=6"])
        .await
        .ok();
    let d = cli
        .run(&["plugins", "show", "threat-feeds", "--json"])
        .await
        .json();
    assert_eq!(d["values"]["refresh_hours"], 6);
    // Out of range → server validation; unknown key and bad type → usage.
    cli.run(&["plugins", "set", "threat-feeds", "refresh_hours=100000"])
        .await
        .code(6);
    cli.run(&["plugins", "set", "threat-feeds", "nope=1"])
        .await
        .code(2);
    cli.run(&["plugins", "set", "threat-feeds", "refresh_hours=six"])
        .await
        .code(2);
    cli.run(&["plugins", "set", "threat-feeds"]).await.code(2);
    cli.run(&["plugins", "set", "threat-feeds", "--unset", "refresh_hours"])
        .await
        .ok();
    let d = cli
        .run(&["plugins", "show", "threat-feeds", "-o", "json"])
        .await
        .json();
    assert!(d["values"].get("refresh_hours").is_none());

    // A secret goes through stdin and is only ever reported as set.
    cli.run_stdin(
        &["plugins", "set", "notifier", "--secret-stdin", "ntfy_url"],
        "https://ntfy.sh/topic\n",
    )
    .await
    .ok();
    let n = cli.run(&["plugins", "show", "notifier"]).await;
    assert!(
        n.out.contains("(set)") && !n.out.contains("ntfy.sh/topic"),
        "{}",
        n.out
    );
    cli.run(&["plugins", "set", "notifier", "ntfy_url=https://x"])
        .await
        .code(2);

    cli.run(&["plugins", "enable", "threat-feeds"]).await.ok();
    let st = cli
        .run(&["plugins", "status", "threat-feeds", "--json"])
        .await
        .json();
    assert_eq!(st[0]["plugin"]["enabled"], true);
    cli.run(&["plugins", "logs", "threat-feeds"]).await.ok();
    cli.run(&["plugins", "run", "threat-feeds", "bogus-action"])
        .await
        .code(2);
    cli.run(&["plugins", "disable", "threat-feeds"]).await.ok();
    cli.run(&["plugins", "reset", "notifier", "--yes"])
        .await
        .ok();
    cli.run(&["plugins", "show", "no-such-plugin"])
        .await
        .code(5);
}

#[tokio::test]
async fn syslog_and_logrotate() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    // Can't enable without a server.
    let e = cli.run(&["syslog", "enable"]).await;
    e.code(2);
    assert!(e.err.contains("aifw syslog set --host"));

    cli.run(&[
        "syslog",
        "set",
        "--host",
        "192.0.2.10",
        "--port",
        "5514",
        "--format",
        "bsd",
        "--facility",
        "local3",
        "--pf",
        "true",
    ])
    .await
    .ok();
    let cfg = cli.run(&["syslog", "show", "--json"]).await.json();
    assert_eq!(cfg["host"], "192.0.2.10");
    assert_eq!(cfg["format"], "rfc3164");
    assert_eq!(cfg["facility"], 19);
    assert_eq!(cfg["pf_enabled"], true);
    let shown = cli.run(&["syslog", "show"]).await;
    assert!(shown.out.contains("local3"), "{}", shown.out);
    cli.run(&["syslog", "enable"]).await.ok();
    assert_eq!(
        cli.run(&["syslog", "show", "-o", "json"]).await.json()["enabled"],
        true
    );
    cli.run(&["syslog", "set", "--facility", "nonsense"])
        .await
        .code(2);
    cli.run(&["syslog", "set"]).await.code(2);
    cli.run(&["syslog", "disable"]).await.ok();

    let lr = cli.run(&["logrotate", "show"]).await;
    lr.ok();
    assert!(lr.out.contains("Rotate at"), "{}", lr.out);
    cli.run(&[
        "logrotate",
        "set",
        "--max-size",
        "20",
        "--keep",
        "5",
        "--compression",
        "zstd",
    ])
    .await
    .ok();
    let v = cli.run(&["logrotate", "show", "--json"]).await.json();
    assert_eq!(v["config"]["max_size_mb"], 20);
    assert_eq!(v["config"]["compression"], "zstd");
    cli.run(&["logrotate", "set"]).await.code(2);
    cli.run(&["logrotate", "set", "--max-size", "99999"])
        .await
        .code(6);
}

/// Suppressions stored with the column default timestamp
/// (`datetime('now')`, e.g. restored from a backup) must still be listed.
#[tokio::test]
async fn suppressions_with_sqlite_default_timestamps_are_listed() {
    let cli = Cli::start().await;
    aifw_ids::IdsEngine::migrate(&cli.pool).await.unwrap();
    sqlx::query("INSERT INTO ids_suppressions (id, sid, suppress_type, ip_cidr) VALUES (?, 42, 'both', NULL)")
        .bind(uuid::Uuid::new_v4().to_string())
        .execute(&cli.pool)
        .await
        .unwrap();
    cli.login_admin().await;
    let v = cli
        .run(&["ids", "suppressions", "list", "-o", "json"])
        .await
        .json();
    assert_eq!(v["data"][0]["sid"], 42);
}
