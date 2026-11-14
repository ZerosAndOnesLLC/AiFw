//! `aifw rules …` through the API.

use super::cli_harness::Cli;
use super::*;

async fn add(cli: &Cli, args: &[&str]) -> String {
    let mut a = vec!["rules", "add", "-o", "json"];
    a.extend_from_slice(args);
    let r = cli.run(&a).await;
    r.ok();
    r.json()["data"]["id"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn add_list_show_edit_remove() {
    let cli = Cli::start().await;
    cli.login_admin().await;

    let r = cli
        .run(&[
            "rules",
            "add",
            "--action",
            "pass",
            "--direction",
            "in",
            "--proto",
            "tcp",
            "--dst",
            "10.0.0.5",
            "--dst-port",
            "443",
            "--interface",
            "em0",
            "--label",
            "web",
            "--log",
        ])
        .await;
    r.ok();
    assert!(r.out.starts_with("Added rule "), "{}", r.out);
    assert!(r.err.contains("aifw apply"), "staged hint: {}", r.err);
    let id = r.out.trim().trim_start_matches("Added rule ").to_string();

    let l = cli.run(&["rules", "list"]).await;
    l.ok();
    for want in [
        "ACTION",
        "DESTINATION",
        "pass",
        "10.0.0.5:443",
        "em0",
        "web",
    ] {
        assert!(l.out.contains(want), "missing {want}:\n{}", l.out);
    }
    let wide = cli.run(&["rules", "ls", "-o", "wide"]).await;
    assert!(wide.out.contains("QUICK"));

    // Legacy --json still works for scripts.
    let j = cli.run(&["rules", "list", "--json"]).await.json();
    assert_eq!(j[0]["id"], id, "bare array, as before");
    assert_eq!(j[0]["log"], true);

    let s = cli.run(&["rules", "show", &id]).await;
    s.ok();
    assert!(s.out.contains("Interface:") && s.out.contains("em0"));

    // Edit one field; everything else (interface, ports, label) survives.
    cli.run(&[
        "rules",
        "edit",
        &id,
        "--action",
        "block-drop",
        "--priority",
        "5",
    ])
    .await
    .ok();
    let v = cli.run(&["rules", "show", &id, "-o", "json"]).await.json();
    let rule = &v["data"];
    assert_eq!(rule["action"], "blockdrop");
    assert_eq!(rule["priority"], 5);
    assert_eq!(rule["interface"], "em0");
    assert_eq!(rule["label"], "web");
    assert_eq!(rule["rule_match"]["dst_port"]["start"], 443);
    assert_eq!(rule["log"], true);

    cli.run(&["rules", "edit", &id]).await.code(2);

    cli.run(&["rules", "disable", &id]).await.ok();
    assert_eq!(
        cli.run(&["rules", "show", &id, "-o", "json"]).await.json()["data"]["status"],
        "disabled"
    );
    cli.run(&["rules", "enable", &id]).await.ok();
    assert_eq!(
        cli.run(&["rules", "show", &id, "-o", "json"]).await.json()["data"]["status"],
        "active"
    );

    // Removal prompts; EOF declines.
    cli.run(&["rules", "rm", &id]).await.code(1);
    cli.run(&["rules", "remove", &id, "--yes"]).await.ok();
    cli.run(&["rules", "show", &id]).await.code(5);
    let empty = cli.run(&["rules", "list"]).await;
    empty.ok();
    assert!(empty.err.contains("No results"));
}

#[tokio::test]
async fn add_from_file_and_defaults() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let file = cli.dir.join("rule.yaml");
    std::fs::write(
        &file,
        "action: block\nprotocol: udp\ndst_addr: 192.0.2.0/24\nlabel: from-file\n",
    )
    .unwrap();
    let id = add(
        &cli,
        &["-f", file.to_str().unwrap(), "--label", "flag-wins"],
    )
    .await;
    let v = cli.run(&["rules", "show", &id, "-o", "json"]).await.json();
    assert_eq!(v["data"]["protocol"], "udp");
    assert_eq!(v["data"]["label"], "flag-wins");
    assert_eq!(v["data"]["direction"], "any", "legacy default");
    assert_eq!(v["data"]["priority"], 100, "legacy default");

    // From stdin.
    let r = cli
        .run_stdin(
            &["rules", "add", "-f", "-", "-o", "json"],
            r#"{"action":"pass","protocol":"icmp"}"#,
        )
        .await;
    r.ok();
    assert_eq!(r.json()["data"]["protocol"], "icmp");
}

#[tokio::test]
async fn validation_usage_and_permission_errors() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    cli.run(&["rules", "add"]).await.code(2);
    cli.run(&["rules", "add", "--action", "deny"]).await.code(2);
    cli.run(&["rules", "add", "--action", "pass", "--dst-port", "99999"])
        .await
        .code(2);
    cli.run(&[
        "rules",
        "add",
        "--action",
        "pass",
        "--src",
        "not-an-address",
    ])
    .await
    .code(6);
    cli.run(&["rules", "show", "00000000-0000-0000-0000-000000000000"])
        .await
        .code(5);

    let key = cli
        .mint_key(json!({ "name": "ro", "role_id": "builtin-viewer" }))
        .await;
    cli.run(&["--url", &cli.base, "--api-key", &key, "rules", "list"])
        .await
        .ok();
    cli.run(&[
        "--url",
        &cli.base,
        "--api-key",
        &key,
        "rules",
        "add",
        "--action",
        "pass",
    ])
    .await
    .code(4);
}

#[tokio::test]
async fn reorder_block_logging_and_pending() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let a = add(&cli, &["--action", "pass", "--label", "a"]).await;
    let b = add(&cli, &["--action", "block", "--label", "b"]).await;
    assert_eq!(
        cli.run(&["pending", "-o", "json"]).await.json()["firewall"],
        true
    );

    cli.run(&["rules", "reorder", &b, &a]).await.ok();
    let j = cli.run(&["rules", "list", "-o", "json"]).await.json();
    let order: Vec<&str> = j["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["label"].as_str().unwrap())
        .collect();
    assert_eq!(order, vec!["b", "a"]);
    cli.run(&["rules", "reorder"]).await.code(2);

    cli.run(&["rules", "block-logging", "on"]).await.ok();
    let v = cli.run(&["rules", "show", &b, "-o", "json"]).await.json();
    assert_eq!(v["data"]["log"], true);
    cli.run(&["rules", "block-logging", "maybe"]).await.code(2);
}
