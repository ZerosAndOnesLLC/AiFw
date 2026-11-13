//! Smaller CLI groups through the API: queue, routes, geoip, dns, users,
//! status, reload, interfaces.

use super::cli_harness::Cli;
use super::*;

#[tokio::test]
async fn queues() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let r = cli
        .run(&[
            "queue",
            "add",
            "--name",
            "voip",
            "--interface",
            "em0",
            "--bandwidth",
            "100Mb",
            "--class",
            "voip",
            "--pct",
            "20",
        ])
        .await;
    r.ok();
    assert!(r.out.starts_with("Added queue "), "{}", r.out);
    assert!(!r.out.contains("pf: \n"), "no empty pf line");
    let j = cli.run(&["queue", "list", "--json"]).await.json();
    let id = j["data"][0]["id"].as_str().unwrap().to_string();
    let l = cli.run(&["queue", "ls"]).await;
    assert!(l.out.contains("voip") && l.out.contains("100"), "{}", l.out);

    cli.run(&["queue", "edit", &id, "--pct", "30"]).await.ok();
    assert_eq!(
        cli.run(&["queue", "list", "-o", "json"]).await.json()["data"][0]["bandwidth_pct"],
        30
    );
    cli.run(&["queue", "edit", &id]).await.code(2);
    cli.run(&["queue", "disable", &id]).await.ok();
    assert_eq!(
        cli.run(&["queue", "list", "-o", "json"]).await.json()["data"][0]["status"],
        "disabled"
    );
    cli.run(&[
        "queue",
        "add",
        "--name",
        "x",
        "--interface",
        "em0",
        "--bandwidth",
        "lots",
    ])
    .await
    .code(2);
    cli.run(&["queue", "status"]).await.ok();
    cli.run(&["queue", "rm", &id, "--yes"]).await.ok();
    cli.run(&["queue", "edit", &id, "--pct", "1"]).await.code(5);
}

#[tokio::test]
async fn static_routes() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    cli.run(&[
        "routes",
        "add",
        "--dest",
        "10.20.0.0/16",
        "--gateway",
        "192.0.2.1",
        "--desc",
        "lab",
    ])
    .await
    .ok();
    let j = cli.run(&["routes", "list", "--json"]).await.json();
    let id = j["data"][0]["id"].as_str().unwrap().to_string();
    assert!(
        cli.run(&["routes", "ls"])
            .await
            .out
            .contains("10.20.0.0/16")
    );

    cli.run(&["routes", "edit", &id, "--metric", "7"])
        .await
        .ok();
    let r = &cli.run(&["routes", "list", "-o", "json"]).await.json()["data"][0];
    assert_eq!(r["metric"], 7);
    assert_eq!(r["description"], "lab", "kept");
    cli.run(&["routes", "disable", &id]).await.ok();
    assert_eq!(
        cli.run(&["routes", "list", "-o", "json"]).await.json()["data"][0]["enabled"],
        false
    );
    cli.run(&[
        "routes",
        "add",
        "--dest",
        "not-a-net",
        "--gateway",
        "192.0.2.1",
    ])
    .await
    .code(6);
    cli.run(&["routes", "rm", &id, "-y"]).await.ok();
    cli.run(&["routes", "rm", &id, "-y"]).await.code(5);
}

#[tokio::test]
async fn geoip_rules_and_database() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let r = cli
        .run(&[
            "geoip",
            "add",
            "--country",
            "cn",
            "--action",
            "block",
            "--label",
            "x",
        ])
        .await;
    r.ok();
    assert!(r.out.contains("block CN"), "{}", r.out);
    let l = cli.run(&["geoip", "list"]).await;
    l.ok();
    assert!(
        l.out.contains("CN") && l.out.contains("Database:"),
        "{}",
        l.out
    );
    let id = cli.run(&["geoip", "list", "--json"]).await.json()["data"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();

    cli.run(&["geoip", "edit", &id, "--action", "allow"])
        .await
        .ok();
    let row = &cli.run(&["geoip", "list", "-o", "json"]).await.json()["data"][0];
    assert_eq!(row["action"], "allow");
    assert_eq!(row["label"], "x");
    cli.run(&["geoip", "disable", &id]).await.ok();

    let lk = cli.run(&["geoip", "lookup", "192.0.2.1"]).await;
    lk.ok();
    assert!(lk.out.contains("192.0.2.1"));
    let db = cli.run(&["geoip", "database", "--json"]).await.json();
    assert!(db.get("loaded").is_some());
    cli.run(&["geoip", "database", "--update-interval-hours", "168"])
        .await
        .ok();
    assert_eq!(
        cli.run(&["geoip", "database", "-o", "json"]).await.json()["update_interval_hours"],
        168
    );
    cli.run(&["geoip", "import", "/nonexistent.zip"])
        .await
        .code(2);

    cli.run(&["geoip", "add", "--country", "ZZZ", "--action", "block"])
        .await
        .code(6);
    cli.run(&["geoip", "rm", &id, "--yes"]).await.ok();
}

#[tokio::test]
async fn dns_servers_and_probe() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    cli.run(&["dns", "set", "1.1.1.1, 9.9.9.9"]).await.ok();
    let l = cli.run(&["dns", "list"]).await;
    l.ok();
    assert_eq!(
        l.out.lines().collect::<Vec<_>>(),
        vec!["1.1.1.1", "9.9.9.9"]
    );
    cli.run(&["dns", "set", " , "]).await.code(2);

    cli.run(&["dns", "probe", "off"]).await.ok();
    assert!(
        cli.run(&["dns", "probe", "status"])
            .await
            .out
            .contains("off")
    );
    cli.run(&["dns", "probe", "on"]).await.ok();
    assert_eq!(
        cli.run(&["dns", "probe", "status", "-o", "json"])
            .await
            .json()["probe_enabled"],
        true
    );
    cli.run(&["dns", "probe", "sideways"]).await.code(2);
}

#[tokio::test]
async fn users_by_name_and_through_an_api_key() {
    let cli = Cli::start().await;
    // An admin API key (like the on-box CLI key) must manage users too.
    let key = cli.mint_key(json!({ "name": "ops" })).await;
    let base = ["--url", cli.base.as_str(), "--api-key", key.as_str()];
    let run = |extra: &[&str]| {
        let mut a: Vec<&str> = base.to_vec();
        a.extend_from_slice(extra);
        a.iter().map(|s| s.to_string()).collect::<Vec<_>>()
    };
    let go = |args: Vec<String>, stdin: &'static str| {
        let cli = &cli;
        async move {
            let refs: Vec<&str> = args.iter().map(String::as_str).collect();
            cli.run_stdin(&refs, stdin).await
        }
    };

    go(
        run(&[
            "users",
            "add",
            "--username",
            "bob",
            "--password-stdin",
            "--role",
            "viewer",
        ]),
        "LongEnough123!\n",
    )
    .await
    .ok();
    let l = go(run(&["users", "ls"]), "").await;
    assert!(l.out.contains("bob") && l.out.contains("viewer"));
    go(run(&["users", "set-role", "bob", "operator"]), "")
        .await
        .ok();
    assert_eq!(
        go(run(&["users", "show", "bob", "-o", "json"]), "")
            .await
            .json()["role"],
        "operator"
    );
    go(run(&["users", "disable", "bob"]), "").await.ok();
    assert_eq!(
        go(run(&["users", "show", "bob", "-o", "json"]), "")
            .await
            .json()["enabled"],
        false
    );
    go(run(&["users", "enable", "bob"]), "").await.ok();
    go(
        run(&["users", "passwd", "bob", "--password-stdin"]),
        "AnotherLong123!\n",
    )
    .await
    .ok();
    // The new password works.
    let ok = cli
        .http()
        .post(cli.url("/auth/login"))
        .json(&json!({"username": "bob", "password": "AnotherLong123!"}))
        .send()
        .await
        .unwrap();
    assert!(ok.status().is_success());
    // Too-short password is the server's validation error.
    go(
        run(&["users", "add", "--username", "x", "--password", "short"]),
        "",
    )
    .await
    .code(6);
    go(run(&["users", "rm", "bob", "--yes"]), "").await.ok();
    go(run(&["users", "show", "bob"]), "").await.code(5);
}

#[tokio::test]
async fn status_reload_interfaces() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let s = cli.run(&["status"]).await;
    s.ok();
    assert!(s.out.contains("pf running:"), "{}", s.out);
    assert!(
        cli.run(&["status", "-o", "json"])
            .await
            .json()
            .get("pf_rules")
            .is_some()
    );
    // reload = apply + queues; on Linux the VLAN step reports a partial reload.
    let r = cli.run(&["reload"]).await;
    assert!(
        r.code == 0 || r.err.contains("Partial reload"),
        "{} {}",
        r.out,
        r.err
    );
    // interfaces needs ifconfig; just make sure it's an API call that renders.
    let i = cli.run(&["interfaces", "-o", "json"]).await;
    assert!(i.code == 0 || i.code == 1, "{}", i.err);
}
