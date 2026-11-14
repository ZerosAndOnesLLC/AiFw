//! `aifw nat …` through the API.

use super::cli_harness::Cli;

#[tokio::test]
async fn dnat_add_list_edit_remove() {
    let cli = Cli::start().await;
    cli.login_admin().await;

    // The help examples' --nat-type spelling works too.
    let r = cli
        .run(&[
            "nat",
            "add",
            "--nat-type",
            "dnat",
            "--interface",
            "em0",
            "--proto",
            "tcp",
            "--dst-port",
            "80",
            "--redirect",
            "10.0.0.5",
            "--redirect-port",
            "8080",
            "--label",
            "web",
        ])
        .await;
    r.ok();
    assert!(r.out.starts_with("Added NAT rule "), "{}", r.out);
    assert!(r.out.contains("pf: rdr"), "pf preview: {}", r.out);
    assert_eq!(
        cli.run(&["pending", "-o", "json"]).await.json()["nat"],
        true
    );

    let j = cli.run(&["nat", "list", "--json"]).await.json();
    let id = j[0]["id"].as_str().unwrap().to_string();
    let l = cli.run(&["nat", "ls"]).await;
    assert!(
        l.out.contains("10.0.0.5:8080") && l.out.contains("dnat") && l.out.contains("any:80"),
        "{}",
        l.out
    );

    cli.run(&["nat", "edit", &id, "--redirect", "10.0.0.6"])
        .await
        .ok();
    let s = cli.run(&["nat", "show", &id, "-o", "json"]).await.json();
    assert_eq!(s["redirect"]["address"], "10.0.0.6");
    assert_eq!(
        s["redirect"]["port"]["start"], 8080,
        "untouched fields kept"
    );
    assert_eq!(s["label"], "web");

    cli.run(&["nat", "disable", &id]).await.ok();
    assert_eq!(
        cli.run(&["nat", "show", &id, "-o", "json"]).await.json()["status"],
        "disabled"
    );
    cli.run(&["nat", "enable", &id]).await.ok();

    let pf = cli.run(&["nat", "pf-output"]).await;
    pf.ok();

    cli.run(&["nat", "rm", &id, "--yes"]).await.ok();
    cli.run(&["nat", "show", &id]).await.code(5);
}

#[tokio::test]
async fn type_specific_defaults_and_errors() {
    let cli = Cli::start().await;
    cli.login_admin().await;

    // masquerade needs no --redirect.
    cli.run(&[
        "nat",
        "add",
        "--type",
        "masquerade",
        "--interface",
        "em0",
        "--src",
        "192.168.1.0/24",
    ])
    .await
    .ok();
    // snat without --redirect is a usage error; missing type/interface too.
    cli.run(&["nat", "add", "--type", "snat", "--interface", "em0"])
        .await
        .code(2);
    cli.run(&["nat", "add", "--interface", "em0"]).await.code(2);
    cli.run(&["nat", "add", "--type", "dnat", "--redirect", "10.0.0.1"])
        .await
        .code(2);
    // Server validation (static-port on dnat) → 6 with a flag hint.
    let r = cli
        .run(&[
            "nat",
            "add",
            "--type",
            "dnat",
            "--interface",
            "em0",
            "--dst-port",
            "80",
            "--redirect",
            "10.0.0.1",
            "--static-port",
        ])
        .await;
    r.code(6);
    assert!(r.err.contains("--static-port"), "hint: {}", r.err);

    let e = cli.run(&["nat", "embed", "64:ff9b::/96", "10.1.2.3"]).await;
    e.ok();
    assert_eq!(e.out.trim(), "64:ff9b::a01:203");
    cli.run(&["nat", "embed", "nope", "10.1.2.3"]).await.code(2);
}
