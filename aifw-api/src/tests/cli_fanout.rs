//! Fleet fan-out: one read-only command across several appliances.

use super::cli_harness::Cli;
use super::*;

/// Two independent API instances, saved as contexts `a` and `b` (API-key
/// credentials) in the first harness's config dir.
async fn two_appliances() -> (Cli, Cli) {
    let a = Cli::start().await;
    let b = Cli::start().await;
    for (name, cli) in [("a", &a), ("b", &b)] {
        let key = cli.mint_key(json!({ "name": "fleet" })).await;
        a.run_stdin(
            &["login", &cli.base, "--context", name, "--api-key-stdin"],
            &format!("{key}\n"),
        )
        .await
        .ok();
    }
    // Different state per box so results are distinguishable.
    a.run(&[
        "--context",
        "a",
        "rules",
        "add",
        "--action",
        "pass",
        "--label",
        "on-a",
    ])
    .await
    .ok();
    a.run(&[
        "--context",
        "b",
        "rules",
        "add",
        "--action",
        "block",
        "--label",
        "on-b",
    ])
    .await
    .ok();
    (a, b)
}

#[tokio::test]
async fn read_only_fan_out_merges_results() {
    let (a, _b) = two_appliances().await;

    let j = a
        .run(&["--context", "a,b", "rules", "list", "-o", "json"])
        .await;
    j.ok();
    let v = j.json();
    assert_eq!(v.as_array().unwrap().len(), 2);
    assert_eq!(v[0]["context"], "a");
    assert_eq!(v[0]["exit_code"], 0);
    assert_eq!(v[0]["result"]["data"][0]["label"], "on-a");
    assert_eq!(v[1]["result"]["data"][0]["label"], "on-b");

    let t = a.run(&["--all-contexts", "rules", "list"]).await;
    t.ok();
    assert!(
        t.out.contains("== a ==") && t.out.contains("== b =="),
        "{}",
        t.out
    );
    assert!(t.out.contains("on-a") && t.out.contains("on-b"));

    // Bounded parallelism still yields every context, in order.
    let p = a
        .run(&["--all-contexts", "--parallel", "1", "status", "-o", "json"])
        .await
        .json();
    assert_eq!(p[1]["context"], "b");
}

#[tokio::test]
async fn partial_failure_and_write_refusal() {
    let (a, _b) = two_appliances().await;
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = format!("http://{}", l.local_addr().unwrap());
    drop(l);
    a.run(&["context", "add", "gone", "--url", &dead])
        .await
        .ok();

    let r = a
        .run(&["--all-contexts", "rules", "list", "-o", "json"])
        .await;
    r.code(8);
    let v = r.json();
    let gone = v
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["context"] == "gone")
        .unwrap();
    assert_eq!(gone["exit_code"], 7);
    assert!(
        gone["error"].as_str().unwrap().contains("cannot reach"),
        "{gone}"
    );

    // Writes never fan out.
    let w = a
        .run(&["--context", "a,b", "rules", "add", "--action", "pass"])
        .await;
    w.code(2);
    assert!(w.err.contains("one appliance at a time"));
    a.run(&["--all-contexts", "apply"]).await.code(2);
}
