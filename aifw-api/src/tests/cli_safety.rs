//! PR #714 review, safety items: reserved `local` context, fan-out limits,
//! concurrent session refresh, logout after expiry.

use super::cli_harness::Cli;
use super::*;

#[tokio::test]
async fn local_context_name_is_reserved() {
    let cli = Cli::start().await;
    cli.run(&["context", "add", "local", "--url", "https://10.0.0.9:8080"])
        .await
        .code(2);
    // Refused before any network traffic.
    let r = cli
        .run_stdin(
            &[
                "login",
                "https://10.0.0.9:8080",
                "--context",
                "local",
                "--api-key-stdin",
            ],
            "aifw_x\n",
        )
        .await;
    r.code(2);
    assert!(r.err.contains("reserved"), "{}", r.err);
}

#[tokio::test]
async fn fan_out_refuses_writes_and_ad_hoc_credentials() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let key = cli.mint_key(json!({"name": "k"})).await;
    cli.run_stdin(
        &["login", &cli.base, "--context", "b", "--api-key-stdin"],
        &format!("{key}\n"),
    )
    .await
    .ok();
    let w = cli
        .run(&[
            "--all-contexts",
            "acme",
            "account",
            "--email",
            "x@example.com",
        ])
        .await;
    w.code(2);
    assert!(w.err.contains("one appliance at a time"));
    cli.run(&["--all-contexts", "totp", "verify", "123456"])
        .await
        .code(2);
    let t = cli
        .run(&["--all-contexts", "--api-key", &key, "whoami"])
        .await;
    t.code(2);
    assert!(t.err.contains("each context's own credentials"));
    cli.run(&["--all-contexts", "--url", &cli.base, "status"])
        .await
        .code(2);
    cli.run(&["--all-contexts", "whoami"]).await.ok();
}

/// Several processes refreshing one session must not log each other out.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_refresh_keeps_the_session() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let mut creds = cli.credentials();
    creds["t"]["access_token"] = toml::Value::String("garbage".into());
    std::fs::write(
        cli.config_dir().join("credentials.toml"),
        toml::to_string(&creds).unwrap(),
    )
    .unwrap();

    let runs = (0..4).map(|_| cli.run(&["whoami"]));
    let codes: Vec<i32> = futures_util::future::join_all(runs)
        .await
        .iter()
        .map(|r| r.code)
        .collect();
    assert_eq!(
        codes,
        vec![0, 0, 0, 0],
        "every concurrent refresh succeeded"
    );
    cli.run(&["whoami"]).await.ok();
}

/// Logout after the access token lapsed still revokes the live session.
#[tokio::test]
async fn logout_after_expiry_revokes() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let mut creds = cli.credentials();
    creds["t"]["access_expires_at"] = toml::Value::String("2000-01-01T00:00:00Z".into());
    std::fs::write(
        cli.config_dir().join("credentials.toml"),
        toml::to_string(&creds).unwrap(),
    )
    .unwrap();
    let r = cli.run(&["logout"]).await;
    r.ok();
    assert!(!r.err.contains("server-side logout failed"), "{}", r.err);
    let (live,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM refresh_tokens WHERE revoked = 0")
        .fetch_one(&cli.pool)
        .await
        .unwrap();
    // The harness's own admin_token() logins aren't used here, so the CLI
    // session was the only one.
    assert_eq!(live, 0, "no live refresh token left behind");
}

/// Plain HTTP to another machine needs an explicit opt-in.
#[tokio::test]
async fn login_refuses_remote_plain_http() {
    let cli = Cli::start().await;
    let r = cli
        .run_stdin(
            &[
                "login",
                "http://10.0.0.9:8080",
                "--context",
                "x",
                "--api-key-stdin",
            ],
            "aifw_x\n",
        )
        .await;
    r.code(2);
    assert!(r.err.contains("--allow-http"), "{}", r.err);
}

/// List output never carries WireGuard peer secrets.
#[tokio::test]
async fn wireguard_lists_hide_peer_secrets() {
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
            "10.7.0.1/24",
            "-o",
            "json",
        ])
        .await
        .json();
    let tid = t["data"]["id"].as_str().unwrap().to_string();
    cli.run(&[
        "vpn",
        "wg",
        "peers",
        "add",
        &tid,
        "--name",
        "l",
        "--generate-key",
    ])
    .await
    .ok();
    for args in [
        &["vpn", "wg", "peers", "list", tid.as_str(), "-o", "json"][..],
        &["vpn", "list", "-o", "json"],
    ] {
        let out = cli.run(args).await.out;
        assert!(
            !out.contains("PrivateKey") && out.contains("REDACTED"),
            "{args:?}: {out}"
        );
    }
}
