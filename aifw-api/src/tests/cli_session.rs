//! CLI v2 phase 1: login/logout/whoami, contexts, output formats, exit
//! codes, session refresh, and the pending/apply/confirm flow — real
//! `aifw` commands against the real router.

use super::cli_harness::{ADMIN_PASS, ADMIN_USER, Cli};
use super::*;
use std::os::unix::fs::PermissionsExt;

#[tokio::test]
async fn password_login_saves_context_and_whoami_works() {
    let cli = Cli::start().await;
    let r = cli
        .run_stdin(
            &[
                "login",
                &cli.base,
                "--context",
                "lab",
                "-u",
                ADMIN_USER,
                "--password-stdin",
            ],
            &format!("{ADMIN_PASS}\n"),
        )
        .await;
    r.ok();
    assert!(r.out.contains("Logged in to lab"), "{}", r.out);
    assert!(r.out.contains("[admin]"));

    let creds = cli.credentials();
    assert!(
        creds["lab"]["refresh_token"]
            .as_str()
            .unwrap()
            .starts_with("rfx_")
    );
    let mode = std::fs::metadata(cli.config_dir().join("credentials.toml"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);
    let cfg = std::fs::read_to_string(cli.config_dir().join("config.toml")).unwrap();
    assert!(cfg.contains("current = \"lab\""));
    assert!(!cfg.contains("rfx_"), "no secrets in config.toml");

    let who = cli.run(&["whoami"]).await;
    who.ok();
    assert!(who.out.contains("User:") && who.out.contains("admin"));
    assert!(who.out.contains("session"));

    let j = cli.run(&["whoami", "-o", "json"]).await;
    j.ok();
    let v = j.json();
    assert_eq!(v["username"], "admin");
    assert_eq!(v["context"], "lab");
    assert_eq!(v["auth"], "session");
    assert!(v["permissions"].as_array().unwrap().len() > 10);

    let y = cli.run(&["whoami", "-o", "yaml"]).await;
    y.ok();
    assert!(y.out.contains("username: admin"));
}

#[tokio::test]
async fn bad_password_exits_3_and_saves_nothing() {
    let cli = Cli::start().await;
    let r = cli
        .run_stdin(
            &[
                "login",
                &cli.base,
                "--context",
                "lab",
                "-u",
                ADMIN_USER,
                "--password-stdin",
            ],
            "wrong\n",
        )
        .await;
    r.code(3);
    assert!(r.err.contains("not authenticated"), "{}", r.err);
    assert!(!cli.config_dir().join("credentials.toml").exists());
    assert!(!cli.config_dir().join("config.toml").exists());
}

#[tokio::test]
async fn totp_login() {
    let cli = Cli::start().await;
    let token = cli.admin_token().await;
    let setup: Value = cli
        .http()
        .post(cli.url("/auth/totp/setup"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let secret = setup["secret"].as_str().unwrap().to_string();
    let code = crate::auth::totp::generate_current(&secret).unwrap();
    cli.http()
        .post(cli.url("/auth/totp/verify"))
        .bearer_auth(&token)
        .json(&json!({ "code": code }))
        .send()
        .await
        .unwrap();

    // Without a code and with --no-input: refuses to prompt.
    cli.run_stdin(
        &[
            "login",
            &cli.base,
            "--context",
            "lab",
            "-u",
            ADMIN_USER,
            "--password-stdin",
            "--no-input",
        ],
        &format!("{ADMIN_PASS}\n"),
    )
    .await
    .code(2);

    let code = crate::auth::totp::generate_current(&secret).unwrap();
    cli.run_stdin(
        &[
            "login",
            &cli.base,
            "--context",
            "lab",
            "-u",
            ADMIN_USER,
            "--password-stdin",
            "--totp",
            &code,
        ],
        &format!("{ADMIN_PASS}\n"),
    )
    .await
    .ok();
    cli.run(&["whoami"]).await.ok();
}

#[tokio::test]
async fn api_key_login_and_ad_hoc_flags() {
    let cli = Cli::start().await;
    let key = cli
        .mint_key(json!({ "name": "ci", "role_id": "builtin-viewer" }))
        .await;

    cli.run_stdin(
        &["login", &cli.base, "--context", "ro", "--api-key-stdin"],
        &format!("{key}\n"),
    )
    .await
    .ok();
    assert_eq!(
        cli.credentials()["ro"]["api_key"].as_str(),
        Some(key.as_str())
    );
    let v = cli.run(&["whoami", "-o", "json"]).await.json();
    assert_eq!(v["role"], "viewer");
    assert_eq!(v["auth"], "api-key");

    // Ad hoc: --url + --api-key, no context at all.
    let v = cli
        .run(&[
            "--url",
            &cli.base,
            "--api-key",
            &key,
            "whoami",
            "-o",
            "json",
            "--context",
            "ro",
        ])
        .await
        .json();
    assert_eq!(v["role"], "viewer");
}

#[tokio::test]
async fn exit_codes_for_auth_permission_reachability_and_usage() {
    let cli = Cli::start().await;

    // No credential at all → 3, with a hint.
    let r = cli.run(&["--url", &cli.base, "whoami"]).await;
    r.code(3);
    assert!(r.err.contains("aifw login"), "{}", r.err);

    // Viewer key can't apply → 4.
    let key = cli
        .mint_key(json!({ "name": "ro", "role_id": "builtin-viewer" }))
        .await;
    cli.run(&["--url", &cli.base, "--api-key", &key, "apply"])
        .await
        .code(4);

    // Unreachable → 7.
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let dead = format!("http://{}", l.local_addr().unwrap());
    drop(l);
    cli.run(&["--url", &dead, "--api-key", &key, "whoami"])
        .await
        .code(7);

    // Usage → 2; help/version → 0.
    cli.run(&["no-such-command"]).await.code(2);
    cli.run(&["--context", "nope", "whoami"]).await.code(2);
    let h = cli.run(&["--help"]).await;
    h.ok();
    assert!(h.out.contains("Exit codes"));
    cli.run(&["--version"]).await.ok();
}

#[tokio::test]
async fn json_errors_are_machine_readable() {
    let cli = Cli::start().await;
    let r = cli.run(&["--url", &cli.base, "whoami", "-o", "json"]).await;
    r.code(3);
    let v: Value = serde_json::from_str(r.err.trim()).unwrap();
    assert_eq!(v["kind"], "unauthenticated");
    assert_eq!(v["exit_code"], 3);
    assert!(r.out.is_empty());
}

#[tokio::test]
async fn expired_access_token_refreshes_and_persists_rotation() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let before = cli.credentials()["t"]["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Corrupt the access token: the next call must refresh with the stored
    // refresh token, then save the rotated pair.
    let mut creds = cli.credentials();
    creds["t"]["access_token"] = toml::Value::String("garbage".into());
    std::fs::write(
        cli.config_dir().join("credentials.toml"),
        toml::to_string(&creds).unwrap(),
    )
    .unwrap();

    cli.run(&["whoami"]).await.ok();
    let after = cli.credentials()["t"]["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(before, after, "rotated refresh token saved");
    // And the saved pair keeps working.
    cli.run(&["whoami"]).await.ok();
}

#[tokio::test]
async fn logout_revokes_and_forgets() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let refresh = cli.credentials()["t"]["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();

    let r = cli.run(&["logout"]).await;
    r.ok();
    assert!(r.out.contains("Logged out of t"));
    assert!(cli.credentials().get("t").is_none());

    // Server-side: the refresh token is dead.
    let resp = cli
        .http()
        .post(cli.url("/auth/refresh"))
        .json(&json!({ "refresh_token": refresh }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 401);

    cli.run(&["whoami"]).await.code(3);
    let again = cli.run(&["logout"]).await;
    again.ok();
    assert!(again.err.contains("Not logged in"));
}

#[tokio::test]
async fn context_management() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    cli.run(&[
        "context",
        "add",
        "edge",
        "--url",
        "10.9.9.9:8080",
        "--fingerprint",
        &"ab".repeat(32),
    ])
    .await
    .ok();

    let l = cli.run(&["context", "list"]).await;
    l.ok();
    assert!(
        l.out.contains("NAME") && l.out.contains("edge") && l.out.contains("https://10.9.9.9:8080")
    );
    let star = l
        .out
        .lines()
        .find(|x| x.contains(" t ") || x.starts_with("* ") || x.contains("*"))
        .unwrap();
    assert!(star.contains('*') && star.contains('t'));

    let j = cli.run(&["context", "list", "-o", "json"]).await.json();
    let names: Vec<&str> = j
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["edge", "t"]);
    assert_eq!(j[1]["auth"], "session");
    assert_eq!(j[1]["current"], true);

    cli.run(&["context", "use", "edge"]).await.ok();
    assert_eq!(
        cli.run(&["context", "show", "-o", "json"]).await.json()["name"],
        "edge"
    );
    cli.run(&["context", "use", "missing"]).await.code(2);
    cli.run(&["context", "add", "edge", "--url", "x"])
        .await
        .code(2);
    cli.run(&["context", "add", "bad name", "--url", "x"])
        .await
        .code(2);

    // Rename carries the credential.
    cli.run(&["context", "rename", "t", "lab"]).await.ok();
    assert!(cli.credentials().get("lab").is_some());
    assert!(cli.credentials().get("t").is_none());
    cli.run(&["--context", "lab", "whoami"]).await.ok();

    // set-pin with an explicit fingerprint (colon form).
    let colon = vec!["CD"; 32].join(":");
    cli.run(&["context", "set-pin", "edge", &colon]).await.ok();
    let shown = cli
        .run(&["context", "show", "edge", "-o", "json"])
        .await
        .json();
    assert_eq!(shown["pin"], "cd".repeat(32));

    // Removal needs confirmation: EOF = no.
    cli.run(&["context", "rm", "lab"]).await.code(1);
    cli.run(&["context", "rm", "lab", "--no-input"])
        .await
        .code(1);
    cli.run(&["context", "rm", "lab", "--yes"]).await.ok();
    assert!(cli.credentials().get("lab").is_none());
}

#[tokio::test]
async fn multi_context_is_refused_for_single_target_commands() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    cli.run(&["--context", "t,t", "apply"]).await.code(2);
}

#[tokio::test]
async fn pending_apply_flow() {
    let cli = Cli::start().await;
    cli.login_admin().await;

    let p = cli.run(&["pending"]).await;
    p.ok();
    assert!(p.out.contains("No unapplied changes"), "{}", p.out);

    // Stage a rule through the API.
    let token = cli.admin_token().await;
    let resp = cli
        .http()
        .post(cli.url("/rules"))
        .bearer_auth(&token)
        .json(&serde_json::to_value(any_tcp_rule()).unwrap())
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "{}", resp.status());

    let p = cli.run(&["pending", "-o", "json"]).await.json();
    assert_eq!(p["firewall"], true);
    let p = cli.run(&["pending"]).await;
    assert!(p.out.contains("firewall") && p.out.contains("aifw apply"));

    // On Linux the reload's VLAN step can't run real ifconfig, so the API
    // reports a partial reload; the CLI must surface the server's message.
    let a = cli.run(&["apply"]).await;
    if a.code == 0 {
        assert!(a.out.contains("applied"), "{}", a.out);
    } else {
        a.code(1);
        assert!(a.err.contains("Partial reload"), "{}", a.err);
    }
    assert_eq!(
        cli.run(&["pending", "-o", "json"]).await.json()["firewall"],
        false
    );
}

#[tokio::test]
async fn commit_confirm_flow() {
    let cli = Cli::start().await;
    cli.login_admin().await;

    let s = cli.run(&["confirm", "status"]).await;
    s.ok();
    assert!(s.out.contains("No commit-confirm window"));

    cli.run(&[
        "confirm",
        "arm",
        "--timeout",
        "10m",
        "--description",
        "cli test",
    ])
    .await
    .ok();
    let st = cli.run(&["confirm", "status", "-o", "json"]).await.json();
    assert_eq!(st["active"], true);
    assert_eq!(st["description"], "cli test");
    assert!(st["seconds_remaining"].as_u64().unwrap() > 500);

    // A second window can't be armed.
    cli.run(&["confirm", "arm"]).await.code(2);
    cli.run(&["confirm", "arm", "--timeout", "soon"])
        .await
        .code(2);

    cli.run(&["confirm", "accept"]).await.ok();
    // Nothing left to confirm → 9 (rolled back / never armed).
    let r = cli.run(&["confirm"]).await;
    r.code(9);
    assert!(r.err.contains("nothing to confirm"));
}

/// On the appliance (loopback URL) with no other credential, the CLI uses
/// the root CLI key file (remote URLs never get it — see the connect unit
/// tests).
#[tokio::test]
async fn loopback_uses_the_onbox_cli_key() {
    let cli = Cli::start().await;
    let key = cli
        .mint_key(json!({ "name": "stand-in-for-cli-key" }))
        .await;
    let env = cli.env();
    std::fs::create_dir_all(env.onbox.cli_key.parent().unwrap()).unwrap();
    std::fs::write(&env.onbox.cli_key, format!("{key}\n")).unwrap();

    let v = cli
        .run(&["--url", &cli.base, "whoami", "-o", "json"])
        .await
        .json();
    assert_eq!(v["username"], "admin");
    assert_eq!(v["auth"], "api-key");
    assert!(v["auth_source"].as_str().unwrap().ends_with("cli.key"));
}

#[tokio::test]
async fn local_cli_key_requires_root() {
    if nix::unistd::geteuid().is_root() {
        return;
    }
    let cli = Cli::start().await;
    let r = cli.run(&["local", "cli-key"]).await;
    r.code(2);
    assert!(r.err.contains("must run as root"));
}
