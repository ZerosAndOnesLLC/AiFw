//! Phase-3 CLI coverage: aliases, schedules, VLANs, roles, API keys,
//! certificates, time, resolver/blocklists, backup/notify, settings,
//! system, 2FA, and the read-only operational views.

use super::cli_harness::Cli;
use super::*;

fn write(cli: &Cli, name: &str, text: &str) -> String {
    let p = cli.dir.join(name);
    std::fs::write(&p, text).unwrap();
    p.to_str().unwrap().to_string()
}

#[tokio::test]
async fn aliases_schedules_vlans() {
    let cli = Cli::start().await;
    cli.login_admin().await;

    cli.run(&[
        "aliases",
        "add",
        "--name",
        "web_servers",
        "--type",
        "host",
        "--entries",
        "10.0.0.5,10.0.0.6",
    ])
    .await
    .ok();
    cli.run(&[
        "aliases",
        "edit",
        "web_servers",
        "--add",
        "10.0.0.7",
        "--del",
        "10.0.0.5",
    ])
    .await
    .ok();
    let a = cli
        .run(&["aliases", "show", "web_servers", "-o", "json"])
        .await
        .json();
    assert_eq!(a["entries"], json!(["10.0.0.6", "10.0.0.7"]));
    assert!(
        cli.run(&["aliases", "ls"])
            .await
            .out
            .contains("web_servers")
    );
    cli.run(&["aliases", "edit", "web_servers"]).await.code(2);
    cli.run(&[
        "aliases",
        "add",
        "--name",
        "x",
        "--type",
        "bogus",
        "--entries",
        "1",
    ])
    .await
    .code(6);
    assert_eq!(
        cli.run(&["pending", "-o", "json"]).await.json()["firewall"],
        true
    );
    cli.run(&["aliases", "rm", "web_servers", "--yes"])
        .await
        .ok();

    cli.run(&[
        "schedules",
        "add",
        "--name",
        "work",
        "--times",
        "08:00-17:00",
        "--days",
        "mon,tue,wed,thu,fri",
    ])
    .await
    .ok();
    cli.run(&["schedules", "edit", "work", "--times", "07:00-18:00"])
        .await
        .ok();
    let s = cli.run(&["schedules", "list", "-o", "json"]).await.json();
    assert_eq!(s["data"][0]["time_ranges"], "07:00-18:00");
    assert!(
        s["data"][0]["days_of_week"]
            .as_str()
            .unwrap()
            .contains("fri"),
        "kept"
    );
    cli.run(&[
        "schedules",
        "add",
        "--name",
        "bad",
        "--times",
        "25:00-26:00",
    ])
    .await
    .code(6);
    cli.run(&["schedules", "rm", "work", "--yes"]).await.ok();

    cli.run(&[
        "vlans",
        "add",
        "--vlan-id",
        "20",
        "--parent",
        "em1",
        "--ipv4-mode",
        "static",
        "--ipv4-address",
        "10.20.0.1/24",
    ])
    .await
    .ok();
    let v = cli.run(&["vlans", "list", "-o", "json"]).await.json();
    let vid = v["data"][0]["id"].as_str().unwrap().to_string();
    cli.run(&["vlans", "edit", &vid, "--mtu", "1400"])
        .await
        .ok();
    let v = cli.run(&["vlans", "list", "-o", "json"]).await.json();
    assert_eq!(v["data"][0]["mtu"], 1400);
    assert_eq!(v["data"][0]["ipv4_address"], "10.20.0.1/24", "kept");
    cli.run(&["vlans", "add", "--vlan-id", "5000", "--parent", "em1"])
        .await
        .code(6);
    cli.run(&["vlans", "rm", &vid, "--yes"]).await.ok();
}

#[tokio::test]
async fn roles_api_keys_totp_audit() {
    let cli = Cli::start().await;
    cli.login_admin().await;

    cli.run(&[
        "roles",
        "add",
        "--name",
        "auditor",
        "--permissions",
        "rules:read,nat:read",
        "--description",
        "read only",
    ])
    .await
    .ok();
    let r = cli
        .run(&["roles", "show", "auditor", "-o", "json"])
        .await
        .json();
    assert_eq!(r["permissions"].as_array().unwrap().len(), 2);
    cli.run(&["roles", "edit", "auditor", "--permissions", "rules:read"])
        .await
        .ok();
    assert_eq!(
        cli.run(&["roles", "show", "auditor", "-o", "json"])
            .await
            .json()["permissions"],
        json!(["rules:read"])
    );
    assert!(
        cli.run(&["roles", "permissions"])
            .await
            .out
            .contains("rules:write")
    );
    cli.run(&["roles", "edit", "admin", "--name", "root"])
        .await
        .code(4);
    let role_id = cli
        .run(&["roles", "show", "auditor", "-o", "json"])
        .await
        .json()["id"]
        .as_str()
        .unwrap()
        .to_string();

    // API key narrowed to that role; the secret is alone on stdout.
    let k = cli
        .run(&[
            "api-keys",
            "create",
            "--name",
            "ci",
            "--role",
            &role_id,
            "--expires-days",
            "7",
        ])
        .await;
    k.ok();
    let key = k.out.trim().to_string();
    assert!(key.starts_with("aifw_") && !k.out.contains("Created"));
    let who = cli
        .run(&[
            "--url",
            &cli.base,
            "--api-key",
            &key,
            "whoami",
            "-o",
            "json",
        ])
        .await
        .json();
    assert_eq!(who["role"], "auditor");
    let l = cli.run(&["api-keys", "ls"]).await;
    assert!(
        l.out.contains("ci") && l.out.contains("auditor"),
        "{}",
        l.out
    );
    let kid = cli.run(&["api-keys", "list", "-o", "json"]).await.json()["data"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    cli.run(&["api-keys", "revoke", &kid, "--yes"]).await.ok();
    cli.run(&["--url", &cli.base, "--api-key", &key, "whoami"])
        .await
        .code(3);
    cli.run(&["roles", "rm", "auditor", "--yes"]).await.ok();

    // 2FA enrolment through the CLI session.
    let s = cli.run(&["totp", "setup", "-o", "json"]).await;
    s.ok();
    let secret = s.json()["secret"].as_str().unwrap().to_string();
    let code = crate::auth::totp::generate_current(&secret).unwrap();
    cli.run(&["totp", "verify", &code]).await.ok();
    assert_eq!(
        cli.run(&["whoami", "-o", "json"]).await.json()["totp_enabled"],
        true
    );
    cli.run(&["totp", "disable", "000000"]).await.code(3);

    let a = cli.run(&["audit"]).await;
    a.ok();
    assert!(a.out.contains("api_key_created"), "{}", a.out);
}

#[tokio::test]
async fn certificates() {
    let cli = Cli::start().await;
    cli.login_admin().await;

    cli.run(&["acme", "account", "--email", "ops@example.com"])
        .await
        .ok();
    assert!(
        cli.run(&["acme", "account"])
            .await
            .out
            .contains("ops@example.com")
    );
    cli.run(&["acme", "account", "--email", "not-an-email"])
        .await
        .code(6);
    let prov = write(
        &cli,
        "p.json",
        r#"{"name":"cf","kind":"cloudflare","zone":"example.com","api_token":"t0k3n"}"#,
    );
    cli.run(&["acme", "dns-providers", "add", "-f", &prov])
        .await
        .ok();
    let l = cli.run(&["acme", "dns-providers"]).await;
    assert!(
        l.out.contains("cloudflare") && !l.out.contains("t0k3n"),
        "{}",
        l.out
    );
    let pid = cli
        .run(&["acme", "dns-providers", "list", "-o", "json"])
        .await
        .json()[0]["id"]
        .as_i64()
        .unwrap();
    cli.run(&["acme", "certs", "add", "--common-name", "fw.example.com"])
        .await
        .code(2);
    cli.run(&[
        "acme",
        "certs",
        "add",
        "--common-name",
        "fw.example.com",
        "--provider",
        &pid.to_string(),
    ])
    .await
    .ok();
    assert!(
        cli.run(&["acme", "certs", "ls"])
            .await
            .out
            .contains("fw.example.com")
    );
    cli.run(&["acme", "dns-providers", "rm", "cf", "--yes"])
        .await
        .ok();
    cli.run(&["ddns", "config", "-o", "json"]).await.ok();

    // Internal CA: init, issue to files, revoke.
    cli.run(&["ca", "init", "--common-name", "Test CA"])
        .await
        .ok();
    assert!(cli.run(&["ca", "show"]).await.out.contains("Test CA"));
    let ca_pem = cli.dir.join("ca.pem");
    cli.run(&["ca", "pem", "-O", ca_pem.to_str().unwrap()])
        .await
        .ok();
    assert!(
        std::fs::read_to_string(&ca_pem)
            .unwrap()
            .contains("BEGIN CERTIFICATE")
    );
    let out = cli.dir.join("certs");
    std::fs::create_dir_all(&out).unwrap();
    let i = cli
        .run(&[
            "ca",
            "certs",
            "issue",
            "--type",
            "server",
            "--common-name",
            "vpn.lan",
            "--sans",
            "vpn.lan,10.0.0.1",
            "--out-dir",
            out.to_str().unwrap(),
        ])
        .await;
    i.ok();
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(out.join("vpn.lan.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let cid = cli.run(&["ca", "certs", "list", "-o", "json"]).await.json()["data"][0]["id"]
        .as_str()
        .unwrap()
        .to_string();
    cli.run(&["ca", "certs", "revoke", &cid, "--yes"])
        .await
        .ok();
    assert!(cli.run(&["ca", "crl"]).await.out.contains("vpn.lan"));
    // Re-init asks first.
    cli.run(&["ca", "init"]).await.code(1);
}

#[tokio::test]
async fn time_resolver_blocklists() {
    let cli = Cli::start().await;
    cli.login_admin().await;

    cli.run(&["time", "add-source", "pool.ntp.org"]).await.ok();
    assert!(
        cli.run(&["time", "sources"])
            .await
            .out
            .contains("pool.ntp.org")
    );
    let tid = cli
        .run(&["time", "sources", "list", "-o", "json"])
        .await
        .json()["data"][0]["id"]
        .to_string()
        .trim_matches('"')
        .to_string();
    let patch = write(&cli, "nts.json", r#"{"nts": true}"#);
    cli.run(&["time", "sources", "edit", &tid, "-f", &patch])
        .await
        .ok();
    assert_eq!(
        cli.run(&["time", "sources", "list", "-o", "json"])
            .await
            .json()["data"][0]["nts"],
        true
    );
    cli.run(&["time", "config"]).await.ok();

    cli.run(&["dns", "add-host", "nas", "home.arpa", "192.168.1.20"])
        .await
        .ok();
    assert!(cli.run(&["dns", "hosts"]).await.out.contains("nas"));
    let dom = write(
        &cli,
        "d.json",
        r#"{"domain":"corp.example","server":"10.0.0.53"}"#,
    );
    cli.run(&["dns", "domains", "add", "-f", &dom]).await.ok();
    assert!(
        cli.run(&["dns", "domains"])
            .await
            .out
            .contains("corp.example")
    );
    let acl = write(
        &cli,
        "acl.json",
        r#"{"network":"192.168.0.0/16","action":"allow"}"#,
    );
    cli.run(&["dns", "acls", "add", "-f", &acl]).await.ok();
    cli.run(&["dns", "config", "-o", "json"]).await.ok();
    cli.run(&["dns", "status"]).await.ok();

    let bl = write(
        &cli,
        "bl.json",
        r#"{"name":"ads","category":"ads","url":"https://example.com/hosts.txt","format":"hosts"}"#,
    );
    cli.run(&["dns", "blocklists", "add", "-f", &bl]).await.ok();
    let id = cli
        .run(&["dns", "blocklists", "list", "-o", "json"])
        .await
        .json()
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["name"] == "ads")
        .unwrap()["id"]
        .to_string();
    cli.run(&["dns", "blocklists", "disable", &id]).await.ok();
    cli.run(&["dns", "blocklists", "schedule"]).await.ok();
    cli.run(&["dns", "blocklists", "rm", &id, "--yes"])
        .await
        .ok();
    cli.run(&[
        "dns",
        "whitelist",
        "add",
        "-f",
        &write(&cli, "w.json", r#"{"pattern":"good.example"}"#),
    ])
    .await
    .ok();
    assert!(
        cli.run(&["dns", "whitelist"])
            .await
            .out
            .contains("good.example")
    );
}

#[tokio::test]
async fn backup_settings_system_and_views() {
    let cli = Cli::start().await;
    cli.login_admin().await;

    let s3 = write(
        &cli,
        "s3.json",
        r#"{"enabled":false,"bucket":"b","region":"us-east-1","secret_access_key":"shh"}"#,
    );
    cli.run(&["backup", "s3", "config", "-f", &s3]).await.ok();
    let c = cli.run(&["backup", "s3", "config", "-o", "json"]).await;
    assert!(
        c.out.contains("has_secret") && !c.out.contains("shh"),
        "{}",
        c.out
    );
    cli.run(&["notify", "smtp", "config"]).await.ok();

    cli.run(&[
        "settings",
        "set",
        "tls",
        "min_version=tls13",
        "block_expired=true",
    ])
    .await
    .ok();
    assert_eq!(
        cli.run(&["settings", "get", "tls"]).await.json()["min_version"],
        "tls13"
    );
    cli.run(&["settings", "set", "tls"]).await.code(2);
    cli.run(&["settings", "auth"]).await.ok();
    cli.run(&["settings", "auth", "max_login_attempts=7"])
        .await
        .ok();
    cli.run(&["settings", "oauth-providers"]).await.ok();

    cli.run(&["system", "general"]).await.ok();
    cli.run(&["system", "timezones"]).await.ok();
    cli.run(&["system", "info"]).await.ok();
    cli.run(&["reboot"]).await.code(1);

    for view in [
        &["connections"][..],
        &["blocked"],
        &["logs"],
        &["metrics"],
        &["metrics", "list"],
        &["about"],
        &["ai", "audit"],
    ] {
        let r = cli.run(view).await;
        assert!(r.code == 0 || r.code == 1, "{view:?}: {}", r.err);
    }
    let l = cli.run(&["logs"]).await;
    l.ok();
}

#[tokio::test]
async fn top_once() {
    let cli = Cli::start().await;
    cli.login_admin().await;
    let t = cli.run(&["top", "--once"]).await;
    t.ok();
    assert!(t.out.contains("states"), "{}", t.out);
    let j = cli.run(&["top", "--once", "-o", "json"]).await.json();
    assert!(j["status"].is_object() && j["metrics"].is_object());
}
