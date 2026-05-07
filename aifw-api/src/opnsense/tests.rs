//! Integration tests for the OPNsense importer.
//!
//! Each test asserts the behavior pinned in epic #230. Fixtures live inline
//! to keep the test self-contained — real OPNsense configs are 50–500 KB but
//! the schema fields the importer actually reads are stable enough that the
//! minimal fixture below covers every code path the parser and applier hit.

#![cfg(test)]

use crate::auth::AuthSettings;
use axum::http::StatusCode;
use axum_test::TestServer;
use serde_json::{Value, json};

const MEDIUM_FIXTURE: &str = include_str!("test_fixtures/medium.xml");

async fn test_app() -> (TestServer, AuthSettings) {
    let auth_settings = AuthSettings {
        jwt_secret: "test-secret-key".to_string(),
        access_token_expiry_mins: 60,
        refresh_token_expiry_days: 7,
        require_totp: false,
        require_totp_for_oauth: false,
        auto_create_oauth_users: true,
        max_login_attempts: 5,
        lockout_duration_secs: 300,
        allow_registration: true,
        password_min_length: 8,
    };
    let state = crate::create_app_state_in_memory(auth_settings.clone())
        .await
        .unwrap();
    let app = crate::build_router(state, None, "*", false);
    let server = TestServer::new(app).unwrap();
    (server, auth_settings)
}

async fn login(server: &TestServer) -> String {
    server
        .post("/api/v1/auth/register")
        .json(&json!({ "username": "admin", "password": "TestPass123" }))
        .await;
    let resp = server
        .post("/api/v1/auth/login")
        .json(&json!({ "username": "admin", "password": "TestPass123" }))
        .await;
    let body: Value = resp.json();
    body["tokens"]["access_token"].as_str().unwrap().to_string()
}

#[tokio::test]
async fn preview_rejects_non_opnsense_xml() {
    let (server, _) = test_app().await;
    let token = login(&server).await;
    let resp = server
        .post("/api/v1/config/preview-opnsense")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({ "xml": "<wireguard><peer/></wireguard>" }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["valid"], false);
    assert!(
        body["error"].as_str().unwrap_or("").contains("OPNsense") ||
        body["error"].as_str().unwrap_or("").contains("pfSense")
    );
}

#[tokio::test]
async fn preview_rejects_oversized_payload() {
    let (server, _) = test_app().await;
    let token = login(&server).await;
    let huge = format!("<opnsense>{}</opnsense>", "x".repeat(11 * 1024 * 1024));
    let resp = server
        .post("/api/v1/config/preview-opnsense")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({ "xml": huge }))
        .await;
    // The DefaultBodyLimit on the route returns 413 before our handler runs.
    assert_eq!(resp.status_code(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn preview_reports_counts_and_skipped() {
    let (server, _) = test_app().await;
    let token = login(&server).await;
    let resp = server
        .post("/api/v1/config/preview-opnsense")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({ "xml": MEDIUM_FIXTURE }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["valid"], true);
    assert_eq!(body["kind"], "opnsense");
    assert_eq!(body["counts"]["aliases"], 2);
    assert_eq!(body["counts"]["nat_port_forwards"], 1);
    assert_eq!(body["counts"]["nat_outbound"], 1);
    assert_eq!(body["counts"]["static_routes"], 1);
    assert_eq!(body["counts"]["dns_servers"], 2);
    let skipped = body["skipped"].as_array().unwrap();
    assert!(
        skipped.iter().any(|s| s.as_str().unwrap_or("").contains("network keywords")),
        "skipped should call out network-keyword rules: {skipped:?}"
    );
}

#[tokio::test]
async fn import_applies_rules_with_ipv6_and_ports() {
    let (server, _) = test_app().await;
    let token = login(&server).await;

    let resp = server
        .post("/api/v1/config/import-opnsense")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "xml": MEDIUM_FIXTURE,
            "interface_map": { "wan": "eth0", "lan": "eth1" },
            "commit_confirm": false,
        }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert!(body["applied"]["rules"].as_u64().unwrap_or(0) >= 1);
    assert!(body["pre_import_version"].is_number());

    // Verify the rule list now includes our SSH-IPv6 rule.
    let list = server
        .get("/api/v1/rules")
        .add_header("authorization", format!("Bearer {token}"))
        .await;
    list.assert_status_ok();
    let rules: Value = list.json();
    let arr = rules["data"].as_array().or_else(|| rules.as_array()).unwrap();
    let ssh = arr
        .iter()
        .find(|r| r["label"].as_str().unwrap_or("").contains("SSH"))
        .expect("SSH rule should have been imported");
    // H1: destination port survives.
    assert_eq!(ssh["rule_match"]["dst_port"]["start"].as_u64(), Some(22));
    // H2: ipv6 family preserved.
    assert_eq!(ssh["ip_version"], "inet6");
}

#[tokio::test]
async fn import_writes_aliases_via_engine() {
    let (server, _) = test_app().await;
    let token = login(&server).await;
    let resp = server
        .post("/api/v1/config/import-opnsense")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({ "xml": MEDIUM_FIXTURE, "commit_confirm": false }))
        .await;
    resp.assert_status_ok();

    // H3: aliases reachable via the alias REST endpoint.
    let aliases = server
        .get("/api/v1/aliases")
        .add_header("authorization", format!("Bearer {token}"))
        .await;
    aliases.assert_status_ok();
    let body: Value = aliases.json();
    let arr = body["data"].as_array().or_else(|| body.as_array()).unwrap();
    assert!(
        arr.iter().any(|a| a["name"] == "my_servers"),
        "imported alias should be visible via the aliases API"
    );
}

#[tokio::test]
async fn import_writes_nat_via_engine_with_proper_columns() {
    let (server, _) = test_app().await;
    let token = login(&server).await;
    let resp = server
        .post("/api/v1/config/import-opnsense")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({ "xml": MEDIUM_FIXTURE, "commit_confirm": false }))
        .await;
    resp.assert_status_ok();

    // C2: NAT redirect target/port land in the right columns. List via API.
    let nat = server
        .get("/api/v1/nat")
        .add_header("authorization", format!("Bearer {token}"))
        .await;
    nat.assert_status_ok();
    let body: Value = nat.json();
    let arr = body["data"].as_array().or_else(|| body.as_array()).unwrap();
    let pf = arr
        .iter()
        .find(|n| n["nat_type"] == "dnat")
        .expect("imported port-forward DNAT rule should exist");
    // redirect_addr should be a bare IP, NOT "10.0.0.10:443".
    let redirect_addr = pf["redirect"]["address"].as_str().unwrap_or("");
    assert!(
        !redirect_addr.contains(':'),
        "redirect_addr must not include port: {redirect_addr}"
    );
    assert_eq!(pf["redirect"]["port"]["start"].as_u64(), Some(443));
}

#[tokio::test]
async fn import_default_does_not_change_dns_or_hostname() {
    // Audit C4 + H1: default import leaves system settings alone. The user
    // must opt in via `import_system_settings: true`.
    let (server, _) = test_app().await;
    let token = login(&server).await;

    let resp = server
        .post("/api/v1/config/import-opnsense")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({ "xml": MEDIUM_FIXTURE, "commit_confirm": false }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["applied"]["dns_servers"], 0, "DNS not applied without opt-in");
    assert_eq!(body["applied"]["hostname"], false, "hostname not applied without opt-in");
}

#[tokio::test]
async fn import_with_system_settings_opt_in_applies_them() {
    let (server, _) = test_app().await;
    let token = login(&server).await;

    let resp = server
        .post("/api/v1/config/import-opnsense")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "xml": MEDIUM_FIXTURE,
            "commit_confirm": false,
            "import_system_settings": true,
        }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["applied"]["dns_servers"], 2, "both DNS upstreams applied");
    assert_eq!(body["applied"]["hostname"], true, "hostname applied");
}

#[tokio::test]
async fn import_refuses_when_commit_confirm_already_active() {
    // Audit H5: stacking a second commit-confirm window silently dropped the
    // first timer. Importer now refuses with 409.
    let (server, _) = test_app().await;
    let token = login(&server).await;

    // First import arms commit-confirm.
    let first = server
        .post("/api/v1/config/import-opnsense")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "xml": MEDIUM_FIXTURE,
            "commit_confirm": true,
        }))
        .await;
    first.assert_status_ok();

    // Second import should be refused.
    let second = server
        .post("/api/v1/config/import-opnsense")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "xml": MEDIUM_FIXTURE,
            "commit_confirm": true,
        }))
        .await;
    assert_eq!(second.status_code(), StatusCode::CONFLICT);

    // Clean up the global commit-confirm state so unrelated tests aren't
    // left with stale active state in this process.
    let _ = server
        .post("/api/v1/config/commit-confirm/confirm")
        .add_header("authorization", format!("Bearer {token}"))
        .await;
}

#[tokio::test]
async fn imported_ipv6_rule_round_trips_through_config_history() {
    // Audit H6: the rules table has ip_version/src_invert/dst_invert columns,
    // but they only matter if `RuleConfig` (used by snapshot/restore) carries
    // them. Without that round-trip the auto-snapshot middleware silently
    // demotes IPv6 rules back to "both" on the very next mutation.
    let (server, _) = test_app().await;
    let token = login(&server).await;

    let resp = server
        .post("/api/v1/config/import-opnsense")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "xml": MEDIUM_FIXTURE,
            "interface_map": { "lan": "eth0" },
            "commit_confirm": false,
        }))
        .await;
    resp.assert_status_ok();

    // History was the *pre-import* state (empty) — make a fresh snapshot
    // post-import that captures the imported rules and verify ip_version
    // survives the FirewallConfig round-trip.
    let save = server
        .post("/api/v1/config/save")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({ "comment": "post-import" }))
        .await;
    save.assert_status_ok();
    let history_list = server
        .get("/api/v1/config/history?limit=5")
        .add_header("authorization", format!("Bearer {token}"))
        .await;
    let body: Value = history_list.json();
    let arr = body["data"].as_array().or_else(|| body.as_array()).unwrap();
    let latest = arr
        .iter()
        .filter_map(|v| v["version"].as_i64())
        .max()
        .unwrap();
    let v = server
        .get(&format!("/api/v1/config/version?version={latest}"))
        .add_header("authorization", format!("Bearer {token}"))
        .await;
    v.assert_status_ok();
    let cfg: Value = v.json();
    let rules = cfg["rules"].as_array().expect("rules array in snapshot");
    let ssh = rules
        .iter()
        .find(|r| r["label"].as_str().unwrap_or("").contains("SSH"))
        .expect("imported SSH rule in snapshot");
    assert_eq!(ssh["ip_version"], "inet6", "ip_version round-trips through FirewallConfig");
}

#[tokio::test]
async fn import_floating_rule_splits_per_interface() {
    let (server, _) = test_app().await;
    let token = login(&server).await;
    let resp = server
        .post("/api/v1/config/import-opnsense")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "xml": MEDIUM_FIXTURE,
            "interface_map": { "wan": "eth0", "lan": "eth1" },
            "commit_confirm": false,
        }))
        .await;
    resp.assert_status_ok();

    let list = server
        .get("/api/v1/rules")
        .add_header("authorization", format!("Bearer {token}"))
        .await;
    let body: Value = list.json();
    let arr = body["data"].as_array().or_else(|| body.as_array()).unwrap();
    // H4: floating rule had `<interface>wan,lan</interface>` and should have
    // landed as two rules, one per mapped interface.
    let floating: Vec<&Value> = arr
        .iter()
        .filter(|r| r["label"].as_str().unwrap_or("").contains("floating"))
        .collect();
    assert_eq!(floating.len(), 2, "expected 2 floating rules (one per iface), got {floating:?}");
    let ifaces: std::collections::HashSet<&str> = floating
        .iter()
        .filter_map(|r| r["interface"].as_str())
        .collect();
    assert!(ifaces.contains("eth0"));
    assert!(ifaces.contains("eth1"));
}

#[tokio::test]
async fn import_skips_unresolved_dynamic_route() {
    let (server, _) = test_app().await;
    let token = login(&server).await;
    let xml = r#"<?xml version="1.0"?>
<opnsense>
  <gateways>
    <gateway_item>
      <name>WAN_DHCP</name>
      <interface>wan</interface>
      <gateway>dynamic</gateway>
    </gateway_item>
  </gateways>
  <staticroutes>
    <route>
      <network>192.0.2.0/24</network>
      <gateway>WAN_DHCP</gateway>
    </route>
  </staticroutes>
</opnsense>"#;
    let resp = server
        .post("/api/v1/config/import-opnsense")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({ "xml": xml, "commit_confirm": false }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["applied"]["static_routes"], 0);
    let skipped = body["skipped"].as_array().unwrap();
    assert!(
        skipped.iter().any(|s| s.as_str().unwrap_or("").contains("WAN_DHCP")),
        "dynamic gateway should be reported in skipped: {skipped:?}"
    );
}

#[tokio::test]
async fn preview_returns_dry_run_plan_with_translated_items() {
    let (server, _) = test_app().await;
    let token = login(&server).await;
    let resp = server
        .post("/api/v1/config/preview-opnsense")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "xml": MEDIUM_FIXTURE,
            "interface_map": { "wan": "eth0", "lan": "eth1" },
        }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();

    let plan = &body["plan"];
    let rules = plan["rules"].as_array().expect("plan.rules");
    let nat = plan["nat"].as_array().expect("plan.nat");
    let aliases = plan["aliases"].as_array().expect("plan.aliases");
    let routes = plan["routes"].as_array().expect("plan.routes");

    // The medium fixture has 4 rules — one is a floating rule across 2
    // interfaces so the plan should show 5 entries.
    assert_eq!(rules.len(), 5, "expected 5 plan rules (one floating splits): {rules:?}");
    // The lanip-keyword rule should carry a skip_reason.
    let lanip_rule = rules
        .iter()
        .find(|r| r["label"].as_str().unwrap_or("").contains("lanip"))
        .expect("captive-portal rule with lanip keyword");
    assert!(lanip_rule["skip_reason"].is_string());

    // Aliases plan reflects both fixture aliases.
    assert_eq!(aliases.len(), 2);
    // NAT plan covers port-forward + outbound.
    assert!(nat.iter().any(|n| n["kind"] == "dnat"));
    assert!(nat.iter().any(|n| n["kind"] == "masquerade" || n["kind"] == "snat"));
    // One route is in the fixture.
    assert_eq!(routes.len(), 1);
}

#[tokio::test]
async fn import_creates_pre_import_snapshot() {
    let (server, _) = test_app().await;
    let token = login(&server).await;
    let resp = server
        .post("/api/v1/config/import-opnsense")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({ "xml": MEDIUM_FIXTURE, "commit_confirm": false }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    let version = body["pre_import_version"].as_i64().expect("snapshot version");

    // H6: snapshot is in config history.
    let history = server
        .get("/api/v1/config/history")
        .add_header("authorization", format!("Bearer {token}"))
        .await;
    history.assert_status_ok();
    let body: Value = history.json();
    let arr = body["data"].as_array().or_else(|| body.as_array()).unwrap();
    assert!(
        arr.iter().any(|v| v["version"] == version),
        "pre_import snapshot version {version} not in history"
    );
}
