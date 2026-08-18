use super::*;

#[tokio::test]
async fn test_status() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let resp = server
        .get("/api/v1/status")
        .authorization_bearer(&token)
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert!(body["pf_running"].as_bool().is_some());
    assert!(body["aifw_rules"].as_u64().is_some());
}

#[tokio::test]
async fn test_connections() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let resp = server
        .get("/api/v1/connections")
        .authorization_bearer(&token)
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert!(body["data"].as_array().is_some());
}

#[tokio::test]
async fn test_reload() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let resp = server
        .post("/api/v1/reload")
        .authorization_bearer(&token)
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    // On non-FreeBSD, VLAN apply fails so we get "Partial reload" or "Changes applied"
    assert!(
        body["message"].as_str().unwrap().contains("applied")
            || body["message"].as_str().unwrap().contains("reload")
    );
}

#[tokio::test]
async fn test_metrics() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let resp = server
        .get("/api/v1/metrics")
        .authorization_bearer(&token)
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert!(body["pf_running"].as_bool().is_some());
    assert!(body["aifw_rules_total"].as_u64().is_some());
}

#[tokio::test]
async fn test_logs() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    // Create a rule so there's an audit entry
    server
        .post("/api/v1/rules")
        .authorization_bearer(&token)
        .json(&json!({
            "action": "block",
            "direction": "in",
            "protocol": "any",
        }))
        .await;

    let resp = server
        .get("/api/v1/logs")
        .authorization_bearer(&token)
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    let entries = body["data"].as_array().unwrap();
    assert!(!entries.is_empty());
}

/// SEC-H4 (#289): the per-provider `tls_insecure` opt-in must persist and
/// round-trip through GET /settings/ai (default false).
#[tokio::test]
async fn test_ai_tls_insecure_roundtrip() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let ollama = |body: &Value| -> Value {
        body["providers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|p| p["provider"] == "ollama")
            .unwrap()
            .clone()
    };

    // Default: not configured → tls_insecure false.
    let resp = server
        .get("/api/v1/settings/ai")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    assert_eq!(ollama(&resp.json::<Value>())["tls_insecure"], false);

    // Opt in.
    server
        .put("/api/v1/settings/ai")
        .authorization_bearer(&token)
        .json(&json!({
            "provider": "ollama",
            "endpoint": "http://127.0.0.1:11434",
            "tls_insecure": true
        }))
        .await
        .assert_status_ok();

    let resp = server
        .get("/api/v1/settings/ai")
        .authorization_bearer(&token)
        .await;
    let cfg = ollama(&resp.json::<Value>());
    assert_eq!(cfg["tls_insecure"], true);
    assert_eq!(cfg["endpoint"], "http://127.0.0.1:11434");

    // Opt back out.
    server
        .put("/api/v1/settings/ai")
        .authorization_bearer(&token)
        .json(&json!({"provider": "ollama", "tls_insecure": false}))
        .await
        .assert_status_ok();
    let resp = server
        .get("/api/v1/settings/ai")
        .authorization_bearer(&token)
        .await;
    assert_eq!(ollama(&resp.json::<Value>())["tls_insecure"], false);
}

/// SEC-H10 (#295): the WS/SSE Origin policy.
#[test]
fn test_origin_allowed_policy() {
    // No policy (CORS = "*"): any origin, and no origin, allowed.
    assert!(crate::origin_allowed(Some("https://evil.test"), &None));
    assert!(crate::origin_allowed(None, &None));

    // Allow-list: only listed origins; case-insensitive; native (no
    // Origin) clients still allowed.
    let allow = Some(vec!["https://ui.example".to_string()]);
    assert!(crate::origin_allowed(Some("https://ui.example"), &allow));
    assert!(crate::origin_allowed(Some("HTTPS://UI.EXAMPLE"), &allow));
    assert!(crate::origin_allowed(None, &allow));
    assert!(!crate::origin_allowed(Some("https://evil.example"), &allow));
}

/// SEC-H10 (#295): a WebSocket upgrade from a disallowed browser Origin is
/// rejected (403) before it reaches the handler, even with valid auth.
#[tokio::test]
async fn test_ws_rejects_disallowed_origin() {
    use axum::http::{HeaderName, HeaderValue};
    let server = test_app_cors("https://ui.example").await;
    let token = create_user_and_login(&server).await;

    let resp = server
        .get("/api/v1/ws")
        .authorization_bearer(&token)
        .add_header(
            HeaderName::from_static("origin"),
            HeaderValue::from_static("https://evil.example"),
        )
        .await;
    resp.assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_multiwan_default_instance_seeded() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let resp = server
        .get("/api/v1/multiwan/instances")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    let list = body["data"].as_array().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0]["name"], "default");
    assert_eq!(list[0]["fib_number"], 0);
    assert_eq!(list[0]["mgmt_reachable"], true);
}

#[tokio::test]
async fn test_multiwan_create_and_list_instance() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let resp = server
        .post("/api/v1/multiwan/instances")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "wan2",
            "fib_number": 0,  // mock has 1 FIB by default — this should fail
            "description": "WAN 2"
        }))
        .await;
    // FIB 0 collides with default seed -> bad request
    resp.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_multiwan_cannot_delete_default() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let list = server
        .get("/api/v1/multiwan/instances")
        .authorization_bearer(&token)
        .await
        .json::<Value>();
    let default_id = list["data"][0]["id"].as_str().unwrap().to_string();

    let resp = server
        .delete(&format!("/api/v1/multiwan/instances/{default_id}"))
        .authorization_bearer(&token)
        .await;
    resp.assert_status(StatusCode::CONFLICT);
}

#[tokio::test]
async fn get_system_general_returns_defaults() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;
    let resp = server
        .get("/api/v1/system/general")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["timezone"], "UTC");
    assert!(body["hostname"].is_string());
    assert!(body["domain"].is_string());
}

#[tokio::test]
async fn put_system_general_round_trips() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let resp = server
        .put("/api/v1/system/general")
        .authorization_bearer(&token)
        .json(&json!({ "hostname": "myfw", "domain": "home.lan", "timezone": "America/Chicago" }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["ok"], true);

    let resp2 = server
        .get("/api/v1/system/general")
        .authorization_bearer(&token)
        .await;
    let back: Value = resp2.json();
    assert_eq!(back["hostname"], "myfw");
    assert_eq!(back["domain"], "home.lan");
    assert_eq!(back["timezone"], "America/Chicago");
}

#[tokio::test]
async fn put_system_general_rejects_invalid_hostname() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;
    let resp = server
        .put("/api/v1/system/general")
        .authorization_bearer(&token)
        .json(&json!({ "hostname": "has.dot", "domain": "", "timezone": "UTC" }))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn get_system_general_requires_auth() {
    let (server, _) = test_app().await;
    let resp = server.get("/api/v1/system/general").await;
    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_multiwan_fibs_endpoint() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let resp = server
        .get("/api/v1/multiwan/fibs")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    // mock backend reports 1 FIB
    assert_eq!(body["data"]["net_fibs"], 1);
    assert_eq!(body["data"]["used"].as_array().unwrap()[0], 0);
}

#[tokio::test]
async fn system_banner_round_trip() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let resp = server
        .put("/api/v1/system/banner")
        .authorization_bearer(&token)
        .json(&json!({ "login_banner": "Authorized only", "motd": "Welcome" }))
        .await;
    resp.assert_status_ok();

    let resp = server
        .get("/api/v1/system/banner")
        .authorization_bearer(&token)
        .await;
    let body: Value = resp.json();
    assert_eq!(body["login_banner"], "Authorized only");
    assert_eq!(body["motd"], "Welcome");
}

#[tokio::test]
async fn system_banner_rejects_oversize() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let big = "x".repeat(9 * 1024);
    let resp = server
        .put("/api/v1/system/banner")
        .authorization_bearer(&token)
        .json(&json!({ "login_banner": big, "motd": "" }))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn system_ssh_defaults_on_fresh_install() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let resp = server
        .get("/api/v1/system/ssh")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["enabled"], true);
    assert_eq!(body["port"], 22);
    assert_eq!(body["password_auth"], false);
    assert_eq!(body["permit_root_login"], false);
}

#[tokio::test]
async fn system_ssh_put_rejects_port_zero() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;
    let resp = server
        .put("/api/v1/system/ssh")
        .authorization_bearer(&token)
        .json(&json!({ "enabled": true, "port": 0, "password_auth": false, "permit_root_login": false }))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn system_ssh_put_round_trips_and_reports_restart() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let resp = server
        .put("/api/v1/system/ssh")
        .authorization_bearer(&token)
        .json(&json!({ "enabled": true, "port": 2222, "password_auth": false, "permit_root_login": false }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["requires_service_restart"], "sshd");

    let resp = server
        .get("/api/v1/system/ssh")
        .authorization_bearer(&token)
        .await;
    let back: Value = resp.json();
    assert_eq!(back["port"], 2222);
}

#[tokio::test]
async fn system_console_defaults_and_round_trip() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let resp = server
        .get("/api/v1/system/console")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["kind"], "video");
    assert_eq!(body["baud"], 115200);

    let resp = server
        .put("/api/v1/system/console")
        .authorization_bearer(&token)
        .json(&json!({ "kind": "serial", "baud": 115200 }))
        .await;
    resp.assert_status_ok();
    let report: Value = resp.json();
    assert_eq!(report["requires_reboot"], true);

    let resp = server
        .get("/api/v1/system/console")
        .authorization_bearer(&token)
        .await;
    let back: Value = resp.json();
    assert_eq!(back["kind"], "serial");
}

#[tokio::test]
async fn system_console_rejects_bad_baud() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;
    let resp = server
        .put("/api/v1/system/console")
        .authorization_bearer(&token)
        .json(&json!({ "kind": "video", "baud": 4242 }))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn system_console_rejects_bad_kind() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;
    // "braille" is not a ConsoleKind variant — serde rejects at deserialize with 400.
    let resp = server
        .put("/api/v1/system/console")
        .authorization_bearer(&token)
        .json(&json!({ "kind": "braille", "baud": 115200 }))
        .await;
    // Axum's JSON extractor returns 422 for unknown enum variants at deserialize time.
    // Both 400 and 422 are acceptable for bad JSON shape.
    let status = resp.status_code().as_u16();
    assert!(
        status == 400 || status == 422,
        "expected 400 or 422, got {}",
        status
    );
}

#[tokio::test]
async fn system_info_returns_shape() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let resp = server
        .get("/api/v1/system/info")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert!(body["os_version"].is_string());
    assert!(body["cpu_count"].as_u64().unwrap() >= 1);
    assert!(body["mem_total_bytes"].as_u64().unwrap() > 0);
    assert!(body["load_avg"].is_array());
    assert_eq!(body["load_avg"].as_array().unwrap().len(), 3);
    assert!(body["temperatures_c"].is_array());
}

#[tokio::test]
async fn system_timezones_non_empty_includes_utc() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let resp = server
        .get("/api/v1/system/timezones")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Vec<String> = resp.json();
    assert!(!body.is_empty());
    assert!(body.iter().any(|z| z == "UTC"));
}

#[tokio::test]
async fn test_log_rotation_settings_defaults_and_roundtrip() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    // Defaults + status shape
    let resp = server
        .get("/api/v1/settings/log-rotation")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["config"]["max_size_mb"], 5);
    assert_eq!(body["config"]["keep"], 7);
    assert_eq!(body["config"]["compression"], "gzip");
    assert_eq!(body["limits"]["max_size_mb"], 500);
    assert_eq!(
        body["logs"].as_array().map(|l| l.len()),
        Some(aifw_core::log_rotation::MANAGED_LOGS.len())
    );
    assert!(body["logs"][0]["service"].is_string());

    // Save + read back
    let cfg = json!({"max_size_mb": 25, "keep": 3, "compression": "zstd"});
    let resp = server
        .put("/api/v1/settings/log-rotation")
        .authorization_bearer(&token)
        .json(&cfg)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["config"]["max_size_mb"], 25);
    assert_eq!(body["config"]["compression"], "zstd");
    let resp = server
        .get("/api/v1/settings/log-rotation")
        .authorization_bearer(&token)
        .await;
    let body: Value = resp.json();
    assert_eq!(body["config"]["keep"], 3);

    // Out of range is rejected and does not persist
    for bad in [
        json!({"max_size_mb": 0, "keep": 3, "compression": "gzip"}),
        json!({"max_size_mb": 501, "keep": 3, "compression": "gzip"}),
        json!({"max_size_mb": 10, "keep": 51, "compression": "gzip"}),
    ] {
        let resp = server
            .put("/api/v1/settings/log-rotation")
            .authorization_bearer(&token)
            .json(&bad)
            .await;
        resp.assert_status(StatusCode::BAD_REQUEST);
    }
    // Unknown compression fails deserialisation (422 from axum's Json)
    let resp = server
        .put("/api/v1/settings/log-rotation")
        .authorization_bearer(&token)
        .json(&json!({"max_size_mb": 10, "keep": 3, "compression": "lz4"}))
        .await;
    assert!(resp.status_code().is_client_error());
    let resp = server
        .get("/api/v1/settings/log-rotation")
        .authorization_bearer(&token)
        .await;
    assert_eq!(resp.json::<Value>()["config"]["max_size_mb"], 25);

    // Config export carries the section
    let resp = server
        .get("/api/v1/config/export")
        .authorization_bearer(&token)
        .await;
    if resp.status_code().is_success() {
        let exported: Value = resp.json();
        assert_eq!(exported["config"]["log_rotation"]["max_size_mb"], 25);
    }

    // Unauthenticated read is rejected
    let resp = server.get("/api/v1/settings/log-rotation").await;
    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_syslog_settings_defaults_and_roundtrip() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    // Defaults
    let resp = server
        .get("/api/v1/settings/syslog")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["enabled"], false);
    assert_eq!(body["port"], 514);
    assert_eq!(body["transport"], "udp");
    assert_eq!(body["format"], "rfc3164");
    assert_eq!(body["facility"], 16);

    // Save a full config and read it back
    let cfg = json!({
        "enabled": true,
        "host": "192.0.2.99",
        "port": 5514,
        "transport": "tcp",
        "format": "rfc5424",
        "facility": 17,
        "hostname_override": "fw-test",
        "pf_enabled": true,
        "ids_enabled": false,
        "app_enabled": true,
        "app_min_level": "warn",
        "disable_local": false
    });
    let resp = server
        .put("/api/v1/settings/syslog")
        .authorization_bearer(&token)
        .json(&cfg)
        .await;
    resp.assert_status_ok();

    let resp = server
        .get("/api/v1/settings/syslog")
        .authorization_bearer(&token)
        .await;
    let body: Value = resp.json();
    assert_eq!(body["host"], "192.0.2.99");
    assert_eq!(body["transport"], "tcp");
    assert_eq!(body["format"], "rfc5424");
    assert_eq!(body["pf_enabled"], true);
    assert_eq!(body["app_min_level"], "warn");

    // Invalid facility is rejected
    let mut bad = cfg.clone();
    bad["facility"] = json!(42);
    let resp = server
        .put("/api/v1/settings/syslog")
        .authorization_bearer(&token)
        .json(&bad)
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    // Enabled without a host is rejected
    let mut no_host = cfg.clone();
    no_host["host"] = json!("");
    let resp = server
        .put("/api/v1/settings/syslog")
        .authorization_bearer(&token)
        .json(&no_host)
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    // Unauthenticated read is rejected
    let resp = server.get("/api/v1/settings/syslog").await;
    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_syslog_test_endpoint_delivers_udp() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = sock.local_addr().unwrap().port();

    // Draft config in the body — nothing saved, forwarding disabled.
    let resp = server
        .post("/api/v1/settings/syslog/test")
        .authorization_bearer(&token)
        .json(&json!({
            "enabled": false,
            "host": "127.0.0.1",
            "port": port,
            "transport": "udp",
            "format": "rfc3164",
            "facility": 16
        }))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["ok"], true, "body: {body}");

    let mut buf = [0u8; 1024];
    let (n, _) = tokio::time::timeout(std::time::Duration::from_secs(5), sock.recv_from(&mut buf))
        .await
        .expect("test datagram should arrive")
        .unwrap();
    let text = std::str::from_utf8(&buf[..n]).unwrap();
    assert!(
        text.contains("AiFw remote syslog test message"),
        "got: {text}"
    );

    // Status endpoint responds with per-process counters; the API
    // process's live row is always present.
    let resp = server
        .get("/api/v1/settings/syslog/status")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    let rows = body.as_array().expect("status is a per-process array");
    let api_row = rows
        .iter()
        .find(|r| r["process"] == "aifw-api")
        .expect("aifw-api row present");
    assert!(api_row["sent"].is_u64());
    assert!(api_row["dropped"].is_u64());

    // Test endpoint without a body falls back to the saved config —
    // nothing saved yet, so it reports a clean failure, not a 4xx.
    let resp = server
        .post("/api/v1/settings/syslog/test")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["ok"], false);
}
