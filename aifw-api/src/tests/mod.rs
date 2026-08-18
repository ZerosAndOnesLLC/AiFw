//! API integration tests, split by area (#447). Shared fixtures (test app,
//! login helpers, cookie helpers) live here; each submodule `use super::*;`.

pub(super) use axum::http::StatusCode;

pub(super) use axum_test::TestServer;

pub(super) use serde_json::{Value, json};

pub(super) use crate::auth::AuthSettings;

pub(super) use aifw_common::{ClusterNode, ClusterRole};

pub(super) async fn test_app() -> (TestServer, AuthSettings) {
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
    let server = TestServer::new(app);
    (server, auth_settings)
}

pub(super) async fn create_user_and_login(server: &TestServer) -> String {
    // Create user
    server
        .post("/api/v1/auth/register")
        .json(&json!({
            "username": "admin",
            "password": "TestPass123"
        }))
        .await;

    // Login — now returns tokens object
    let resp = server
        .post("/api/v1/auth/login")
        .json(&json!({
            "username": "admin",
            "password": "TestPass123"
        }))
        .await;

    let body: Value = resp.json();
    // New format: { tokens: { access_token, refresh_token, ... }, totp_required: false }
    body["tokens"]["access_token"].as_str().unwrap().to_string()
}

/// Build a test server whose AuthSettings override `password_min_length`.
pub(super) async fn test_app_min_len(min_length: u32) -> TestServer {
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
        password_min_length: min_length,
    };
    let state = crate::create_app_state_in_memory(auth_settings)
        .await
        .unwrap();
    TestServer::new(crate::build_router(state, None, "*", false))
}

/// Build a test server with a specific CORS/WS origin allow-list.
pub(super) async fn test_app_cors(origins: &str) -> TestServer {
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
    let state = crate::create_app_state_in_memory(auth_settings)
        .await
        .unwrap();
    TestServer::new(crate::build_router(state, None, origins, false))
}

/// Helper: create admin + a viewer user, return (admin_token, viewer_token)
pub(super) async fn create_admin_and_viewer(server: &TestServer) -> (String, String) {
    let admin_token = create_user_and_login(server).await;

    // Admin creates a viewer user
    server
        .post("/api/v1/auth/users")
        .authorization_bearer(&admin_token)
        .json(&json!({"username": "viewer", "password": "ViewPass123", "role": "viewer"}))
        .await;

    // Login as viewer
    let resp = server
        .post("/api/v1/auth/login")
        .json(&json!({"username": "viewer", "password": "ViewPass123"}))
        .await;
    let body: Value = resp.json();
    let viewer_token = body["tokens"]["access_token"].as_str().unwrap().to_string();

    (admin_token, viewer_token)
}

pub(super) fn plain_auth_settings() -> AuthSettings {
    AuthSettings {
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
    }
}

pub(super) fn any_tcp_rule() -> aifw_common::Rule {
    aifw_common::Rule::new(
        aifw_common::Action::Pass,
        aifw_common::Direction::In,
        aifw_common::Protocol::Tcp,
        aifw_common::RuleMatch {
            src_addr: aifw_common::Address::Any,
            src_port: None,
            dst_addr: aifw_common::Address::Any,
            dst_port: None,
        },
    )
}

pub(super) fn ipsec_tunnel_body() -> Value {
    json!({
        "name": "site-a",
        "remote_addr": "203.0.113.10",
        "psk": "correct-horse-battery-staple",
        "local_ts": ["10.0.0.0/24"],
        "remote_ts": ["10.1.0.0/24"],
    })
}

/// Collect the `Set-Cookie` header values from a response.
pub(super) fn set_cookies(resp: &axum_test::TestResponse) -> Vec<String> {
    resp.headers()
        .get_all(axum::http::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok().map(str::to_string))
        .collect()
}

/// Extract `<name>=<value>` (value only) from a `Set-Cookie` list.
pub(super) fn cookie_from(cookies: &[String], name: &str) -> String {
    cookies
        .iter()
        .find(|c| c.starts_with(&format!("{name}=")))
        .and_then(|c| c.split(';').next())
        .and_then(|kv| kv.split('=').nth(1))
        .unwrap_or_else(|| panic!("cookie {name} not found in {cookies:?}"))
        .to_string()
}

/// Register the first user and log in, returning the raw `Set-Cookie`
/// values from the login response.
pub(super) async fn login_cookies(server: &TestServer) -> Vec<String> {
    server
        .post("/api/v1/auth/register")
        .json(&json!({"username": "admin", "password": "TestPass123"}))
        .await;
    let resp = server
        .post("/api/v1/auth/login")
        .json(&json!({"username": "admin", "password": "TestPass123"}))
        .await;
    resp.assert_status_ok();
    set_cookies(&resp)
}

mod auth;
mod backup;
mod cluster;
mod cookies;
mod rbac;
mod resources;
mod rules;
mod system;
mod vpn_pki;
