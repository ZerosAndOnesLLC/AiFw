//! CLI v2 phase 0: API keys are bound to the user who mints them, can be
//! narrowed to a role, expire, and can be listed and revoked.

use super::*;

/// State + server so tests can poke the DB directly.
async fn app_with_pool() -> (TestServer, sqlx::SqlitePool) {
    let state = crate::create_app_state_in_memory(plain_auth_settings())
        .await
        .unwrap();
    let pool = state.pool.clone();
    (
        TestServer::new(crate::build_router(state, None, "*", false)),
        pool,
    )
}

async fn create_user(server: &TestServer, admin: &str, username: &str, role: &str) -> String {
    let resp = server
        .post("/api/v1/auth/users")
        .authorization_bearer(admin)
        .json(&json!({"username": username, "password": "LongEnough123!", "role": role}))
        .await;
    resp.assert_status(StatusCode::CREATED);
    let body: Value = resp.json();
    body["data"]["id"].as_str().unwrap().to_string()
}

async fn login(server: &TestServer, username: &str) -> String {
    let resp = server
        .post("/api/v1/auth/login")
        .json(&json!({"username": username, "password": "LongEnough123!"}))
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    body["tokens"]["access_token"].as_str().unwrap().to_string()
}

async fn mint(server: &TestServer, token: &str, body: Value) -> axum_test::TestResponse {
    server
        .post("/api/v1/auth/api-keys")
        .authorization_bearer(token)
        .json(&body)
        .await
}

fn api_key_header(key: &str) -> (axum::http::HeaderName, axum::http::HeaderValue) {
    (
        axum::http::header::AUTHORIZATION,
        axum::http::HeaderValue::from_str(&format!("ApiKey {key}")).unwrap(),
    )
}

async fn me_with_key(server: &TestServer, key: &str) -> axum_test::TestResponse {
    let (n, v) = api_key_header(key);
    server.get("/api/v1/auth/me").add_header(n, v).await
}

#[tokio::test]
async fn key_is_bound_to_the_caller_not_the_first_user() {
    let (server, _) = app_with_pool().await;
    let admin = create_user_and_login(&server).await;
    create_user(&server, &admin, "ops", "operator").await;
    let ops = login(&server, "ops").await;

    let resp = mint(&server, &ops, json!({"name": "ops-cli"})).await;
    resp.assert_status(StatusCode::CREATED);
    let key = resp.json::<Value>()["key"].as_str().unwrap().to_string();
    assert!(key.starts_with("aifw_"));

    let me: Value = me_with_key(&server, &key).await.json();
    assert_eq!(me["username"], "ops");
    assert_eq!(me["role"], "operator");
    // Operators lack users:write; an admin-bound key would have it.
    let perms: Vec<&str> = me["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(!perms.contains(&"users:write"));
}

#[tokio::test]
async fn minting_for_another_user_needs_users_write() {
    let (server, _) = app_with_pool().await;
    let admin = create_user_and_login(&server).await;
    let ops_id = create_user(&server, &admin, "ops", "operator").await;
    let viewer_id = create_user(&server, &admin, "view", "viewer").await;
    let ops = login(&server, "ops").await;

    mint(&server, &ops, json!({"name": "x", "user_id": viewer_id}))
        .await
        .assert_status(StatusCode::FORBIDDEN);

    let resp = mint(
        &server,
        &admin,
        json!({"name": "for-ops", "user_id": ops_id}),
    )
    .await;
    resp.assert_status(StatusCode::CREATED);
    let body: Value = resp.json();
    assert_eq!(body["user_id"], ops_id);
    let me: Value = me_with_key(&server, body["key"].as_str().unwrap())
        .await
        .json();
    assert_eq!(me["username"], "ops");

    // Unknown owner.
    mint(
        &server,
        &admin,
        json!({"name": "x", "user_id": "00000000-0000-0000-0000-000000000000"}),
    )
    .await
    .assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn role_narrowed_key_is_limited_to_the_role() {
    let (server, _) = app_with_pool().await;
    let admin = create_user_and_login(&server).await;

    let resp = mint(
        &server,
        &admin,
        json!({"name": "ro", "role_id": "builtin-viewer"}),
    )
    .await;
    resp.assert_status(StatusCode::CREATED);
    let body: Value = resp.json();
    assert_eq!(body["role_id"], "builtin-viewer");
    let key = body["key"].as_str().unwrap();

    let me: Value = me_with_key(&server, key).await.json();
    assert_eq!(me["role"], "viewer");

    let (n, v) = api_key_header(key);
    server
        .get("/api/v1/rules")
        .add_header(n.clone(), v.clone())
        .await
        .assert_status_ok();
    server
        .post("/api/v1/rules")
        .add_header(n, v)
        .json(&serde_json::to_value(any_tcp_rule()).unwrap())
        .await
        .assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn key_role_must_be_a_subset_of_owner_and_caller() {
    let (server, _) = app_with_pool().await;
    let admin = create_user_and_login(&server).await;
    let ops_id = create_user(&server, &admin, "ops", "operator").await;
    let ops = login(&server, "ops").await;

    // Operator can't widen their own key to admin.
    mint(
        &server,
        &ops,
        json!({"name": "x", "role_id": "builtin-admin"}),
    )
    .await
    .assert_status(StatusCode::FORBIDDEN);
    // Admin can't mint an operator a key wider than the operator.
    mint(
        &server,
        &admin,
        json!({"name": "x", "user_id": ops_id, "role_id": "builtin-admin"}),
    )
    .await
    .assert_status(StatusCode::FORBIDDEN);
    // Narrower is fine.
    mint(
        &server,
        &ops,
        json!({"name": "x", "role_id": "builtin-viewer"}),
    )
    .await
    .assert_status(StatusCode::CREATED);
    // Unknown role.
    mint(
        &server,
        &ops,
        json!({"name": "x", "role_id": "no-such-role"}),
    )
    .await
    .assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn deleted_key_role_fails_closed() {
    let (server, pool) = app_with_pool().await;
    let admin = create_user_and_login(&server).await;
    let resp = server
        .post("/api/v1/auth/roles")
        .authorization_bearer(&admin)
        .json(&json!({"name": "rules-reader", "permissions": ["rules:read"]}))
        .await;
    resp.assert_status(StatusCode::CREATED);
    let role_id = resp.json::<Value>()["id"].as_str().unwrap().to_string();

    let key = mint(&server, &admin, json!({"name": "k", "role_id": role_id}))
        .await
        .json::<Value>()["key"]
        .as_str()
        .unwrap()
        .to_string();
    let (n, v) = api_key_header(&key);
    server
        .get("/api/v1/rules")
        .add_header(n.clone(), v.clone())
        .await
        .assert_status_ok();

    sqlx::query("DELETE FROM roles WHERE id = ?1")
        .bind(&role_id)
        .execute(&pool)
        .await
        .unwrap();
    server
        .get("/api/v1/rules")
        .add_header(n, v)
        .await
        .assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn expired_key_is_rejected_and_lifetime_is_validated() {
    let (server, pool) = app_with_pool().await;
    let admin = create_user_and_login(&server).await;

    for bad in [0, crate::auth::MAX_KEY_LIFETIME_DAYS + 1] {
        mint(
            &server,
            &admin,
            json!({"name": "x", "expires_in_days": bad}),
        )
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    }

    let body: Value = mint(
        &server,
        &admin,
        json!({"name": "short", "expires_in_days": 1}),
    )
    .await
    .json();
    assert!(body["expires_at"].as_str().is_some());
    let key = body["key"].as_str().unwrap();
    me_with_key(&server, key).await.assert_status_ok();

    sqlx::query("UPDATE api_keys SET expires_at = '2000-01-01T00:00:00Z' WHERE id = ?1")
        .bind(body["id"].as_str().unwrap())
        .execute(&pool)
        .await
        .unwrap();
    me_with_key(&server, key)
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    let list: Value = server
        .get("/api/v1/auth/api-keys")
        .authorization_bearer(&admin)
        .await
        .json();
    assert_eq!(list["data"][0]["expired"], true);
}

#[tokio::test]
async fn reserved_and_invalid_names_rejected() {
    let (server, _) = app_with_pool().await;
    let admin = create_user_and_login(&server).await;
    for name in ["aifw-cli-local", "", "   "] {
        mint(&server, &admin, json!({ "name": name }))
            .await
            .assert_status(StatusCode::BAD_REQUEST);
    }
    let long = "x".repeat(129);
    mint(&server, &admin, json!({ "name": long }))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn api_key_cannot_mint_keys() {
    let (server, _) = app_with_pool().await;
    let admin = create_user_and_login(&server).await;
    let key = mint(&server, &admin, json!({"name": "k"}))
        .await
        .json::<Value>()["key"]
        .as_str()
        .unwrap()
        .to_string();
    let (n, v) = api_key_header(&key);
    server
        .post("/api/v1/auth/api-keys")
        .add_header(n, v)
        .json(&json!({"name": "child"}))
        .await
        .assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn list_is_scoped_and_hides_internal_keys() {
    let (server, _) = app_with_pool().await;
    let admin = create_user_and_login(&server).await;
    create_user(&server, &admin, "ops", "operator").await;
    create_user(&server, &admin, "view", "viewer").await;
    let ops = login(&server, "ops").await;
    let view = login(&server, "view").await;

    mint(&server, &admin, json!({"name": "admin-key"})).await;
    mint(&server, &ops, json!({"name": "ops-key"})).await;
    // An internal key that must never show up.
    server
        .post("/api/v1/cluster/loopback-key/generate")
        .authorization_bearer(&admin)
        .await
        .assert_status_ok();

    let names = |v: &Value| -> Vec<String> {
        v["data"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["name"].as_str().unwrap().to_string())
            .collect()
    };

    let own: Value = server
        .get("/api/v1/auth/api-keys")
        .authorization_bearer(&ops)
        .await
        .json();
    assert_eq!(names(&own), vec!["ops-key"]);
    assert!(
        own["data"][0].get("key").is_none(),
        "secret must never be listed"
    );
    assert!(own["data"][0].get("key_hash").is_none());

    let all: Value = server
        .get("/api/v1/auth/api-keys?all=true")
        .authorization_bearer(&admin)
        .await
        .json();
    let mut all_names = names(&all);
    all_names.sort();
    assert_eq!(all_names, vec!["admin-key", "ops-key"]);

    server
        .get("/api/v1/auth/api-keys?all=true")
        .authorization_bearer(&view)
        .await
        .assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn revoke_own_and_others() {
    let (server, pool) = app_with_pool().await;
    let admin = create_user_and_login(&server).await;
    create_user(&server, &admin, "ops", "operator").await;
    let ops = login(&server, "ops").await;

    let ops_key: Value = mint(&server, &ops, json!({"name": "ops-key"})).await.json();
    let admin_key: Value = mint(&server, &admin, json!({"name": "admin-key"}))
        .await
        .json();
    let ops_key_id = ops_key["id"].as_str().unwrap();
    let admin_key_id = admin_key["id"].as_str().unwrap();

    // Operator can't revoke the admin's key.
    server
        .delete(&format!("/api/v1/auth/api-keys/{admin_key_id}"))
        .authorization_bearer(&ops)
        .await
        .assert_status(StatusCode::FORBIDDEN);

    // Operator revokes their own; the key stops working immediately.
    me_with_key(&server, ops_key["key"].as_str().unwrap())
        .await
        .assert_status_ok();
    server
        .delete(&format!("/api/v1/auth/api-keys/{ops_key_id}"))
        .authorization_bearer(&ops)
        .await
        .assert_status_ok();
    me_with_key(&server, ops_key["key"].as_str().unwrap())
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    // Admin can revoke anyone's; unknown ids are 404.
    let ops_key2: Value = mint(&server, &ops, json!({"name": "ops-key2"}))
        .await
        .json();
    server
        .delete(&format!(
            "/api/v1/auth/api-keys/{}",
            ops_key2["id"].as_str().unwrap()
        ))
        .authorization_bearer(&admin)
        .await
        .assert_status_ok();
    server
        .delete("/api/v1/auth/api-keys/nope")
        .authorization_bearer(&admin)
        .await
        .assert_status(StatusCode::NOT_FOUND);

    // Internal keys can't be revoked through this path.
    server
        .post("/api/v1/cluster/loopback-key/generate")
        .authorization_bearer(&admin)
        .await
        .assert_status_ok();
    let (loopback_id,): (String,) =
        sqlx::query_as("SELECT id FROM api_keys WHERE name = 'aifw-daemon-loopback'")
            .fetch_one(&pool)
            .await
            .unwrap();
    server
        .delete(&format!("/api/v1/auth/api-keys/{loopback_id}"))
        .authorization_bearer(&admin)
        .await
        .assert_status(StatusCode::NOT_FOUND);

    // Revocations are audited.
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM user_audit_log WHERE action IN ('api_key_created', 'api_key_revoked')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(n, 5);
}

#[tokio::test]
async fn last_used_is_recorded() {
    let (server, pool) = app_with_pool().await;
    let admin = create_user_and_login(&server).await;
    let body: Value = mint(&server, &admin, json!({"name": "k"})).await.json();
    let id = body["id"].as_str().unwrap();
    let before: (Option<String>,) =
        sqlx::query_as("SELECT last_used_at FROM api_keys WHERE id = ?1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(before.0.is_none());
    me_with_key(&server, body["key"].as_str().unwrap())
        .await
        .assert_status_ok();
    let after: (Option<String>,) =
        sqlx::query_as("SELECT last_used_at FROM api_keys WHERE id = ?1")
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(after.0.is_some());
}

#[tokio::test]
async fn deleting_a_user_removes_their_keys() {
    let (server, _) = app_with_pool().await;
    let admin = create_user_and_login(&server).await;
    let ops_id = create_user(&server, &admin, "ops", "operator").await;
    let ops = login(&server, "ops").await;
    let key = mint(&server, &ops, json!({"name": "k"}))
        .await
        .json::<Value>()["key"]
        .as_str()
        .unwrap()
        .to_string();
    server
        .delete(&format!("/api/v1/auth/users/{ops_id}"))
        .authorization_bearer(&admin)
        .await
        .assert_status_ok();
    me_with_key(&server, &key)
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

/// The second login factor shares the login limiter: guessing TOTP codes
/// is throttled, and a lockout also blocks a correct code.
#[tokio::test]
async fn totp_login_is_rate_limited() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;
    let body: Value = server
        .post("/api/v1/auth/totp/setup")
        .authorization_bearer(&token)
        .await
        .json();
    let secret = body["secret"].as_str().unwrap().to_string();
    let code = crate::auth::totp::generate_current(&secret).unwrap();
    server
        .post("/api/v1/auth/totp/verify")
        .authorization_bearer(&token)
        .json(&json!({ "code": &code }))
        .await
        .assert_status_ok();

    for _ in 0..5 {
        server
            .post("/api/v1/auth/totp/login")
            .json(&json!({"username": "admin", "password": "TestPass123", "totp_code": "000000"}))
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
    }
    let code = crate::auth::totp::generate_current(&secret).unwrap();
    server
        .post("/api/v1/auth/totp/login")
        .json(&json!({"username": "admin", "password": "TestPass123", "totp_code": &code}))
        .await
        .assert_status(StatusCode::TOO_MANY_REQUESTS);
}

/// Unknown users and bad passwords on the TOTP step count as failures too.
#[tokio::test]
async fn totp_login_bad_password_counts_toward_limit() {
    let (server, _) = test_app().await;
    create_user_and_login(&server).await;
    for _ in 0..5 {
        server
            .post("/api/v1/auth/totp/login")
            .json(&json!({"username": "ghost", "password": "nope", "totp_code": "000000"}))
            .await
            .assert_status(StatusCode::UNAUTHORIZED);
    }
    server
        .post("/api/v1/auth/totp/login")
        .json(&json!({"username": "ghost", "password": "nope", "totp_code": "000000"}))
        .await
        .assert_status(StatusCode::TOO_MANY_REQUESTS);
}

/// User update/delete identify the actor from the auth middleware, so an
/// API key (the CLI) can manage users — they used to demand a Bearer JWT.
#[tokio::test]
async fn api_key_can_update_and_delete_users() {
    let (server, pool) = app_with_pool().await;
    let admin = create_user_and_login(&server).await;
    let ops_id = create_user(&server, &admin, "ops", "operator").await;
    let key = mint(&server, &admin, json!({"name": "k"}))
        .await
        .json::<Value>()["key"]
        .as_str()
        .unwrap()
        .to_string();
    let (n, v) = api_key_header(&key);
    server
        .put(&format!("/api/v1/auth/users/{ops_id}"))
        .add_header(n.clone(), v.clone())
        .json(&json!({"enabled": false}))
        .await
        .assert_status_ok();
    server
        .delete(&format!("/api/v1/auth/users/{ops_id}"))
        .add_header(n, v)
        .await
        .assert_status_ok();
    let (actor,): (String,) =
        sqlx::query_as("SELECT actor_id FROM user_audit_log WHERE action = 'user_deleted'")
            .fetch_one(&pool)
            .await
            .unwrap();
    let (admin_id,): (String,) = sqlx::query_as("SELECT id FROM users WHERE username = 'admin'")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(actor, admin_id, "audit records the key's owner");
}
