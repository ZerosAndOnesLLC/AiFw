use super::*;

#[tokio::test]
async fn test_protected_route_no_auth() {
    let (server, _) = test_app().await;

    let resp = server.get("/api/v1/rules").await;
    resp.assert_status(StatusCode::UNAUTHORIZED);
}

/// #318: the daemon-loopback service user must not be an admin. New rows
/// get the built-in `system` role (HaManage only); a legacy row that
/// inherited the column default 'admin' is demoted by the auth migration.
#[tokio::test]
async fn test_daemon_service_user_is_not_admin() {
    use aifw_common::permission::{Permission, PermissionSet};
    let state = crate::create_app_state_in_memory(plain_auth_settings())
        .await
        .unwrap();
    let pool = state.pool.clone();
    let server = TestServer::new(crate::build_router(state, None, "*", false));
    let token = create_user_and_login(&server).await;

    // Generating the loopback key creates the service user.
    let resp = server
        .post("/api/v1/cluster/loopback-key/generate")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();

    let (role, role_id): (String, Option<String>) =
        sqlx::query_as("SELECT role, role_id FROM users WHERE username = 'aifw-daemon'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(role, "system");
    assert_eq!(
        role_id.as_deref(),
        Some(crate::auth::migrate::SYSTEM_ROLE_ID)
    );

    let (bits, name) =
        crate::auth::tokens::resolve_token_permissions(&pool, &role, role_id.as_deref())
            .await
            .unwrap();
    let perms = PermissionSet::from_bits(bits);
    assert_eq!(name, "system");
    assert!(perms.has(Permission::HaManage));
    assert!(
        !perms.has(Permission::UsersWrite),
        "must not be able to mint admins"
    );
    assert!(!perms.has(Permission::SettingsWrite));
    assert!(!perms.has(Permission::UpdatesInstall));

    // People can't be given the system role.
    for role in ["system", crate::auth::migrate::SYSTEM_ROLE_ID] {
        let resp = server
            .post("/api/v1/auth/users")
            .authorization_bearer(&token)
            .json(&json!({"username": format!("u-{role}"), "password": "LongEnough123!", "role": role}))
            .await;
        resp.assert_status(StatusCode::BAD_REQUEST);
    }
}

/// #318: a pre-existing daemon user that got the 'admin' column default is
/// demoted to `system` when the auth migration runs.
#[tokio::test]
async fn test_auth_migration_demotes_legacy_daemon_user() {
    let state = crate::create_app_state_in_memory(plain_auth_settings())
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO users (id, username, password_hash, totp_enabled, auth_provider, created_at)
         VALUES ('d1', 'aifw-daemon', 'x', 0, 'system', 'now')",
    )
    .execute(&state.pool)
    .await
    .unwrap();
    let (role, role_id): (String, Option<String>) =
        sqlx::query_as("SELECT role, role_id FROM users WHERE id = 'd1'")
            .fetch_one(&state.pool)
            .await
            .unwrap();
    assert_eq!(role, "admin", "column default is the bug being fixed");
    assert!(role_id.is_none());

    crate::auth::migrate::migrate(&state.pool).await.unwrap();

    let (role, role_id): (String, Option<String>) =
        sqlx::query_as("SELECT role, role_id FROM users WHERE id = 'd1'")
            .fetch_one(&state.pool)
            .await
            .unwrap();
    assert_eq!(role, "system");
    assert_eq!(role_id.as_deref(), Some("builtin-system"));
    // A real admin is untouched.
    sqlx::query(
        "INSERT INTO users (id, username, password_hash, totp_enabled, auth_provider, role, role_id, created_at)
         VALUES ('a1', 'alice', 'x', 0, 'local', 'admin', 'builtin-admin', 'now')",
    )
    .execute(&state.pool)
    .await
    .unwrap();
    crate::auth::migrate::migrate(&state.pool).await.unwrap();
    let (role,): (String,) = sqlx::query_as("SELECT role FROM users WHERE id = 'a1'")
        .fetch_one(&state.pool)
        .await
        .unwrap();
    assert_eq!(role, "admin");
}

/// SEC-H12 (#297): the reserved cluster key names can't be minted through
/// the normal Users → API Keys path (would otherwise self-grant peer
/// privilege).
#[tokio::test]
async fn test_reserved_api_key_names_rejected() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    for name in ["aifw-cluster-peer", "aifw-daemon-loopback"] {
        let resp = server
            .post("/api/v1/auth/api-keys")
            .authorization_bearer(&token)
            .json(&json!({ "name": name }))
            .await;
        resp.assert_status(StatusCode::BAD_REQUEST);
    }

    // A normal name still works.
    let resp = server
        .post("/api/v1/auth/api-keys")
        .authorization_bearer(&token)
        .json(&json!({ "name": "my-key" }))
        .await;
    resp.assert_status(StatusCode::CREATED);
}

#[tokio::test]
async fn test_missing_auth_returns_401() {
    let (server, _) = test_app().await;
    server
        .get("/api/v1/rules")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    server
        .get("/api/v1/status")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    server
        .get("/api/v1/connections")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    server
        .get("/api/v1/metrics")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_disabled_user_token_rejected() {
    let (server, _) = test_app().await;
    let (admin_token, viewer_token) = create_admin_and_viewer(&server).await;

    // Viewer can access rules
    server
        .get("/api/v1/rules")
        .authorization_bearer(&viewer_token)
        .await
        .assert_status_ok();

    // Admin disables viewer
    let resp = server
        .get("/api/v1/auth/users")
        .authorization_bearer(&admin_token)
        .await;
    let body: Value = resp.json();
    let viewer_id = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|u| u["username"] == "viewer")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_string();

    server
        .put(&format!("/api/v1/auth/users/{viewer_id}"))
        .authorization_bearer(&admin_token)
        .json(&json!({"enabled": false}))
        .await;

    // Viewer's token should now be rejected
    server
        .get("/api/v1/rules")
        .authorization_bearer(&viewer_token)
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_revoked_access_token_rejected() {
    let (server, _) = test_app().await;
    create_user_and_login(&server).await;

    let resp = server
        .post("/api/v1/auth/login")
        .json(&json!({"username": "admin", "password": "TestPass123"}))
        .await;
    let body: Value = resp.json();
    let access = body["tokens"]["access_token"].as_str().unwrap().to_string();
    let refresh = body["tokens"]["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Token works
    server
        .get("/api/v1/rules")
        .authorization_bearer(&access)
        .await
        .assert_status_ok();

    // Logout (revokes access token)
    server
        .post("/api/v1/auth/logout")
        .authorization_bearer(&access)
        .json(&json!({"refresh_token": &refresh}))
        .await;

    // Token should be revoked
    server
        .get("/api/v1/rules")
        .authorization_bearer(&access)
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_viewer_cannot_access_admin_routes() {
    let (server, _) = test_app().await;
    let (_admin_token, viewer_token) = create_admin_and_viewer(&server).await;

    // Admin-only routes should return 403 for viewer
    server
        .get("/api/v1/auth/users")
        .authorization_bearer(&viewer_token)
        .await
        .assert_status(StatusCode::FORBIDDEN);
    server
        .get("/api/v1/auth/settings")
        .authorization_bearer(&viewer_token)
        .await
        .assert_status(StatusCode::FORBIDDEN);
    server
        .get("/api/v1/auth/audit")
        .authorization_bearer(&viewer_token)
        .await
        .assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_viewer_can_read_rules() {
    let (server, _) = test_app().await;
    let (_admin_token, viewer_token) = create_admin_and_viewer(&server).await;

    // Viewer should be able to read rules, status, connections
    server
        .get("/api/v1/rules")
        .authorization_bearer(&viewer_token)
        .await
        .assert_status_ok();
    server
        .get("/api/v1/status")
        .authorization_bearer(&viewer_token)
        .await
        .assert_status_ok();
    server
        .get("/api/v1/connections")
        .authorization_bearer(&viewer_token)
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn test_admin_can_access_admin_routes() {
    let (server, _) = test_app().await;
    let (admin_token, _viewer_token) = create_admin_and_viewer(&server).await;

    server
        .get("/api/v1/auth/users")
        .authorization_bearer(&admin_token)
        .await
        .assert_status_ok();
    server
        .get("/api/v1/auth/settings")
        .authorization_bearer(&admin_token)
        .await
        .assert_status_ok();
}

#[tokio::test]
async fn test_second_registration_forbidden() {
    let (server, _) = test_app().await;

    // First registration succeeds
    let resp = server
        .post("/api/v1/auth/register")
        .json(&json!({"username":"admin","password":"TestPass123"}))
        .await;
    resp.assert_status(StatusCode::CREATED);

    // Second registration fails
    let resp = server
        .post("/api/v1/auth/register")
        .json(&json!({"username":"attacker","password":"HackPass1"}))
        .await;
    resp.assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_first_user_forced_to_admin() {
    let (server, _) = test_app().await;

    // Register with explicit "viewer" role — should be overridden to admin
    let resp = server
        .post("/api/v1/auth/register")
        .json(&json!({"username":"admin","password":"TestPass123","role":"viewer"}))
        .await;
    resp.assert_status(StatusCode::CREATED);
    let body: Value = resp.json();
    assert_eq!(body["data"]["role"], "admin");
}

/// Verifies that apply_cluster_snapshot does NOT wipe per-peer API keys
/// that were stored locally when the master-side snapshot does not carry
/// them (they are local credentials, never replicated).
///
/// Regression guard for the Commit 5 R2 fix.
#[tokio::test]
async fn apply_cluster_snapshot_preserves_local_peer_api_key() {
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
    // apply_cluster_snapshot queries ids_suppressions and ids_rules;
    // run the IDS migration so those tables exist in the in-memory DB.
    aifw_ids::IdsEngine::migrate(&state.pool).await.unwrap();

    // Insert a cluster node with a peer_api_key set (simulates a key the
    // operator generated before the master pushed its first snapshot).
    let node = ClusterNode::new(
        "peer-node".to_string(),
        "10.0.0.2".parse().unwrap(),
        ClusterRole::Secondary,
    );
    state.cluster_engine.add_node(node.clone()).await.unwrap();
    // Set the peer_api_key directly on the DB row (mirrors generate_node_key).
    let key_value = "local-key-for-peer-abc123";
    let key_hash = aifw_core::sha256_hex(key_value);
    sqlx::query("UPDATE cluster_nodes SET peer_api_key = ?1, peer_api_key_hash = ?2 WHERE id = ?3")
        .bind(key_value)
        .bind(&key_hash)
        .bind(node.id.to_string())
        .execute(&state.pool)
        .await
        .unwrap();

    // Verify the key is there before the snapshot apply.
    let key_before = state.cluster_engine.peer_api_key(node.id).await.unwrap();
    assert_eq!(key_before.as_deref(), Some(key_value));

    // Build a minimal snapshot payload that includes the cluster node
    // WITHOUT a peer_api_key (as the master would generate it).
    let snapshot = crate::backup::cluster_export_payload(&state).await.unwrap();
    let snapshot_json = serde_json::to_string(&snapshot).unwrap();

    // Apply the snapshot (simulates the standby receiving a replication push).
    crate::backup::apply_cluster_snapshot(&state, &snapshot_json)
        .await
        .unwrap();

    // After apply, the peer_api_key must still be the locally-stored value.
    // If the fix regresses, this will be None (wiped by DELETE+re-insert).
    let key_after = state.cluster_engine.peer_api_key(node.id).await.unwrap();
    assert_eq!(
        key_after.as_deref(),
        Some(key_value),
        "peer_api_key was wiped by apply_cluster_snapshot — regression in Commit 5 R2 fix"
    );
}
