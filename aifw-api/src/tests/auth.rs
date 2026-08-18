use super::*;

#[tokio::test]
async fn test_create_user() {
    let (server, _) = test_app().await;

    let resp = server
        .post("/api/v1/auth/register")
        .json(&json!({
            "username": "admin",
            "password": "TestPass123"
        }))
        .await;

    resp.assert_status(StatusCode::CREATED);
    let body: Value = resp.json();
    assert_eq!(body["data"]["username"], "admin");
}

#[tokio::test]
async fn test_login() {
    let (server, _) = test_app().await;

    // Create user first
    server
        .post("/api/v1/auth/register")
        .json(&json!({
            "username": "admin",
            "password": "TestPass123"
        }))
        .await;

    let resp = server
        .post("/api/v1/auth/login")
        .json(&json!({
            "username": "admin",
            "password": "TestPass123"
        }))
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert!(body["tokens"]["access_token"].as_str().is_some());
    assert!(body["tokens"]["refresh_token"].as_str().is_some());
    assert_eq!(body["totp_required"], false);
}

#[tokio::test]
async fn test_login_wrong_password() {
    let (server, _) = test_app().await;

    server
        .post("/api/v1/auth/register")
        .json(&json!({
            "username": "admin",
            "password": "TestPass123"
        }))
        .await;

    let resp = server
        .post("/api/v1/auth/login")
        .json(&json!({
            "username": "admin",
            "password": "wrongpassword"
        }))
        .await;

    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_refresh_token_flow() {
    let (server, _) = test_app().await;

    server
        .post("/api/v1/auth/register")
        .json(&json!({"username": "rfuser", "password": "TestPass123"}))
        .await;

    // Login to get tokens
    let resp = server
        .post("/api/v1/auth/login")
        .json(&json!({"username": "rfuser", "password": "TestPass123"}))
        .await;

    let body: Value = resp.json();
    let refresh = body["tokens"]["refresh_token"].as_str().unwrap();

    // Use refresh token to get new pair
    let resp = server
        .post("/api/v1/auth/refresh")
        .json(&json!({"refresh_token": refresh}))
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert!(body["access_token"].as_str().is_some());
    assert!(body["refresh_token"].as_str().is_some());
    // New refresh token should be different
    assert_ne!(body["refresh_token"].as_str().unwrap(), refresh);
}

#[tokio::test]
async fn test_refresh_token_reuse_detection() {
    let (server, _) = test_app().await;

    server
        .post("/api/v1/auth/register")
        .json(&json!({"username": "reuseuser", "password": "TestPass123"}))
        .await;

    let resp = server
        .post("/api/v1/auth/login")
        .json(&json!({"username": "reuseuser", "password": "TestPass123"}))
        .await;

    let body: Value = resp.json();
    let old_refresh = body["tokens"]["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Use it once (valid)
    server
        .post("/api/v1/auth/refresh")
        .json(&json!({"refresh_token": &old_refresh}))
        .await;

    // Use it again (reuse — should fail and revoke family)
    let resp = server
        .post("/api/v1/auth/refresh")
        .json(&json!({"refresh_token": &old_refresh}))
        .await;

    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_logout() {
    let (server, _) = test_app().await;

    server
        .post("/api/v1/auth/register")
        .json(&json!({"username": "logoutuser", "password": "TestPass123"}))
        .await;

    let resp = server
        .post("/api/v1/auth/login")
        .json(&json!({"username": "logoutuser", "password": "TestPass123"}))
        .await;

    let body: Value = resp.json();
    let access = body["tokens"]["access_token"].as_str().unwrap().to_string();
    let refresh = body["tokens"]["refresh_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Logout
    let resp = server
        .post("/api/v1/auth/logout")
        .authorization_bearer(&access)
        .json(&json!({"refresh_token": &refresh}))
        .await;

    resp.assert_status_ok();

    // Refresh token should no longer work
    let resp = server
        .post("/api/v1/auth/refresh")
        .json(&json!({"refresh_token": &refresh}))
        .await;

    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_totp_setup_and_verify() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    // Setup TOTP
    let resp = server
        .post("/api/v1/auth/totp/setup")
        .authorization_bearer(&token)
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert!(body["secret"].as_str().is_some());
    assert!(
        body["provisioning_uri"]
            .as_str()
            .unwrap()
            .starts_with("otpauth://")
    );
    let recovery_codes = body["recovery_codes"].as_array().unwrap();
    assert_eq!(recovery_codes.len(), 8);

    // Generate a valid TOTP code from the secret
    let secret = body["secret"].as_str().unwrap();
    let code = crate::auth::totp::generate_current(secret).unwrap();

    // Verify (activates TOTP)
    let resp = server
        .post("/api/v1/auth/totp/verify")
        .authorization_bearer(&token)
        .json(&json!({"code": code}))
        .await;

    resp.assert_status_ok();
}

#[tokio::test]
async fn test_totp_login_flow() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    // Setup + verify TOTP
    let resp = server
        .post("/api/v1/auth/totp/setup")
        .authorization_bearer(&token)
        .await;

    let body: Value = resp.json();
    let secret = body["secret"].as_str().unwrap().to_string();
    let code = crate::auth::totp::generate_current(&secret).unwrap();

    server
        .post("/api/v1/auth/totp/verify")
        .authorization_bearer(&token)
        .json(&json!({"code": &code}))
        .await;

    // Now login should require TOTP
    let resp = server
        .post("/api/v1/auth/login")
        .json(&json!({"username": "admin", "password": "TestPass123"}))
        .await;

    let body: Value = resp.json();
    assert_eq!(body["totp_required"], true);
    assert!(body["tokens"].is_null() || body["access_token"].is_null());

    // Complete login with TOTP
    let code = crate::auth::totp::generate_current(&secret).unwrap();
    let resp = server
        .post("/api/v1/auth/totp/login")
        .json(&json!({"username": "admin", "password": "TestPass123", "totp_code": &code}))
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert!(body["access_token"].as_str().is_some());
}

#[tokio::test]
async fn test_recovery_code_login() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    // Setup + verify TOTP
    let resp = server
        .post("/api/v1/auth/totp/setup")
        .authorization_bearer(&token)
        .await;

    let body: Value = resp.json();
    let secret = body["secret"].as_str().unwrap().to_string();
    let recovery = body["recovery_codes"][0].as_str().unwrap().to_string();
    let code = crate::auth::totp::generate_current(&secret).unwrap();

    server
        .post("/api/v1/auth/totp/verify")
        .authorization_bearer(&token)
        .json(&json!({"code": &code}))
        .await;

    // Login with recovery code instead of TOTP
    let resp = server
        .post("/api/v1/auth/totp/login")
        .json(&json!({"username": "admin", "password": "TestPass123", "totp_code": &recovery}))
        .await;

    resp.assert_status_ok();

    // Same recovery code should not work again
    let resp = server
        .post("/api/v1/auth/totp/login")
        .json(&json!({"username": "admin", "password": "TestPass123", "totp_code": &recovery}))
        .await;

    resp.assert_status(StatusCode::UNAUTHORIZED);
}

/// #298: OAuth client secrets are sealed in the DB; the loader opens them.
#[tokio::test]
async fn test_oauth_client_secret_sealed_at_rest() {
    let state = crate::create_app_state_in_memory(plain_auth_settings())
        .await
        .unwrap();
    let provider = crate::auth::oauth::OAuthProvider::google("cid", "very-secret");
    crate::auth::oauth::save_provider(&state.pool, &provider)
        .await
        .unwrap();
    let (stored,): (String,) =
        sqlx::query_as("SELECT client_secret FROM oauth_providers WHERE client_id = 'cid'")
            .fetch_one(&state.pool)
            .await
            .unwrap();
    assert!(aifw_core::secrets::is_sealed(&stored));
    assert!(!stored.contains("very-secret"));
    let listed = crate::auth::oauth::list_providers(&state.pool)
        .await
        .unwrap();
    assert_eq!(listed[0].client_secret, "very-secret");
}

#[tokio::test]
async fn test_oauth_provider_crud() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    // Create Google provider
    let resp = server
        .post("/api/v1/auth/oauth/providers")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "Google",
            "provider_type": "google",
            "client_id": "test-client-id",
            "client_secret": "test-secret"
        }))
        .await;

    resp.assert_status(StatusCode::CREATED);
    let body: Value = resp.json();
    let provider_id = body["data"]["id"].as_str().unwrap().to_string();

    // List providers
    let resp = server
        .get("/api/v1/auth/oauth/providers")
        .authorization_bearer(&token)
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["data"].as_array().unwrap().len(), 1);

    // Delete
    let resp = server
        .delete(&format!("/api/v1/auth/oauth/providers/{provider_id}"))
        .authorization_bearer(&token)
        .await;

    resp.assert_status_ok();
}

/// SEC-H7 (#292): the configured `password_min_length` must be enforced,
/// not the hardcoded floor of 8.
#[tokio::test]
async fn test_password_min_length_enforced() {
    let server = test_app_min_len(16).await;

    // First-user bootstrap (register) must honor the 16-char minimum:
    // a complexity-valid but 12-char password is rejected.
    let resp = server
        .post("/api/v1/auth/register")
        .json(&json!({"username": "admin", "password": "ShortPass123"}))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    // A 16-char password satisfies it.
    let resp = server
        .post("/api/v1/auth/register")
        .json(&json!({"username": "admin", "password": "LongEnoughPass12"}))
        .await;
    resp.assert_status(StatusCode::CREATED);

    // Log in and exercise the admin create-user path too.
    let login = server
        .post("/api/v1/auth/login")
        .json(&json!({"username": "admin", "password": "LongEnoughPass12"}))
        .await;
    let token = login.json::<Value>()["tokens"]["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    let resp = server
        .post("/api/v1/auth/users")
        .authorization_bearer(&token)
        .json(&json!({"username": "bob", "password": "ShortPass123", "role": "viewer"}))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    let resp = server
        .post("/api/v1/auth/users")
        .authorization_bearer(&token)
        .json(&json!({"username": "bob", "password": "LongEnoughPass12", "role": "viewer"}))
        .await;
    resp.assert_status(StatusCode::CREATED);
}

/// SEC-H8 (#293): the refresh endpoint is rate-limited so a spray of
/// forged tokens can't tie up the CPU indefinitely.
#[tokio::test]
async fn test_refresh_endpoint_rate_limited() {
    let (server, _) = test_app().await;
    // max_login_attempts is 5. A forged token with a fixed prefix keeps
    // the rate-limit key stable across attempts.
    let forged = "rfx_deadbeefdeadbeefdeadbeefdeadbeef";

    // First failure returns 401 (invalid token), not yet blocked.
    let resp = server
        .post("/api/v1/auth/refresh")
        .json(&json!({"refresh_token": forged}))
        .await;
    resp.assert_status(StatusCode::UNAUTHORIZED);

    // Exhaust the remaining attempts.
    for _ in 0..4 {
        server
            .post("/api/v1/auth/refresh")
            .json(&json!({"refresh_token": forged}))
            .await;
    }

    // Now blocked.
    let resp = server
        .post("/api/v1/auth/refresh")
        .json(&json!({"refresh_token": forged}))
        .await;
    resp.assert_status(StatusCode::TOO_MANY_REQUESTS);
}

/// SEC-H9 (#294): the OAuth callback must reject a `state` it never
/// issued, and a valid state is single-use (replay-proof).
#[tokio::test]
async fn test_oauth_callback_state_binding() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    // A forged state is rejected before any token exchange — the
    // browser is bounced to the login page with the `state` error (#170
    // made the callback a redirecting endpoint).
    let resp = server
        .get("/api/v1/auth/oauth/Google/callback?code=abc&state=forged-nonce")
        .await;
    assert!(resp.status_code().is_redirection());
    assert_eq!(
        resp.headers().get("location").unwrap(),
        "/login/?oauth_error=state"
    );

    // Create the provider, then obtain a real state from /authorize.
    server
        .post("/api/v1/auth/oauth/providers")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "Google",
            "provider_type": "google",
            "client_id": "test-client-id",
            "client_secret": "test-secret"
        }))
        .await
        .assert_status(StatusCode::CREATED);

    let authorize = server.get("/api/v1/auth/oauth/Google/authorize").await;
    authorize.assert_status_ok();
    let state = authorize.json::<Value>()["state"]
        .as_str()
        .unwrap()
        .to_string();

    // A valid state passes the CSRF check and reaches the token
    // exchange — which fails here (no real Google), so the error is
    // `exchange`, not `state`.
    let resp = server
        .get(&format!(
            "/api/v1/auth/oauth/Google/callback?code=abc&state={state}"
        ))
        .await;
    assert_eq!(
        resp.headers().get("location").unwrap(),
        "/login/?oauth_error=exchange"
    );

    // Replaying the same (now-consumed) state is rejected.
    let resp = server
        .get(&format!(
            "/api/v1/auth/oauth/Google/callback?code=abc&state={state}"
        ))
        .await;
    assert_eq!(
        resp.headers().get("location").unwrap(),
        "/login/?oauth_error=state"
    );
}

/// SEC-M3 #300: browser-hardening headers are present on every
/// response — API JSON, errors, and (when served) the static UI.
#[tokio::test]
async fn test_security_headers_on_every_response() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    for resp in [
        server
            .get("/api/v1/status")
            .authorization_bearer(&token)
            .await,
        server.get("/api/v1/rules").await,           // 401 path
        server.get("/definitely/not/a/route").await, // 404 path
    ] {
        let h = resp.headers();
        let csp = h
            .get("content-security-policy")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert!(csp.contains("default-src 'self'"), "csp: {csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "csp: {csp}");
        assert!(csp.contains("object-src 'none'"), "csp: {csp}");
        assert_eq!(h.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(h.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(h.get("referrer-policy").unwrap(), "no-referrer");
        // HSTS only when TLS is on; test_app builds with tls_enabled=false.
        assert!(h.get("strict-transport-security").is_none());
    }
}

/// #200 follow-through: auto-snapshots record the acting username as
/// the config-history actor (was a hardcoded "auto"). Waits out the
/// real 5s debounce (paused time breaks the sqlx pool's acquire timer).
#[tokio::test]
async fn test_auto_snapshot_records_acting_user() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    // Any successful mutation on a snapshot-worthy path.
    server
        .post("/api/v1/aliases")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "snap_actor_test",
            "alias_type": "host",
            "entries": ["10.9.9.9"]
        }))
        .await
        .assert_status_success();

    // Let the debounced background snapshot fire and finish.
    tokio::time::sleep(std::time::Duration::from_secs(7)).await;

    let resp = server
        .get("/api/v1/config/history")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    let versions = body["data"].as_array().expect("history array");
    assert!(
        versions.iter().any(|v| v["created_by"] == "admin"),
        "expected an auto-snapshot attributed to 'admin', got: {versions:?}"
    );
}

#[tokio::test]
async fn test_invalid_token_returns_401() {
    let (server, _) = test_app().await;
    let resp = server
        .get("/api/v1/rules")
        .authorization_bearer("totally.invalid.token")
        .await;
    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_password_validation() {
    let (server, _) = test_app().await;

    // Too short
    let resp = server
        .post("/api/v1/auth/register")
        .json(&json!({"username":"u1","password":"Ab1"}))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    // No uppercase
    let resp = server
        .post("/api/v1/auth/register")
        .json(&json!({"username":"u2","password":"testpass123"}))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    // No lowercase
    let resp = server
        .post("/api/v1/auth/register")
        .json(&json!({"username":"u3","password":"TESTPASS123"}))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    // No digit
    let resp = server
        .post("/api/v1/auth/register")
        .json(&json!({"username":"u4","password":"TestPasswd"}))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    // Valid
    let resp = server
        .post("/api/v1/auth/register")
        .json(&json!({"username":"u5","password":"GoodPass1"}))
        .await;
    resp.assert_status(StatusCode::CREATED);
}

#[tokio::test]
async fn test_login_rate_limiting() {
    let (server, _) = test_app().await;
    create_user_and_login(&server).await;

    // 5 failed attempts
    for _ in 0..5 {
        server
            .post("/api/v1/auth/login")
            .json(&json!({"username":"admin","password":"WrongPass1"}))
            .await;
    }

    // 6th attempt should be rate limited
    let resp = server
        .post("/api/v1/auth/login")
        .json(&json!({"username":"admin","password":"WrongPass1"}))
        .await;
    resp.assert_status(StatusCode::TOO_MANY_REQUESTS);

    // Even correct password should be blocked
    let resp = server
        .post("/api/v1/auth/login")
        .json(&json!({"username":"admin","password":"TestPass123"}))
        .await;
    resp.assert_status(StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_jwt_secret_not_in_settings_response() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let resp = server
        .get("/api/v1/auth/settings")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    // jwt_secret should NOT be present (skip_serializing)
    assert!(body.get("jwt_secret").is_none());
}

#[tokio::test]
async fn test_auth_settings() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    // Get settings
    let resp = server
        .get("/api/v1/auth/settings")
        .authorization_bearer(&token)
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["require_totp"], false);

    // Update settings
    let resp = server
        .put("/api/v1/auth/settings")
        .authorization_bearer(&token)
        .json(&json!({"require_totp": true, "access_token_expiry_mins": 30}))
        .await;

    resp.assert_status_ok();
}

/// #170: full OAuth/OIDC round-trip against an in-process mock IdP —
/// PKCE + state, token exchange, userinfo, auto-provisioning, session
/// cookies, replay rejection, auto-create off, and the TOTP second step.
#[tokio::test]
async fn test_oauth_login_round_trip_with_mock_idp() {
    use axum::{
        Json, Router,
        routing::{get, post},
    };
    use std::sync::{Arc, Mutex};

    // ---- mock identity provider ------------------------------------
    #[derive(Clone, Default)]
    struct Idp {
        token_forms: Arc<Mutex<Vec<String>>>,
        userinfo: Arc<Mutex<Value>>,
    }
    let idp = Idp {
        userinfo: Arc::new(Mutex::new(json!({
            "sub": "sub-123", "email": "Alice@Example.com", "email_verified": true, "name": "Alice"
        }))),
        ..Default::default()
    };
    let idp_for_token = idp.clone();
    let idp_for_info = idp.clone();
    let idp_app = Router::new()
        .route(
            "/token",
            post(move |body: String| {
                let idp = idp_for_token.clone();
                async move {
                    idp.token_forms.lock().unwrap().push(body.clone());
                    if body.contains("code=goodcode") {
                        Json(json!({"access_token": "at-xyz", "token_type": "Bearer"}))
                    } else {
                        Json(json!({"error": "invalid_grant"}))
                    }
                }
            }),
        )
        .route(
            "/userinfo",
            get(move |headers: axum::http::HeaderMap| {
                let idp = idp_for_info.clone();
                async move {
                    let ok = headers.get("authorization").and_then(|h| h.to_str().ok())
                        == Some("Bearer at-xyz");
                    if ok {
                        (StatusCode::OK, Json(idp.userinfo.lock().unwrap().clone()))
                    } else {
                        (StatusCode::UNAUTHORIZED, Json(json!({})))
                    }
                }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let idp_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, idp_app).await.unwrap();
    });
    let idp_base = format!("http://127.0.0.1:{}", idp_addr.port());

    // ---- AiFw side ---------------------------------------------------
    let state = crate::create_app_state_in_memory(plain_auth_settings())
        .await
        .unwrap();
    let pool = state.pool.clone();
    let server = TestServer::new(crate::build_router(state, None, "*", false));
    let token = create_user_and_login(&server).await;

    // No providers yet → empty public login options.
    let resp = server.get("/api/v1/auth/oauth/login-options").await;
    resp.assert_status_ok();
    assert_eq!(resp.json::<Value>()["data"].as_array().unwrap().len(), 0);

    // Register a generic OIDC provider pointing at the mock.
    let resp = server
        .post("/api/v1/auth/oauth/providers")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "MockIdP", "provider_type": "oidc",
            "client_id": "cid", "client_secret": "csecret",
            "auth_url": format!("{idp_base}/authorize"),
            "token_url": format!("{idp_base}/token"),
            "userinfo_url": format!("{idp_base}/userinfo"),
            "scopes": "openid email"
        }))
        .await;
    assert_eq!(resp.status_code(), StatusCode::CREATED, "{}", resp.text());
    let resp = server.get("/api/v1/auth/oauth/login-options").await;
    let opts: Value = resp.json();
    assert_eq!(opts["data"][0]["name"], "MockIdP");
    assert!(opts["data"][0].get("client_secret").is_none());

    // Pin the public URL (what the redirect URI is built from).
    server
        .put("/api/v1/auth/oauth/settings")
        .authorization_bearer(&token)
        .json(&json!({"public_url": "https://fw.example.test:8080/"}))
        .await
        .assert_status_ok();

    // authorize → URL with state + PKCE
    async fn start(server: &TestServer, idp_base: &str) -> String {
        let resp = server.get("/api/v1/auth/oauth/MockIdP/authorize").await;
        resp.assert_status_ok();
        let body: Value = resp.json();
        let url = body["authorize_url"].as_str().unwrap().to_string();
        assert!(url.starts_with(&format!("{idp_base}/authorize?")), "{url}");
        assert!(url.contains("redirect_uri=https%3A%2F%2Ffw.example.test%3A8080%2Fapi%2Fv1%2Fauth%2Foauth%2FMockIdP%2Fcallback"), "{url}");
        assert!(url.contains("code_challenge_method=S256"), "{url}");
        body["state"].as_str().unwrap().to_string()
    }

    // Happy path: new identity, auto-created viewer, session cookies set.
    let st = start(&server, &idp_base).await;
    let resp = server
        .get(&format!(
            "/api/v1/auth/oauth/MockIdP/callback?code=goodcode&state={st}"
        ))
        .await;
    assert!(resp.status_code().is_redirection(), "{}", resp.text());
    let loc = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert_eq!(loc, "/login/?oauth=ok", "{loc}");
    let cookies: Vec<String> = resp
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap().to_string())
        .collect();
    assert!(
        cookies.iter().any(|c| c.starts_with("aifw_at=")),
        "{cookies:?}"
    );
    let access = cookies
        .iter()
        .find(|c| c.starts_with("aifw_at="))
        .and_then(|c| c.split(';').next())
        .and_then(|kv| kv.strip_prefix("aifw_at="))
        .unwrap()
        .to_string();
    // Exchange carried the PKCE verifier and the exact redirect URI.
    let forms = idp.token_forms.lock().unwrap().clone();
    assert_eq!(forms.len(), 1);
    assert!(forms[0].contains("code_verifier="), "{}", forms[0]);
    assert!(forms[0].contains("client_secret=csecret"), "{}", forms[0]);
    assert!(forms[0].contains("redirect_uri=https%3A%2F%2Ffw.example.test%3A8080%2Fapi%2Fv1%2Fauth%2Foauth%2FMockIdP%2Fcallback"), "{}", forms[0]);
    // The cookie session works, and the account is the provisioned viewer.
    let resp = server
        .get("/api/v1/auth/me")
        .add_header("cookie", format!("aifw_at={access}"))
        .await;
    resp.assert_status_ok();
    let me: Value = resp.json();
    assert_eq!(me["username"], "alice@example.com", "{me}");
    assert_eq!(me["role"], "viewer");
    assert_eq!(me["auth_provider"], "MockIdP");

    // Replaying the same state is refused before any exchange.
    let resp = server
        .get(&format!(
            "/api/v1/auth/oauth/MockIdP/callback?code=goodcode&state={st}"
        ))
        .await;
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/login/?oauth_error=state"
    );
    assert_eq!(idp.token_forms.lock().unwrap().len(), 1);

    // Bad code → exchange error.
    let st = start(&server, &idp_base).await;
    let resp = server
        .get(&format!(
            "/api/v1/auth/oauth/MockIdP/callback?code=badcode&state={st}"
        ))
        .await;
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/login/?oauth_error=exchange"
    );

    // Second login of the same subject links to the same account (no dup user).
    let st = start(&server, &idp_base).await;
    let resp = server
        .get(&format!(
            "/api/v1/auth/oauth/MockIdP/callback?code=goodcode&state={st}"
        ))
        .await;
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/login/?oauth=ok"
    );
    let n: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = 'alice@example.com'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(n, 1);

    // Auto-create off: an unknown subject is refused.
    server
        .put("/api/v1/auth/settings")
        .authorization_bearer(&token)
        .json(&json!({"auto_create_oauth_users": false}))
        .await
        .assert_status_ok();
    *idp.userinfo.lock().unwrap() =
        json!({"sub": "sub-999", "email": "bob@example.com", "email_verified": true});
    let st = start(&server, &idp_base).await;
    let resp = server
        .get(&format!(
            "/api/v1/auth/oauth/MockIdP/callback?code=goodcode&state={st}"
        ))
        .await;
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/login/?oauth_error=no_account"
    );

    // Verified email matching an existing local username links it —
    // here the bootstrap admin, whose username is "admin".
    *idp.userinfo.lock().unwrap() =
        json!({"sub": "sub-admin", "email": "admin", "email_verified": true});
    let st = start(&server, &idp_base).await;
    let resp = server
        .get(&format!(
            "/api/v1/auth/oauth/MockIdP/callback?code=goodcode&state={st}"
        ))
        .await;
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/login/?oauth=ok"
    );
    // …but an unverified email must not.
    *idp.userinfo.lock().unwrap() =
        json!({"sub": "sub-evil", "email": "admin", "email_verified": false});
    let st = start(&server, &idp_base).await;
    let resp = server
        .get(&format!(
            "/api/v1/auth/oauth/MockIdP/callback?code=goodcode&state={st}"
        ))
        .await;
    assert_eq!(
        resp.headers().get("location").unwrap().to_str().unwrap(),
        "/login/?oauth_error=no_account"
    );

    // TOTP second step: admin enrols TOTP and require_totp_for_oauth is on.
    let resp = server
        .post("/api/v1/auth/totp/setup")
        .authorization_bearer(&token)
        .await;
    let secret = resp.json::<Value>()["secret"].as_str().unwrap().to_string();
    let code = crate::auth::totp::generate_current(&secret).unwrap();
    server
        .post("/api/v1/auth/totp/verify")
        .authorization_bearer(&token)
        .json(&json!({"code": &code}))
        .await
        .assert_status_ok();
    server
        .put("/api/v1/auth/settings")
        .authorization_bearer(&token)
        .json(&json!({"require_totp_for_oauth": true}))
        .await
        .assert_status_ok();
    *idp.userinfo.lock().unwrap() =
        json!({"sub": "sub-admin", "email": "admin", "email_verified": true});
    let st = start(&server, &idp_base).await;
    let resp = server
        .get(&format!(
            "/api/v1/auth/oauth/MockIdP/callback?code=goodcode&state={st}"
        ))
        .await;
    let loc = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    assert!(loc.starts_with("/login/?oauth_totp="), "{loc}");
    assert!(
        !resp.headers().contains_key("set-cookie"),
        "no session before TOTP"
    );
    let ticket = loc
        .trim_start_matches("/login/?oauth_totp=")
        .split('&')
        .next()
        .unwrap()
        .to_string();
    // Wrong code refused, ticket burnt.
    let resp = server
        .post("/api/v1/auth/oauth/totp")
        .json(&json!({"ticket": &ticket, "totp_code": "000000"}))
        .await;
    resp.assert_status(StatusCode::UNAUTHORIZED);
    let code = crate::auth::totp::generate_current(&secret).unwrap();
    let resp = server
        .post("/api/v1/auth/oauth/totp")
        .json(&json!({"ticket": &ticket, "totp_code": &code}))
        .await;
    resp.assert_status(StatusCode::UNAUTHORIZED); // single-use ticket
    // Fresh ticket + right code → session.
    let st = start(&server, &idp_base).await;
    let resp = server
        .get(&format!(
            "/api/v1/auth/oauth/MockIdP/callback?code=goodcode&state={st}"
        ))
        .await;
    let loc = resp
        .headers()
        .get("location")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();
    let ticket = loc
        .trim_start_matches("/login/?oauth_totp=")
        .split('&')
        .next()
        .unwrap()
        .to_string();
    let code = crate::auth::totp::generate_current(&secret).unwrap();
    let resp = server
        .post("/api/v1/auth/oauth/totp")
        .json(&json!({"ticket": &ticket, "totp_code": &code}))
        .await;
    resp.assert_status_ok();
    assert!(resp.json::<Value>()["access_token"].is_string());
    assert!(resp.headers().contains_key("set-cookie"));
}
