#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use axum_test::TestServer;
    use serde_json::{json, Value};

    use crate::auth::AuthSettings;

    async fn test_app() -> (TestServer, AuthSettings) {
        let auth_settings = AuthSettings {
            jwt_secret: "test-secret-key".to_string(),
            access_token_expiry_mins: 60,
            refresh_token_expiry_days: 7,
            require_totp: false,
            require_totp_for_oauth: false,
            auto_create_oauth_users: true,
        };

        let state = crate::create_app_state_in_memory(auth_settings.clone())
            .await
            .unwrap();

        let app = crate::build_router(state);
        let server = TestServer::new(app).unwrap();
        (server, auth_settings)
    }

    async fn create_user_and_login(server: &TestServer) -> String {
        // Create user
        server
            .post("/api/v1/auth/users")
            .json(&json!({
                "username": "admin",
                "password": "testpass123"
            }))
            .await;

        // Login — now returns tokens object
        let resp = server
            .post("/api/v1/auth/login")
            .json(&json!({
                "username": "admin",
                "password": "testpass123"
            }))
            .await;

        let body: Value = resp.json();
        // New format: { tokens: { access_token, refresh_token, ... }, totp_required: false }
        body["tokens"]["access_token"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn test_create_user() {
        let (server, _) = test_app().await;

        let resp = server
            .post("/api/v1/auth/users")
            .json(&json!({
                "username": "admin",
                "password": "testpass123"
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
            .post("/api/v1/auth/users")
            .json(&json!({
                "username": "admin",
                "password": "testpass123"
            }))
            .await;

        let resp = server
            .post("/api/v1/auth/login")
            .json(&json!({
                "username": "admin",
                "password": "testpass123"
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
            .post("/api/v1/auth/users")
            .json(&json!({
                "username": "admin",
                "password": "testpass123"
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
    async fn test_protected_route_no_auth() {
        let (server, _) = test_app().await;

        let resp = server.get("/api/v1/rules").await;
        resp.assert_status(StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_list_rules_empty() {
        let (server, _) = test_app().await;
        let token = create_user_and_login(&server).await;

        let resp = server
            .get("/api/v1/rules")
            .authorization_bearer(&token)
            .await;

        resp.assert_status_ok();
        let body: Value = resp.json();
        assert_eq!(body["data"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn test_create_and_list_rule() {
        let (server, _) = test_app().await;
        let token = create_user_and_login(&server).await;

        let resp = server
            .post("/api/v1/rules")
            .authorization_bearer(&token)
            .json(&json!({
                "action": "block",
                "direction": "in",
                "protocol": "tcp",
                "dst_port_start": 22,
                "label": "block-ssh"
            }))
            .await;

        resp.assert_status(StatusCode::CREATED);
        let body: Value = resp.json();
        let rule_id = body["data"]["id"].as_str().unwrap().to_string();

        // List rules
        let resp = server
            .get("/api/v1/rules")
            .authorization_bearer(&token)
            .await;

        resp.assert_status_ok();
        let body: Value = resp.json();
        let rules = body["data"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["id"], rule_id);
    }

    #[tokio::test]
    async fn test_get_rule() {
        let (server, _) = test_app().await;
        let token = create_user_and_login(&server).await;

        let resp = server
            .post("/api/v1/rules")
            .authorization_bearer(&token)
            .json(&json!({
                "action": "pass",
                "direction": "in",
                "protocol": "tcp",
                "dst_port_start": 443,
            }))
            .await;

        let body: Value = resp.json();
        let id = body["data"]["id"].as_str().unwrap();

        let resp = server
            .get(&format!("/api/v1/rules/{id}"))
            .authorization_bearer(&token)
            .await;

        resp.assert_status_ok();
        let body: Value = resp.json();
        assert_eq!(body["data"]["id"], id);
    }

    #[tokio::test]
    async fn test_delete_rule() {
        let (server, _) = test_app().await;
        let token = create_user_and_login(&server).await;

        let resp = server
            .post("/api/v1/rules")
            .authorization_bearer(&token)
            .json(&json!({
                "action": "block",
                "direction": "in",
                "protocol": "any",
            }))
            .await;

        let body: Value = resp.json();
        let id = body["data"]["id"].as_str().unwrap();

        let resp = server
            .delete(&format!("/api/v1/rules/{id}"))
            .authorization_bearer(&token)
            .await;

        resp.assert_status_ok();

        // Verify deleted
        let resp = server
            .get("/api/v1/rules")
            .authorization_bearer(&token)
            .await;

        let body: Value = resp.json();
        assert_eq!(body["data"].as_array().unwrap().len(), 0);
    }

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
        assert_eq!(body["message"], "Rules reloaded");
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

    #[tokio::test]
    async fn test_nat_crud() {
        let (server, _) = test_app().await;
        let token = create_user_and_login(&server).await;

        // Create NAT rule
        let resp = server
            .post("/api/v1/nat")
            .authorization_bearer(&token)
            .json(&json!({
                "nat_type": "snat",
                "interface": "em0",
                "protocol": "any",
                "src_addr": "192.168.1.0/24",
                "redirect_addr": "203.0.113.1",
            }))
            .await;

        resp.assert_status(StatusCode::CREATED);
        let body: Value = resp.json();
        let id = body["data"]["id"].as_str().unwrap().to_string();

        // List NAT rules
        let resp = server
            .get("/api/v1/nat")
            .authorization_bearer(&token)
            .await;

        resp.assert_status_ok();
        let body: Value = resp.json();
        assert_eq!(body["data"].as_array().unwrap().len(), 1);

        // Delete
        let resp = server
            .delete(&format!("/api/v1/nat/{id}"))
            .authorization_bearer(&token)
            .await;

        resp.assert_status_ok();
    }

    // --- New auth system tests ---

    #[tokio::test]
    async fn test_refresh_token_flow() {
        let (server, _) = test_app().await;

        server
            .post("/api/v1/auth/users")
            .json(&json!({"username": "rfuser", "password": "pass123"}))
            .await;

        // Login to get tokens
        let resp = server
            .post("/api/v1/auth/login")
            .json(&json!({"username": "rfuser", "password": "pass123"}))
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
            .post("/api/v1/auth/users")
            .json(&json!({"username": "reuseuser", "password": "pass123"}))
            .await;

        let resp = server
            .post("/api/v1/auth/login")
            .json(&json!({"username": "reuseuser", "password": "pass123"}))
            .await;

        let body: Value = resp.json();
        let old_refresh = body["tokens"]["refresh_token"].as_str().unwrap().to_string();

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
            .post("/api/v1/auth/users")
            .json(&json!({"username": "logoutuser", "password": "pass123"}))
            .await;

        let resp = server
            .post("/api/v1/auth/login")
            .json(&json!({"username": "logoutuser", "password": "pass123"}))
            .await;

        let body: Value = resp.json();
        let access = body["tokens"]["access_token"].as_str().unwrap().to_string();
        let refresh = body["tokens"]["refresh_token"].as_str().unwrap().to_string();

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
        assert!(body["provisioning_uri"].as_str().unwrap().starts_with("otpauth://"));
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
            .json(&json!({"username": "admin", "password": "testpass123"}))
            .await;

        let body: Value = resp.json();
        assert_eq!(body["totp_required"], true);
        assert!(body["tokens"].is_null() || body["access_token"].is_null());

        // Complete login with TOTP
        let code = crate::auth::totp::generate_current(&secret).unwrap();
        let resp = server
            .post("/api/v1/auth/totp/login")
            .json(&json!({"username": "admin", "totp_code": &code}))
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
            .json(&json!({"username": "admin", "totp_code": &recovery}))
            .await;

        resp.assert_status_ok();

        // Same recovery code should not work again
        let resp = server
            .post("/api/v1/auth/totp/login")
            .json(&json!({"username": "admin", "totp_code": &recovery}))
            .await;

        resp.assert_status(StatusCode::UNAUTHORIZED);
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
}
