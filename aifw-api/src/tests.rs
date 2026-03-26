#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use axum_test::TestServer;
    use serde_json::{json, Value};

    use crate::auth::AuthConfig;

    async fn test_app() -> (TestServer, AuthConfig) {
        let auth_config = AuthConfig {
            jwt_secret: "test-secret-key".to_string(),
            token_expiry_hours: 24,
        };

        let state = crate::create_app_state_in_memory(auth_config.clone())
            .await
            .unwrap();

        let app = crate::build_router(state);
        let server = TestServer::new(app).unwrap();
        (server, auth_config)
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

        // Login
        let resp = server
            .post("/api/v1/auth/login")
            .json(&json!({
                "username": "admin",
                "password": "testpass123"
            }))
            .await;

        let body: Value = resp.json();
        body["token"].as_str().unwrap().to_string()
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
        assert!(body["token"].as_str().is_some());
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
}
