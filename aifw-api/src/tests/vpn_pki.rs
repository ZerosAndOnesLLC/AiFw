use super::*;

/// SEC-M14 #311 / SEC-M13 #310: ACME write endpoints validate the
/// operator-supplied URL / header at write time instead of storing a
/// value that can only fail (or pivot) later.
#[tokio::test]
async fn test_acme_target_and_account_reject_bad_input() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    // Webhook auth_header with CRLF is not a legal header value.
    let resp = server
        .post("/api/v1/acme/certs/1/targets")
        .authorization_bearer(&token)
        .json(&json!({
            "kind": "webhook",
            "config": {
                "url": "https://example.com/hook",
                "auth_header": "Bearer abc\r\nX-Injected: 1"
            }
        }))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    assert!(resp.text().contains("auth_header"), "{}", resp.text());

    // Webhook URL must pass the outbound allow-list (https, public host).
    let resp = server
        .post("/api/v1/acme/certs/1/targets")
        .authorization_bearer(&token)
        .json(&json!({
            "kind": "webhook",
            "config": { "url": "http://127.0.0.1:9/hook" }
        }))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    assert!(resp.text().contains("url"), "{}", resp.text());

    // Non-webhook kinds are not subject to the webhook checks: the
    // request gets past validation (cert 1 doesn't exist in this
    // fixture, so the insert itself fails on the FK — not a 400).
    let resp = server
        .post("/api/v1/acme/certs/1/targets")
        .authorization_bearer(&token)
        .json(&json!({ "kind": "local-tls-store", "config": {} }))
        .await;
    assert_ne!(
        resp.status_code(),
        StatusCode::BAD_REQUEST,
        "{}",
        resp.text()
    );

    // ACME directory URL: loopback / plaintext is refused up front.
    let resp = server
        .put("/api/v1/acme/account")
        .authorization_bearer(&token)
        .json(&json!({
            "directory_url": "http://127.0.0.1:14000/dir",
            "contact_email": "ops@example.com"
        }))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    assert!(resp.text().contains("directory_url"), "{}", resp.text());
}

#[tokio::test]
async fn test_ca_generate_honors_key_type() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    // Default (no key_type) stays ECDSA P-256.
    let resp = server
        .post("/api/v1/ca")
        .authorization_bearer(&token)
        .json(&json!({}))
        .await;
    resp.assert_status(StatusCode::CREATED);
    let body: Value = resp.json();
    assert_eq!(body["algorithm"], "ECDSA P-256");

    // rsa2048 is honored (regenerating replaces the CA).
    let resp = server
        .post("/api/v1/ca")
        .authorization_bearer(&token)
        .json(&json!({ "key_type": "rsa2048" }))
        .await;
    resp.assert_status(StatusCode::CREATED);
    let body: Value = resp.json();
    assert_eq!(body["algorithm"], "RSA-2048");

    // ...and the stored algorithm reflects it.
    let resp = server.get("/api/v1/ca").authorization_bearer(&token).await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["initialized"], true);
    assert_eq!(body["algorithm"], "RSA-2048");

    // Unknown key_type is rejected, not silently defaulted (#489).
    let resp = server
        .post("/api/v1/ca")
        .authorization_bearer(&token)
        .json(&json!({ "key_type": "dsa" }))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_issue_cert_honors_key_type() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let resp = server
        .post("/api/v1/ca")
        .authorization_bearer(&token)
        .json(&json!({}))
        .await;
    resp.assert_status(StatusCode::CREATED);

    // EC leaf (default) for a size baseline.
    let resp = server
        .post("/api/v1/ca/certs")
        .authorization_bearer(&token)
        .json(&json!({ "cert_type": "server", "common_name": "ec.example.com" }))
        .await;
    resp.assert_status(StatusCode::CREATED);
    let body: Value = resp.json();
    let ec_key_len = body["private_key_pem"].as_str().unwrap().len();

    // RSA-2048 leaf under the EC CA. PKCS#8 PEM headers are identical
    // across algorithms, so tell them apart by encoded key size — an
    // RSA-2048 private key is several times larger than a P-256 key.
    let resp = server
        .post("/api/v1/ca/certs")
        .authorization_bearer(&token)
        .json(&json!({
            "cert_type": "server",
            "common_name": "rsa.example.com",
            "key_type": "rsa2048"
        }))
        .await;
    resp.assert_status(StatusCode::CREATED);
    let body: Value = resp.json();
    let rsa_key_pem = body["private_key_pem"].as_str().unwrap();
    assert!(rsa_key_pem.contains("BEGIN PRIVATE KEY"));
    assert!(
        rsa_key_pem.len() > ec_key_len * 3,
        "rsa2048 key ({} bytes) should dwarf the EC key ({} bytes)",
        rsa_key_pem.len(),
        ec_key_len
    );

    // Unknown key_type is rejected before any cert is issued.
    let resp = server
        .post("/api/v1/ca/certs")
        .authorization_bearer(&token)
        .json(&json!({
            "cert_type": "server",
            "common_name": "bad.example.com",
            "key_type": "ed25519"
        }))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_ipsec_tunnel_crud_and_redaction() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    // Create — PSK must come back redacted
    let resp = server
        .post("/api/v1/vpn/ipsec/tunnels")
        .authorization_bearer(&token)
        .json(&ipsec_tunnel_body())
        .await;
    resp.assert_status(StatusCode::CREATED);
    let body: Value = resp.json();
    assert_eq!(body["data"]["name"], "site-a");
    assert_eq!(body["data"]["psk"], "REDACTED");
    assert_eq!(body["data"]["ike_proposal"], "aes256gcm16-prfsha256-ecp256");
    let id = body["data"]["id"].as_str().unwrap().to_string();

    // List
    let resp = server
        .get("/api/v1/vpn/ipsec/tunnels")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["data"].as_array().unwrap().len(), 1);
    assert_eq!(body["data"][0]["psk"], "REDACTED");

    // Update with redacted PSK keeps the stored secret and applies
    // the remote change
    let mut update = ipsec_tunnel_body();
    update["psk"] = json!("REDACTED");
    update["remote_addr"] = json!("203.0.113.99");
    let resp = server
        .put(&format!("/api/v1/vpn/ipsec/tunnels/{id}"))
        .authorization_bearer(&token)
        .json(&update)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["data"]["remote_addr"], "203.0.113.99");

    // Live status: mock control has no SAs → DOWN
    let resp = server
        .get(&format!("/api/v1/vpn/ipsec/tunnels/{id}/status"))
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["data"]["ike_state"], "DOWN");

    // Delete
    let resp = server
        .delete(&format!("/api/v1/vpn/ipsec/tunnels/{id}"))
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let resp = server
        .get("/api/v1/vpn/ipsec/tunnels")
        .authorization_bearer(&token)
        .await;
    let body: Value = resp.json();
    assert!(body["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_ipsec_tunnel_validation_surfaces_message() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let mut body = ipsec_tunnel_body();
    body["psk"] = json!("short");
    let resp = server
        .post("/api/v1/vpn/ipsec/tunnels")
        .authorization_bearer(&token)
        .json(&body)
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = resp.json();
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("PSK must be at least 16 characters"),
        "validation detail must reach the client: {body}"
    );
}

#[tokio::test]
async fn test_legacy_ipsec_sa_creation_gone() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let resp = server
        .post("/api/v1/vpn/ipsec")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "legacy",
            "local_addr": "1.2.3.4",
            "remote_addr": "5.6.7.8",
            "protocol": "esp",
            "mode": "tunnel",
        }))
        .await;
    resp.assert_status(StatusCode::GONE);
    let body: Value = resp.json();
    assert!(body["message"].as_str().unwrap().contains("tunnels"));
}

#[tokio::test]
async fn test_ipsec_status_endpoint_lists_all() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    server
        .post("/api/v1/vpn/ipsec/tunnels")
        .authorization_bearer(&token)
        .json(&ipsec_tunnel_body())
        .await
        .assert_status(StatusCode::CREATED);

    let resp = server
        .get("/api/v1/vpn/ipsec/status")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    let statuses = body["data"].as_array().unwrap();
    assert_eq!(statuses.len(), 1);
    assert_eq!(statuses[0]["ike_state"], "DOWN");
    assert!(
        statuses[0]["conn_name"]
            .as_str()
            .unwrap()
            .starts_with("aifw-")
    );
}
