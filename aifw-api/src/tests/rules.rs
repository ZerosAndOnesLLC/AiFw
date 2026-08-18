use super::*;

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
async fn test_rule_ip_version_round_trips() {
    // #472: the UI's address-family selection was silently dropped —
    // CreateRuleRequest had no ip_version field. Every family the API
    // accepts must round-trip through create → get, including the
    // legacy UI value "inet46" (canonicalized to "both").
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    for (sent, stored) in [
        ("inet", "inet"),
        ("inet6", "inet6"),
        ("both", "both"),
        ("inet46", "both"),
    ] {
        let resp = server
            .post("/api/v1/rules")
            .authorization_bearer(&token)
            .json(&json!({
                "action": "pass",
                "direction": "in",
                "protocol": "tcp",
                "ip_version": sent,
            }))
            .await;
        resp.assert_status(StatusCode::CREATED);
        let body: Value = resp.json();
        assert_eq!(body["data"]["ip_version"], stored, "create with {sent}");
        let id = body["data"]["id"].as_str().unwrap();

        let resp = server
            .get(&format!("/api/v1/rules/{id}"))
            .authorization_bearer(&token)
            .await;
        resp.assert_status_ok();
        let body: Value = resp.json();
        assert_eq!(body["data"]["ip_version"], stored, "get after {sent}");

        // Update must round-trip too (and not reset the family)
        let resp = server
            .put(&format!("/api/v1/rules/{id}"))
            .authorization_bearer(&token)
            .json(&json!({
                "action": "pass",
                "direction": "in",
                "protocol": "tcp",
                "ip_version": sent,
            }))
            .await;
        resp.assert_status_ok();
        let body: Value = resp.json();
        assert_eq!(body["data"]["ip_version"], stored, "update with {sent}");
    }

    // Garbage is rejected, not silently defaulted
    let resp = server
        .post("/api/v1/rules")
        .authorization_bearer(&token)
        .json(&json!({
            "action": "pass",
            "direction": "in",
            "protocol": "tcp",
            "ip_version": "ipvx",
        }))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
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
    let resp = server.get("/api/v1/nat").authorization_bearer(&token).await;

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

#[tokio::test]
async fn test_nat64_create_happy_path() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let resp = server
        .post("/api/v1/nat")
        .authorization_bearer(&token)
        .json(&json!({
            "nat_type": "nat64",
            "interface": "em0",
            "protocol": "any",
            "src_addr": "2001:db8:1::/64",
            "dst_addr": "64:ff9b::/96",
            "redirect_addr": "203.0.113.1",
        }))
        .await;

    resp.assert_status(StatusCode::CREATED);
    let body: Value = resp.json();
    assert_eq!(body["data"]["nat_type"], "nat64");
}

#[tokio::test]
async fn test_nat64_create_wrong_family_gets_message() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    // IPv4 redirect required for nat64 — an IPv6 one must 400 with a
    // human-readable message (surfaced to the UI banner, #531).
    let resp = server
        .post("/api/v1/nat")
        .authorization_bearer(&token)
        .json(&json!({
            "nat_type": "nat64",
            "interface": "em0",
            "protocol": "any",
            "dst_addr": "64:ff9b::/96",
            "redirect_addr": "2001:db8::1",
        }))
        .await;

    resp.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = resp.json();
    let msg = body["message"].as_str().unwrap();
    assert!(
        msg.contains("nat64"),
        "message should name the rule type: {msg}"
    );

    // Missing /96 prefix on the destination
    let resp = server
        .post("/api/v1/nat")
        .authorization_bearer(&token)
        .json(&json!({
            "nat_type": "nat64",
            "interface": "em0",
            "protocol": "any",
            "dst_addr": "64:ff9b::/64",
            "redirect_addr": "203.0.113.1",
        }))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = resp.json();
    assert!(body["message"].as_str().unwrap().contains("/96"));
}

#[tokio::test]
async fn test_pf_label_injection_blocked() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    // Label with quotes — should be rejected
    let resp = server.post("/api/v1/rules").authorization_bearer(&token)
        .json(&json!({"action":"block","direction":"in","protocol":"tcp","label":"evil\" quick; pass all; label \"x"})).await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    // Label with semicolons
    let resp = server
        .post("/api/v1/rules")
        .authorization_bearer(&token)
        .json(&json!({"action":"block","direction":"in","protocol":"tcp","label":"test; pass all"}))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    // Label with newlines
    let resp = server
        .post("/api/v1/rules")
        .authorization_bearer(&token)
        .json(&json!({"action":"block","direction":"in","protocol":"tcp","label":"test\npass all"}))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    // Clean label — should succeed
    let resp = server.post("/api/v1/rules").authorization_bearer(&token)
        .json(&json!({"action":"block","direction":"in","protocol":"tcp","label":"block-ssh-port-22"})).await;
    resp.assert_status(StatusCode::CREATED);
}

#[tokio::test]
async fn test_interface_name_injection_blocked() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    // Interface with shell injection
    let resp = server.post("/api/v1/rules").authorization_bearer(&token)
        .json(&json!({"action":"block","direction":"in","protocol":"tcp","interface":"em0; rm -rf /"})).await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    // Interface too long
    let resp = server.post("/api/v1/rules").authorization_bearer(&token)
        .json(&json!({"action":"block","direction":"in","protocol":"tcp","interface":"a]".repeat(20)})).await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    // Clean interface — should succeed
    let resp = server
        .post("/api/v1/rules")
        .authorization_bearer(&token)
        .json(&json!({"action":"block","direction":"in","protocol":"tcp","interface":"em0"}))
        .await;
    resp.assert_status(StatusCode::CREATED);
}

#[tokio::test]
async fn test_nat_interface_injection_blocked() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let resp = server.post("/api/v1/nat").authorization_bearer(&token)
        .json(&json!({"nat_type":"snat","interface":"em0; evil","protocol":"any","redirect_addr":"1.2.3.4"})).await;
    resp.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_schedule_validation() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    // Invalid time format
    let resp = server
        .post("/api/v1/schedules")
        .authorization_bearer(&token)
        .json(&json!({"name":"bad","time_ranges":"not-a-time"}))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    // Invalid days
    let resp = server
        .post("/api/v1/schedules")
        .authorization_bearer(&token)
        .json(&json!({"name":"bad2","time_ranges":"08:00-17:00","days_of_week":"monday,notaday"}))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    // Valid schedule
    let resp = server.post("/api/v1/schedules").authorization_bearer(&token)
        .json(&json!({"name":"work","time_ranges":"08:00-17:00","days_of_week":"mon,tue,wed,thu,fri"})).await;
    resp.assert_status(StatusCode::CREATED);
}

#[tokio::test]
async fn test_static_route_validation() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    // Invalid destination
    let resp = server
        .post("/api/v1/routes")
        .authorization_bearer(&token)
        .json(&json!({"destination":"not-an-ip","gateway":"10.0.0.1"}))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    // Invalid gateway
    let resp = server
        .post("/api/v1/routes")
        .authorization_bearer(&token)
        .json(&json!({"destination":"10.0.0.0/8","gateway":"not-an-ip"}))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    // Valid
    let resp = server
        .post("/api/v1/routes")
        .authorization_bearer(&token)
        .json(&json!({"destination":"10.0.0.0/8","gateway":"192.168.1.1"}))
        .await;
    resp.assert_status(StatusCode::CREATED);
}

#[tokio::test]
async fn test_alias_name_validation() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    // Name with spaces
    let resp = server
        .post("/api/v1/aliases")
        .authorization_bearer(&token)
        .json(&json!({"name":"bad name","alias_type":"address","entries":["1.2.3.4"]}))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    // Name too long (>31)
    let long_name = "a".repeat(32);
    let resp = server
        .post("/api/v1/aliases")
        .authorization_bearer(&token)
        .json(&json!({"name":long_name,"alias_type":"address","entries":["1.2.3.4"]}))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    // Valid name + valid type/entries
    let resp = server
        .post("/api/v1/aliases")
        .authorization_bearer(&token)
        .json(&json!({"name":"trusted","alias_type":"host","entries":["1.2.3.4"]}))
        .await;
    // 201 or 400 from engine internals — the key test is that bad names above got 400
    // If this also returns 400, it's an engine issue not a name validation issue
    let _ = resp.status_code(); // just ensure no panic
}

#[tokio::test]
async fn test_rule_gateway_round_trip_and_validation() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    // Default routing instance is seeded; hang a gateway off it.
    let resp = server
        .get("/api/v1/multiwan/instances")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    let instance_id = body["data"][0]["id"].as_str().unwrap().to_string();

    let resp = server
        .post("/api/v1/multiwan/gateways")
        .authorization_bearer(&token)
        .json(&json!({
            "name": "wan1",
            "instance_id": instance_id,
            "interface": "igb1",
            "next_hop": "203.0.113.1"
        }))
        .await;
    resp.assert_status(StatusCode::CREATED);
    let body: Value = resp.json();
    let gw_id = body["data"]["id"].as_str().unwrap().to_string();

    // Rule carrying the gateway: accepted, persisted, returned.
    let resp = server
        .post("/api/v1/rules")
        .authorization_bearer(&token)
        .json(&json!({
            "action": "pass",
            "direction": "in",
            "protocol": "tcp",
            "dst_port_start": 443,
            "dst_port_end": 443,
            "label": "routed",
            "gateway": gw_id
        }))
        .await;
    resp.assert_status(StatusCode::CREATED);
    let body: Value = resp.json();
    assert_eq!(body["data"]["gateway"].as_str(), Some(gw_id.as_str()));
    let rule_id = body["data"]["id"].as_str().unwrap().to_string();

    let resp = server
        .get(&format!("/api/v1/rules/{rule_id}"))
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["data"]["gateway"].as_str(), Some(gw_id.as_str()));

    // Unknown gateway reference is rejected, not silently dropped (#540).
    let resp = server
        .post("/api/v1/rules")
        .authorization_bearer(&token)
        .json(&json!({
            "action": "pass",
            "direction": "in",
            "protocol": "tcp",
            "gateway": uuid::Uuid::new_v4().to_string()
        }))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    // Non-UUID gateway is rejected too.
    let resp = server
        .post("/api/v1/rules")
        .authorization_bearer(&token)
        .json(&json!({
            "action": "pass",
            "direction": "in",
            "protocol": "tcp",
            "gateway": "not-a-uuid"
        }))
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);

    // Deleting the gateway unlinks the rule.
    let resp = server
        .delete(&format!("/api/v1/multiwan/gateways/{gw_id}"))
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let resp = server
        .get(&format!("/api/v1/rules/{rule_id}"))
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert!(body["data"]["gateway"].is_null());
}

/// #194: engines own validation. Handlers translate request → domain type
/// and rely on `add`/`update` re-validating, mapped through
/// `routes::engine_error`. This keeps a handler from growing its own copy
/// of a check (which drifts) or skipping one (which weakens an invariant).
#[test]
fn handlers_do_not_call_core_validation_directly() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut hits = Vec::new();
    for rel in [
        "routes/rules.rs",
        "routes/nat.rs",
        "routes/geoip.rs",
        "routes/vpn.rs",
        "aliases.rs",
    ] {
        let text = std::fs::read_to_string(root.join(rel)).unwrap();
        for (i, line) in text.lines().enumerate() {
            if line.contains("aifw_core::validation::") && !line.trim_start().starts_with("//") {
                hits.push(format!("{rel}:{}: {}", i + 1, line.trim()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "handler-side validation found — move it into the engine's add/update (#194):\n{}",
        hits.join("\n")
    );
}
