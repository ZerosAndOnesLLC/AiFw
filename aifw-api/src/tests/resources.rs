//! Round-trip coverage for API resources that had no integration tests
//! (#442): geo-IP, WireGuard tunnels/peers, IDS endpoints without the IDS process,
//! DHCP subnets/reservations, DNS resolver host overrides. Each test drives
//! create → list → get/update → delete and one validation rejection.

use super::*;

#[tokio::test]
async fn geoip_rules_round_trip_and_reject_bad_country() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let resp = server
        .post("/api/v1/geoip")
        .authorization_bearer(&token)
        .json(&json!({"country_code": "CN", "action": "block"}))
        .await;
    assert!(resp.status_code().is_success(), "{}", resp.text());
    let created: Value = resp.json();
    let id = created["data"]["id"].as_str().unwrap().to_string();

    let resp = server
        .get("/api/v1/geoip")
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let list: Value = resp.json();
    assert_eq!(list["data"].as_array().unwrap().len(), 1);
    assert_eq!(list["data"][0]["country"], "CN");

    // Not a real ISO code → 400, list unchanged.
    let resp = server
        .post("/api/v1/geoip")
        .authorization_bearer(&token)
        .json(&json!({"country_code": "XYZ", "action": "block"}))
        .await;
    assert!(resp.status_code().is_client_error(), "{}", resp.text());
    let resp = server
        .post("/api/v1/geoip")
        .authorization_bearer(&token)
        .json(&json!({"country_code": "US", "action": "nuke"}))
        .await;
    assert!(
        resp.status_code().is_client_error(),
        "bad action: {}",
        resp.text()
    );

    server
        .delete(&format!("/api/v1/geoip/{id}"))
        .authorization_bearer(&token)
        .await
        .assert_status_ok();
    let list: Value = server
        .get("/api/v1/geoip")
        .authorization_bearer(&token)
        .await
        .json();
    assert!(list["data"].as_array().unwrap().is_empty());

    // Unauthenticated read is refused.
    server
        .get("/api/v1/geoip")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn geoip_database_upload_counts_cidrs_and_fills_tables() {
    use axum_test::multipart::{MultipartForm, Part};
    let (_, settings) = test_app().await;
    let state = crate::create_app_state_in_memory(settings).await.unwrap();
    let dir = std::env::temp_dir().join(format!("aifw-geoip-api-{}", uuid::Uuid::new_v4()));
    state.geoip_engine.set_db_dir(&dir).await.unwrap();
    let pf = state.pf.clone();
    let server = TestServer::new(crate::build_router(state, None, "*", false));
    let token = create_user_and_login(&server).await;

    // Nothing loaded yet.
    let st: Value = server
        .get("/api/v1/geoip/database")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(st["loaded"], false);
    assert_eq!(st["has_license_key"], false);

    // A rule for a country counts zero CIDRs until a database exists.
    let created: Value = server
        .post("/api/v1/geoip")
        .authorization_bearer(&token)
        .json(&json!({"country": "CN", "action": "block"}))
        .await
        .json();
    let id = created["data"]["id"].as_str().unwrap().to_string();
    let list: Value = server
        .get("/api/v1/geoip")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(list["data"][0]["country"], "CN");
    assert_eq!(list["data"][0]["cidr_count"], 0);
    assert_eq!(list["data"][0]["table"], "geoip_cn");

    // Upload the CSV release as separate files.
    let blocks = "network,geoname_id,registered_country_geoname_id\n\
                  1.0.2.0/24,1814991,1814991\n1.0.3.0/24,1814991,1814991\n";
    let locations = "geoname_id,locale_code,continent_code,continent_name,country_iso_code\n\
                     1814991,en,AS,Asia,CN\n";
    let form = MultipartForm::new()
        .add_part(
            "blocks",
            Part::text(blocks).file_name("GeoLite2-Country-Blocks-IPv4.csv"),
        )
        .add_part(
            "locations",
            Part::text(locations).file_name("GeoLite2-Country-Locations-en.csv"),
        );
    let resp = server
        .post("/api/v1/geoip/database/upload")
        .authorization_bearer(&token)
        .multipart(form)
        .await;
    assert!(resp.status_code().is_success(), "{}", resp.text());
    let up: Value = resp.json();
    assert_eq!(up["cidrs"], 1, "aligned /24 pair aggregates to one /23");
    assert_eq!(up["status"]["source"], "upload");

    // The rule now reports its CIDRs and the pf table is filled.
    let list: Value = server
        .get("/api/v1/geoip")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(list["data"][0]["cidr_count"], 1);
    assert_eq!(pf.get_table_entries("geoip_cn").await.unwrap().len(), 1);
    let anchor = pf.get_rules("aifw-geoip").await.unwrap();
    assert_eq!(anchor.len(), 1);
    assert!(anchor[0].starts_with("block drop in quick from <geoip_cn>"));

    // Settings: a key is stored but never returned; a bad key is refused.
    let st: Value = server
        .put("/api/v1/geoip/database")
        .authorization_bearer(&token)
        .json(&json!({"license_key": "abcDEF0123456789", "update_interval_hours": 24}))
        .await
        .json();
    assert_eq!(st["has_license_key"], true);
    assert_eq!(st["update_interval_hours"], 24);
    assert!(st.get("license_key").is_none());
    assert!(st["next_refresh"].is_string());
    server
        .put("/api/v1/geoip/database")
        .authorization_bearer(&token)
        .json(&json!({"license_key": "bad key!"}))
        .await
        .assert_status(StatusCode::BAD_REQUEST);
    let st: Value = server
        .put("/api/v1/geoip/database")
        .authorization_bearer(&token)
        .json(&json!({"license_key": null}))
        .await
        .json();
    assert_eq!(st["has_license_key"], false);

    // Refresh without a key explains itself instead of 500ing.
    let resp = server
        .post("/api/v1/geoip/database/refresh")
        .authorization_bearer(&token)
        .await;
    assert_eq!(resp.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(resp.text().contains("license key"), "{}", resp.text());

    // Garbage upload is a 400 and leaves the loaded release alone.
    let resp = server
        .post("/api/v1/geoip/database/upload")
        .authorization_bearer(&token)
        .multipart(MultipartForm::new().add_part("f", Part::text("x").file_name("evil.sh")))
        .await;
    assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);
    let st: Value = server
        .get("/api/v1/geoip/database")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(st["cidrs"], 1);

    // Deleting the rule empties the table and the anchor.
    server
        .delete(&format!("/api/v1/geoip/{id}"))
        .authorization_bearer(&token)
        .await
        .assert_status_ok();
    assert!(pf.get_table_entries("geoip_cn").await.unwrap().is_empty());
    assert!(pf.get_rules("aifw-geoip").await.unwrap().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn wireguard_tunnel_and_peer_round_trip() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let resp = server
        .post("/api/v1/vpn/wg")
        .authorization_bearer(&token)
        .json(&json!({"name": "wg-office", "listen_port": 51820, "address": "10.66.0.1/24"}))
        .await;
    assert!(resp.status_code().is_success(), "{}", resp.text());
    let t: Value = resp.json();
    let tid = t["data"]["id"].as_str().unwrap().to_string();
    // Key pair generated server-side.
    assert!(
        t["data"]["public_key"]
            .as_str()
            .map(|k| !k.is_empty())
            .unwrap_or(false)
    );

    let resp = server
        .post(&format!("/api/v1/vpn/wg/{tid}/peers"))
        .authorization_bearer(&token)
        .json(&json!({"name": "laptop", "auto_generate_key": true, "allowed_ips": "10.66.0.2/32"}))
        .await;
    assert!(resp.status_code().is_success(), "{}", resp.text());
    let p: Value = resp.json();
    let pid = p["data"]["id"].as_str().unwrap().to_string();

    // next-ip skips the address the peer just took.
    let resp = server
        .get(&format!("/api/v1/vpn/wg/{tid}/peers/next-ip"))
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let next = resp.text();
    assert!(
        !next.contains("10.66.0.2/32"),
        "next-ip must skip the used address: {next}"
    );

    let resp = server
        .get(&format!("/api/v1/vpn/wg/{tid}/peers"))
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.json::<Value>()["data"].as_array().unwrap().len(), 1);

    // Client config export renders a [Peer] section pointing at our public key.
    let resp = server
        .get(&format!("/api/v1/vpn/wg/{tid}/peers/{pid}/config"))
        .authorization_bearer(&token)
        .await;
    resp.assert_status_ok();
    let cfg = resp.text();
    assert!(
        cfg.contains("[Interface]") && cfg.contains("[Peer]"),
        "{cfg}"
    );

    // Bad address is rejected.
    let resp = server
        .post("/api/v1/vpn/wg")
        .authorization_bearer(&token)
        .json(&json!({"name": "bad", "listen_port": 51821, "address": "not-an-address"}))
        .await;
    assert!(resp.status_code().is_client_error(), "{}", resp.text());

    server
        .delete(&format!("/api/v1/vpn/wg/{tid}/peers/{pid}"))
        .authorization_bearer(&token)
        .await
        .assert_status_ok();
    server
        .delete(&format!("/api/v1/vpn/wg/{tid}"))
        .authorization_bearer(&token)
        .await
        .assert_status_ok();
    let list: Value = server
        .get("/api/v1/vpn/wg")
        .authorization_bearer(&token)
        .await
        .json();
    assert!(list["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn wireguard_private_key_is_write_only() {
    // #691: the tunnel's private key must never come back from the API —
    // not on create, list, or update — and an update without a key must
    // keep the stored one.
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;
    let no_key = |v: &Value| {
        assert!(v.get("private_key").is_none(), "private key leaked: {v}");
    };

    let resp = server
        .post("/api/v1/vpn/wg")
        .authorization_bearer(&token)
        .json(&json!({"name": "wg-keys", "listen_port": 51830, "address": "10.67.0.1/24"}))
        .await;
    assert!(resp.status_code().is_success(), "{}", resp.text());
    let created: Value = resp.json();
    no_key(&created["data"]);
    let tid = created["data"]["id"].as_str().unwrap().to_string();
    let pubkey = created["data"]["public_key"].as_str().unwrap().to_string();

    let list: Value = server
        .get("/api/v1/vpn/wg")
        .authorization_bearer(&token)
        .await
        .json();
    for t in list["data"].as_array().unwrap() {
        no_key(t);
    }

    // Update with an empty key keeps the keypair.
    let resp = server
        .put(&format!("/api/v1/vpn/wg/{tid}"))
        .authorization_bearer(&token)
        .json(&json!({"name": "wg-keys", "listen_port": 51830, "address": "10.67.0.1/24", "private_key": ""}))
        .await;
    assert!(resp.status_code().is_success(), "{}", resp.text());
    let updated: Value = resp.json();
    no_key(&updated["data"]);
    assert_eq!(
        updated["data"]["public_key"].as_str(),
        Some(pubkey.as_str())
    );

    // Update with a new key replaces it and re-derives the public key.
    let (new_priv, new_pub) = aifw_common::vpn::generate_wg_keypair().unwrap();
    let resp = server
        .put(&format!("/api/v1/vpn/wg/{tid}"))
        .authorization_bearer(&token)
        .json(&json!({"name": "wg-keys", "listen_port": 51830, "address": "10.67.0.1/24", "private_key": new_priv}))
        .await;
    assert!(resp.status_code().is_success(), "{}", resp.text());
    let rotated: Value = resp.json();
    no_key(&rotated["data"]);
    assert_eq!(
        rotated["data"]["public_key"].as_str(),
        Some(new_pub.as_str())
    );
}

#[tokio::test]
async fn ids_endpoints_degrade_cleanly_without_the_ids_process() {
    // The IDS config and alert/suppression tables belong to the aifw-ids
    // process (IPC + its own schema). Without it the API must answer 503
    // for the config, never 500, and auth still gates everything.
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;
    let resp = server
        .get("/api/v1/ids/config")
        .authorization_bearer(&token)
        .await;
    assert!(
        resp.status_code() == StatusCode::OK
            || resp.status_code() == StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        resp.text()
    );
    server
        .get("/api/v1/ids/config")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    // Unknown suppress_type is a client error regardless of IDS state.
    let resp = server
        .post("/api/v1/ids/suppressions")
        .authorization_bearer(&token)
        .json(&json!({"sid": 1, "suppress_type": "by_magic", "ip_cidr": "10.0.0.0/8"}))
        .await;
    assert!(resp.status_code().is_client_error(), "{}", resp.text());
}

#[tokio::test]
async fn dhcp_subnets_and_reservations_round_trip() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let resp = server
        .post("/api/v1/dhcp/v4/subnets")
        .authorization_bearer(&token)
        .json(&json!({
            "network": "192.168.50.0/24", "pool_start": "192.168.50.100",
            "pool_end": "192.168.50.200", "gateway": "192.168.50.1",
            "dns_servers": ["192.168.50.1"], "lease_time": 3600
        }))
        .await;
    assert!(resp.status_code().is_success(), "{}", resp.text());
    let sub: Value = resp.json();
    let sub_id = sub["data"]["id"].as_str().unwrap().to_string();
    assert_eq!(sub["data"]["network"], "192.168.50.0/24");

    let list: Value = server
        .get("/api/v1/dhcp/v4/subnets")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(list["data"].as_array().unwrap().len(), 1);

    // Pool outside the network is rejected.
    let resp = server
        .post("/api/v1/dhcp/v4/subnets")
        .authorization_bearer(&token)
        .json(&json!({
            "network": "192.168.60.0/24", "pool_start": "10.0.0.5",
            "pool_end": "10.0.0.9", "gateway": "192.168.60.1"
        }))
        .await;
    assert!(resp.status_code().is_client_error(), "{}", resp.text());

    let resp = server
        .post("/api/v1/dhcp/v4/reservations")
        .authorization_bearer(&token)
        .json(&json!({
            "subnet_id": sub_id, "mac_address": "aa:bb:cc:dd:ee:ff",
            "ip_address": "192.168.50.10", "hostname": "printer"
        }))
        .await;
    assert!(resp.status_code().is_success(), "{}", resp.text());
    let res: Value = resp.json();
    let res_id = res["data"]["id"].as_str().unwrap().to_string();

    // Malformed MAC rejected.
    let resp = server
        .post("/api/v1/dhcp/v4/reservations")
        .authorization_bearer(&token)
        .json(&json!({"mac_address": "not-a-mac", "ip_address": "192.168.50.11"}))
        .await;
    assert!(resp.status_code().is_client_error(), "{}", resp.text());

    let list: Value = server
        .get("/api/v1/dhcp/v4/reservations")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(list["data"].as_array().unwrap().len(), 1);
    assert_eq!(list["data"][0]["hostname"], "printer");

    server
        .delete(&format!("/api/v1/dhcp/v4/reservations/{res_id}"))
        .authorization_bearer(&token)
        .await
        .assert_status_ok();
    server
        .delete(&format!("/api/v1/dhcp/v4/subnets/{sub_id}"))
        .authorization_bearer(&token)
        .await
        .assert_status_ok();
    let list: Value = server
        .get("/api/v1/dhcp/v4/subnets")
        .authorization_bearer(&token)
        .await
        .json();
    assert!(list["data"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn dns_resolver_host_overrides_round_trip() {
    let (server, _) = test_app().await;
    let token = create_user_and_login(&server).await;

    let resp = server
        .post("/api/v1/dns/resolver/hosts")
        .authorization_bearer(&token)
        .json(&json!({"hostname": "nas", "domain": "home.arpa", "value": "192.168.1.20"}))
        .await;
    assert!(resp.status_code().is_success(), "{}", resp.text());
    let h: Value = resp.json();
    let hid = h["data"]["id"].as_str().unwrap().to_string();
    assert_eq!(h["data"]["record_type"], "A", "record type defaults to A");

    // AAAA with a v4 value is inconsistent → rejected.
    let resp = server
        .post("/api/v1/dns/resolver/hosts")
        .authorization_bearer(&token)
        .json(&json!({"hostname": "bad", "domain": "home.arpa", "record_type": "AAAA", "value": "192.168.1.21"}))
        .await;
    assert!(resp.status_code().is_client_error(), "{}", resp.text());

    let list: Value = server
        .get("/api/v1/dns/resolver/hosts")
        .authorization_bearer(&token)
        .await
        .json();
    assert_eq!(list["data"].as_array().unwrap().len(), 1);

    server
        .delete(&format!("/api/v1/dns/resolver/hosts/{hid}"))
        .authorization_bearer(&token)
        .await
        .assert_status_ok();
    let list: Value = server
        .get("/api/v1/dns/resolver/hosts")
        .authorization_bearer(&token)
        .await
        .json();
    assert!(list["data"].as_array().unwrap().is_empty());
}
