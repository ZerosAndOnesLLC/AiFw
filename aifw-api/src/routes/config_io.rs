//! `/api/v1/config` handlers — export the running configuration as JSON
//! and restore it from a previously exported backup.

use super::*;

pub async fn export_config(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let config = crate::backup::build_current_config(&state).await?;

    let routes = sqlx::query_as::<_, (String, String, String, Option<String>, i32, bool, Option<String>, String)>(
        "SELECT id, destination, gateway, interface, metric, enabled, description, created_at FROM static_routes ORDER BY metric ASC",
    ).fetch_all(&state.pool).await.unwrap_or_default();

    let static_routes: Vec<serde_json::Value> = routes.iter().map(|(id, d, g, i, m, e, desc, ca)| {
        serde_json::json!({"id": id, "destination": d, "gateway": g, "interface": i, "metric": m, "enabled": e, "description": desc, "created_at": ca})
    }).collect();

    Ok(Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "config": config,
        "static_routes": static_routes,
    })))
}

pub async fn import_config(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let config_val = payload.get("config").ok_or(StatusCode::BAD_REQUEST)?;
    // Strict deserialization: FirewallConfig uses deny_unknown_fields, so a
    // backup that tries to smuggle in a field we don't recognise is rejected
    // here rather than silently restored with the unknown fields ignored.
    let config: aifw_core::config::FirewallConfig = serde_json::from_value(config_val.clone())
        .map_err(|e| {
            tracing::warn!(error = %e, "import_config rejected malformed backup");
            StatusCode::BAD_REQUEST
        })?;
    // Structural sanity — size caps, schema version, DNS + hostname shape.
    if let Err(e) = config.validate() {
        tracing::warn!(error = %e, "import_config rejected invalid backup");
        return Err(StatusCode::BAD_REQUEST);
    }

    let iface_map: crate::backup::InterfaceMap = payload
        .get("interface_map")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let rules_n = config.rules.len();
    let nat_n = config.nat.len();
    let geoip_n = config.geoip.len();
    let wg_n = config.vpn.wireguard.len();
    let ipsec_n = config.vpn.ipsec.len();
    let dns_n = config.system.dns_servers.len();

    crate::backup::apply_firewall_config(&state, &config, &iface_map).await?;

    let _ = sqlx::query("DELETE FROM static_routes")
        .execute(&state.pool)
        .await;
    let mut routes_n = 0;
    if let Some(routes) = payload.get("static_routes").and_then(|v| v.as_array()) {
        for route in routes {
            let dest = route
                .get("destination")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let gw = route.get("gateway").and_then(|v| v.as_str()).unwrap_or("");
            if dest.is_empty() || gw.is_empty() {
                continue;
            }
            let iface = route.get("interface").and_then(|v| v.as_str());
            let metric = route.get("metric").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            let enabled = route
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(true);
            let desc = route.get("description").and_then(|v| v.as_str());
            let id = route
                .get("id")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let created_at = route
                .get("created_at")
                .and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
            let _ = sqlx::query(
                "INSERT INTO static_routes (id, destination, gateway, interface, metric, enabled, description, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)")
                .bind(&id).bind(dest).bind(gw).bind(iface).bind(metric).bind(enabled).bind(desc).bind(&created_at)
                .execute(&state.pool).await;
            routes_n += 1;
        }
    }

    let msg = format!(
        "Imported: {rules_n} rules, {nat_n} NAT, {geoip_n} geo-IP, {wg_n} WireGuard, {ipsec_n} IPsec, {dns_n} DNS, {routes_n} static routes"
    );
    Ok(Json(MessageResponse { message: msg }))
}
