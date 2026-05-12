//! `/api/v1/geoip` handlers — country-based blocking rules and a
//! reverse lookup. Extracted from the legacy 4000-line `routes.rs` God
//! module (#187).
//!
//! Shared helpers (`bad_request`, `internal`) live in `super`
//! (`routes/mod.rs`) and are imported via the wildcard at the top.

use super::*;
use aifw_common::{CountryCode, GeoIpAction, GeoIpRule, GeoIpRuleStatus};

#[derive(Debug, Deserialize)]
pub struct CreateGeoIpRuleRequest {
    pub country_code: String,
    pub action: String,
    pub status: Option<String>,
}

pub async fn list_geoip_rules(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<GeoIpRule>>>, StatusCode> {
    let rules = state
        .geoip_engine
        .list_rules()
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: rules }))
}

pub async fn create_geoip_rule(
    State(state): State<AppState>,
    Json(req): Json<CreateGeoIpRuleRequest>,
) -> Result<(StatusCode, Json<ApiResponse<GeoIpRule>>), StatusCode> {
    let country = CountryCode::new(&req.country_code).map_err(|_| bad_request())?;
    let action = GeoIpAction::parse(&req.action).map_err(|_| bad_request())?;
    let rule = GeoIpRule::new(country, action);
    let rule = state
        .geoip_engine
        .add_rule(rule)
        .await
        .map_err(|_| bad_request())?;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: rule })))
}

pub async fn update_geoip_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateGeoIpRuleRequest>,
) -> Result<Json<ApiResponse<GeoIpRule>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let mut rule = state
        .geoip_engine
        .get_rule(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    rule.country = CountryCode::new(&req.country_code).map_err(|_| bad_request())?;
    rule.action = GeoIpAction::parse(&req.action).map_err(|_| bad_request())?;
    if let Some(ref s) = req.status {
        rule.status = match s.as_str() {
            "active" => GeoIpRuleStatus::Active,
            "disabled" => GeoIpRuleStatus::Disabled,
            _ => return Err(bad_request()),
        };
    }
    state
        .geoip_engine
        .update_rule(&rule)
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: rule }))
}

pub async fn delete_geoip_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    state
        .geoip_engine
        .delete_rule(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(MessageResponse {
        message: format!("Geo-IP rule {id} deleted"),
    }))
}

pub async fn geoip_lookup(
    State(state): State<AppState>,
    Path(ip_str): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let ip: std::net::IpAddr = ip_str.parse().map_err(|_| bad_request())?;
    let result = state.geoip_engine.lookup(ip).await;
    Ok(Json(serde_json::to_value(result).unwrap_or_default()))
}
