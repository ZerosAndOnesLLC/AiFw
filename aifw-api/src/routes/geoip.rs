//! `/api/v1/geoip` handlers — country-based blocking rules, the GeoLite2
//! database behind them, and a reverse lookup. Extracted from the legacy
//! 4000-line `routes.rs` God module (#187).
//!
//! Every rule write re-applies the anchor, so pf always reflects the
//! database. Shared helpers (`bad_request`, `internal`) live in `super`
//! (`routes/mod.rs`) and are imported via the wildcard at the top.

use super::*;
use aifw_common::{CountryCode, GeoIpAction, GeoIpRule, GeoIpRuleStatus};
use aifw_core::geoip::{GeoIpDbStatus, GeoIpRuleView};
use axum::Extension;
use axum::extract::Multipart;
use std::collections::HashMap;

use crate::auth::AuthUser;

#[derive(Debug, Deserialize)]
pub struct CreateGeoIpRuleRequest {
    /// ISO 3166-1 alpha-2; `country` is accepted too (docs used that name)
    #[serde(alias = "country")]
    pub country_code: String,
    pub action: String,
    pub status: Option<String>,
    pub label: Option<String>,
}

/// Settings for the database: `null` clears the key; absent fields are
/// left alone.
#[derive(Debug, Deserialize)]
pub struct GeoIpDatabaseSettings {
    #[serde(default, deserialize_with = "deserialize_some")]
    pub license_key: Option<Option<String>>,
    #[serde(default, deserialize_with = "deserialize_some")]
    pub account_id: Option<Option<String>>,
    pub update_interval_hours: Option<u32>,
}

/// Distinguish "absent" from "null" for a nullable field.
fn deserialize_some<'de, D>(d: D) -> Result<Option<Option<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::<String>::deserialize(d).map(Some)
}

#[derive(Serialize)]
pub struct GeoIpRefreshResponse {
    pub cidrs: usize,
    pub status: GeoIpDbStatus,
}

async fn audit(state: &AppState, user: &AuthUser, details: String) {
    if let Err(e) = aifw_core::audit::AuditLog::new(state.pool.clone())
        .log(
            aifw_core::audit::AuditAction::ConfigChanged,
            None,
            &format!("{details} (by {})", user.username),
            "geoip",
        )
        .await
    {
        tracing::warn!(error = %e, "geoip: audit log write failed");
    }
}

/// Push the current rules to pf. The rule row is already saved, so a pf
/// failure is reported as 500 with the row intact; the periodic
/// re-apply loop retries.
async fn apply(state: &AppState) -> Result<(), StatusCode> {
    state.geoip_engine.apply_rules().await.map_err(|e| {
        tracing::error!(error = %e, "geoip: applying rules to pf failed");
        internal()
    })
}

pub async fn list_geoip_rules(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<GeoIpRuleView>>>, StatusCode> {
    let rules = state
        .geoip_engine
        .list_views()
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: rules }))
}

pub async fn create_geoip_rule(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<CreateGeoIpRuleRequest>,
) -> Result<(StatusCode, Json<ApiResponse<GeoIpRule>>), StatusCode> {
    let country = CountryCode::new(&req.country_code).map_err(|_| bad_request())?;
    let action = GeoIpAction::parse(&req.action).map_err(|_| bad_request())?;
    let mut rule = GeoIpRule::new(country, action);
    rule.label = req
        .label
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty());
    if let Some(s) = req.status.as_deref() {
        rule.status = parse_status(s)?;
    }
    let rule = state.geoip_engine.add(rule).await.map_err(engine_error)?;
    apply(&state).await?;
    audit(
        &state,
        &user,
        format!("geo-ip rule added: {} {}", rule.action, rule.country),
    )
    .await;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: rule })))
}

fn parse_status(s: &str) -> Result<GeoIpRuleStatus, StatusCode> {
    match s {
        "active" => Ok(GeoIpRuleStatus::Active),
        "disabled" => Ok(GeoIpRuleStatus::Disabled),
        _ => Err(bad_request()),
    }
}

pub async fn update_geoip_rule(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
    Json(req): Json<CreateGeoIpRuleRequest>,
) -> Result<Json<ApiResponse<GeoIpRule>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let mut rule = state
        .geoip_engine
        .get(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    rule.country = CountryCode::new(&req.country_code).map_err(|_| bad_request())?;
    rule.action = GeoIpAction::parse(&req.action).map_err(|_| bad_request())?;
    if let Some(ref s) = req.status {
        rule.status = parse_status(s)?;
    }
    if let Some(label) = req.label {
        rule.label = Some(label.trim().to_string()).filter(|l| !l.is_empty());
    }
    state
        .geoip_engine
        .update(&rule)
        .await
        .map_err(engine_error)?;
    apply(&state).await?;
    audit(
        &state,
        &user,
        format!(
            "geo-ip rule updated: {} {} ({})",
            rule.action,
            rule.country,
            match rule.status {
                GeoIpRuleStatus::Active => "active",
                GeoIpRuleStatus::Disabled => "disabled",
            }
        ),
    )
    .await;
    Ok(Json(ApiResponse { data: rule }))
}

pub async fn delete_geoip_rule(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    state
        .geoip_engine
        .delete(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    apply(&state).await?;
    audit(&state, &user, format!("geo-ip rule {id} deleted")).await;
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

// ---- database ---------------------------------------------------------------

pub async fn get_geoip_database(
    State(state): State<AppState>,
) -> Result<Json<GeoIpDbStatus>, StatusCode> {
    state
        .geoip_engine
        .status()
        .await
        .map(Json)
        .map_err(|_| internal())
}

pub async fn update_geoip_database(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    Json(req): Json<GeoIpDatabaseSettings>,
) -> Result<Json<GeoIpDbStatus>, StatusCode> {
    let mut changed = Vec::new();
    if let Some(key) = req.license_key {
        state
            .geoip_engine
            .set_license_key(key.as_deref())
            .await
            .map_err(engine_error)?;
        changed.push(if key.is_some() {
            "license key set"
        } else {
            "license key cleared"
        });
    }
    if let Some(acct) = req.account_id {
        state
            .geoip_engine
            .set_account_id(acct.as_deref())
            .await
            .map_err(engine_error)?;
        changed.push(if acct.is_some() {
            "account ID set"
        } else {
            "account ID cleared"
        });
    }
    if let Some(hours) = req.update_interval_hours {
        state
            .geoip_engine
            .set_update_interval_hours(hours)
            .await
            .map_err(engine_error)?;
        changed.push("update interval changed");
    }
    if !changed.is_empty() {
        audit(
            &state,
            &user,
            format!("geo-ip database settings: {}", changed.join(", ")),
        )
        .await;
    }
    get_geoip_database(State(state)).await
}

/// Download the GeoLite2 Country CSV release from MaxMind now.
pub async fn refresh_geoip_database(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
) -> Result<Json<GeoIpRefreshResponse>, (StatusCode, Json<MessageResponse>)> {
    let cidrs = crate::geoip_db::refresh(&state).await.map_err(|e| {
        (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(MessageResponse {
                message: e.to_string(),
            }),
        )
    })?;
    audit(
        &state,
        &user,
        format!("geo-ip database refreshed ({cidrs} networks)"),
    )
    .await;
    let status = state.geoip_engine.status().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(MessageResponse {
                message: "status unavailable".into(),
            }),
        )
    })?;
    Ok(Json(GeoIpRefreshResponse { cidrs, status }))
}

/// Upload a GeoLite2 Country CSV release: either the MaxMind zip as one
/// field, or the CSV files as separate fields. Field names don't matter;
/// file names do.
pub async fn upload_geoip_database(
    State(state): State<AppState>,
    Extension(user): Extension<AuthUser>,
    mut multipart: Multipart,
) -> Result<Json<GeoIpRefreshResponse>, (StatusCode, Json<MessageResponse>)> {
    let bad = |m: String| {
        (
            StatusCode::BAD_REQUEST,
            Json(MessageResponse { message: m }),
        )
    };
    let mut archive: Option<Vec<u8>> = None;
    let mut csvs: HashMap<String, String> = HashMap::new();
    let mut total = 0usize;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| bad(format!("malformed upload: {e}")))?
    {
        let name = field
            .file_name()
            .map(str::to_string)
            .or_else(|| field.name().map(str::to_string))
            .unwrap_or_default();
        let data = field
            .bytes()
            .await
            .map_err(|e| bad(format!("reading '{name}': {e}")))?;
        total += data.len();
        if total > aifw_core::geoip::MAX_ARCHIVE_BYTES {
            return Err(bad("upload too large".into()));
        }
        if name.to_ascii_lowercase().ends_with(".zip") || data.starts_with(b"PK\x03\x04") {
            archive = Some(data.to_vec());
        } else if name.ends_with(".csv") {
            let text = String::from_utf8(data.to_vec())
                .map_err(|_| bad(format!("'{name}' is not UTF-8 text")))?;
            csvs.insert(name, text);
        } else {
            return Err(bad(format!(
                "'{name}': expected the GeoLite2 Country CSV zip or its .csv files"
            )));
        }
    }
    let cidrs = match (archive, csvs.is_empty()) {
        (Some(zip), true) => state.geoip_engine.import_archive(zip, "upload").await,
        (None, false) => state.geoip_engine.import_csv_files(csvs, "upload").await,
        (None, true) => return Err(bad("no file in the upload".into())),
        (Some(_), false) => {
            return Err(bad("send either the zip or the CSV files, not both".into()));
        }
    }
    .map_err(|e| match e {
        aifw_common::AifwError::Validation(m) => bad(m),
        other => {
            tracing::error!(error = %other, "geoip: database import failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(MessageResponse {
                    message: "import failed; see the API log".into(),
                }),
            )
        }
    })?;
    if let Err(e) = state.geoip_engine.apply_rules().await {
        tracing::warn!(error = %e, "geoip: re-apply after upload failed");
    }
    audit(
        &state,
        &user,
        format!("geo-ip database uploaded ({cidrs} networks)"),
    )
    .await;
    let status = state.geoip_engine.status().await.map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(MessageResponse {
                message: "status unavailable".into(),
            }),
        )
    })?;
    Ok(Json(GeoIpRefreshResponse { cidrs, status }))
}
