//! System settings API — KV-backed persistence + apply hooks.

use crate::AppState;
use aifw_core::system_apply::{apply_general, ApplyReport, GeneralInput};
use aifw_core::system_apply_helpers::{validate_domain, validate_hostname};
use axum::{extract::State, http::StatusCode, Json};
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS system_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
    ).execute(pool).await?;
    Ok(())
}

async fn get_kv(pool: &SqlitePool, key: &str) -> Option<String> {
    sqlx::query_as::<_, (String,)>("SELECT value FROM system_config WHERE key = ?1")
        .bind(key).fetch_optional(pool).await.ok().flatten().map(|(v,)| v)
}

async fn set_kv(pool: &SqlitePool, key: &str, value: &str) {
    let _ = sqlx::query("INSERT OR REPLACE INTO system_config (key, value) VALUES (?1, ?2)")
        .bind(key).bind(value).execute(pool).await;
}

// ---------- General (hostname, domain, timezone) ----------

#[derive(Debug, Serialize, Deserialize)]
pub struct GeneralDto {
    pub hostname: String,
    pub domain: String,
    pub timezone: String,
}

pub async fn get_general(State(state): State<AppState>) -> Result<Json<GeneralDto>, StatusCode> {
    let hostname = get_kv(&state.pool, "hostname").await.unwrap_or_default();
    let domain = get_kv(&state.pool, "domain").await.unwrap_or_default();
    let timezone = get_kv(&state.pool, "timezone").await.unwrap_or_else(|| "UTC".to_string());
    Ok(Json(GeneralDto { hostname, domain, timezone }))
}

pub async fn put_general(
    State(state): State<AppState>,
    Json(req): Json<GeneralDto>,
) -> Result<Json<ApplyReport>, (StatusCode, String)> {
    validate_hostname(&req.hostname).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    validate_domain(&req.domain).map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    if req.timezone.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "timezone must not be empty".into()));
    }

    set_kv(&state.pool, "hostname", &req.hostname).await;
    set_kv(&state.pool, "domain", &req.domain).await;
    set_kv(&state.pool, "timezone", &req.timezone).await;

    let report = apply_general(&GeneralInput {
        hostname: req.hostname,
        domain: req.domain,
        timezone: req.timezone,
    }).await;
    Ok(Json(report))
}

// ---------- Banner / SSH / Console / Info — stubs (filled in Tasks 6-9) ----------

pub async fn get_banner() -> Result<Json<serde_json::Value>, StatusCode> { Err(StatusCode::NOT_IMPLEMENTED) }
pub async fn put_banner() -> Result<Json<ApplyReport>, StatusCode> { Err(StatusCode::NOT_IMPLEMENTED) }
pub async fn get_ssh() -> Result<Json<serde_json::Value>, StatusCode> { Err(StatusCode::NOT_IMPLEMENTED) }
pub async fn put_ssh() -> Result<Json<ApplyReport>, StatusCode> { Err(StatusCode::NOT_IMPLEMENTED) }
pub async fn get_console() -> Result<Json<serde_json::Value>, StatusCode> { Err(StatusCode::NOT_IMPLEMENTED) }
pub async fn put_console() -> Result<Json<ApplyReport>, StatusCode> { Err(StatusCode::NOT_IMPLEMENTED) }
pub async fn get_info() -> Result<Json<serde_json::Value>, StatusCode> { Err(StatusCode::NOT_IMPLEMENTED) }
pub async fn list_timezones() -> Result<Json<Vec<String>>, StatusCode> { Err(StatusCode::NOT_IMPLEMENTED) }
