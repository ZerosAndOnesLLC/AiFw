//! System settings API — KV-backed persistence + apply hooks.

use crate::AppState;
use aifw_core::system_apply::{apply_banner, apply_general, apply_ssh, ApplyReport, BannerInput, GeneralInput, SshInput};
use aifw_core::system_apply_helpers::{validate_domain, validate_hostname, validate_ssh_port};
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

// ---------- Banner ----------

#[derive(Debug, Serialize, Deserialize)]
pub struct BannerDto { pub login_banner: String, pub motd: String }

pub async fn get_banner(State(state): State<AppState>) -> Result<Json<BannerDto>, StatusCode> {
    let login_banner = get_kv(&state.pool, "login_banner").await.unwrap_or_default();
    let motd = get_kv(&state.pool, "motd").await.unwrap_or_default();
    Ok(Json(BannerDto { login_banner, motd }))
}

pub async fn put_banner(
    State(state): State<AppState>,
    Json(req): Json<BannerDto>,
) -> Result<Json<ApplyReport>, (StatusCode, String)> {
    const MAX: usize = 8 * 1024;
    if req.login_banner.len() > MAX || req.motd.len() > MAX {
        return Err((StatusCode::BAD_REQUEST, "banner/motd must be ≤ 8 KiB".into()));
    }
    set_kv(&state.pool, "login_banner", &req.login_banner).await;
    set_kv(&state.pool, "motd", &req.motd).await;
    let report = apply_banner(&BannerInput { login_banner: req.login_banner, motd: req.motd }).await;
    Ok(Json(report))
}

// ---------- SSH ----------

#[derive(Debug, Serialize, Deserialize)]
pub struct SshDto {
    pub enabled: bool,
    pub port: u16,
    pub password_auth: bool,
    pub permit_root_login: bool,
}

pub async fn get_ssh(State(state): State<AppState>) -> Result<Json<SshDto>, StatusCode> {
    let enabled = get_kv(&state.pool, "ssh_enabled").await.map(|v| v == "true").unwrap_or(true);
    let port = get_kv(&state.pool, "ssh_port").await.and_then(|v| v.parse().ok()).unwrap_or(22);
    let password_auth = get_kv(&state.pool, "ssh_password_auth").await.map(|v| v == "true").unwrap_or(false);
    let permit_root_login = get_kv(&state.pool, "ssh_permit_root_login").await.map(|v| v == "true").unwrap_or(false);
    Ok(Json(SshDto { enabled, port, password_auth, permit_root_login }))
}

pub async fn put_ssh(
    State(state): State<AppState>,
    Json(req): Json<SshDto>,
) -> Result<Json<ApplyReport>, (StatusCode, String)> {
    validate_ssh_port(req.port).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    set_kv(&state.pool, "ssh_enabled", if req.enabled { "true" } else { "false" }).await;
    set_kv(&state.pool, "ssh_port", &req.port.to_string()).await;
    set_kv(&state.pool, "ssh_password_auth", if req.password_auth { "true" } else { "false" }).await;
    set_kv(&state.pool, "ssh_permit_root_login", if req.permit_root_login { "true" } else { "false" }).await;

    let report = apply_ssh(&SshInput {
        enabled: req.enabled,
        port: req.port,
        password_auth: req.password_auth,
        permit_root_login: req.permit_root_login,
    }).await;
    Ok(Json(report))
}

// ---------- Console / Info — stubs (filled in Tasks 8-9) ----------
pub async fn get_console() -> Result<Json<serde_json::Value>, StatusCode> { Err(StatusCode::NOT_IMPLEMENTED) }
pub async fn put_console() -> Result<Json<ApplyReport>, StatusCode> { Err(StatusCode::NOT_IMPLEMENTED) }
pub async fn get_info() -> Result<Json<serde_json::Value>, StatusCode> { Err(StatusCode::NOT_IMPLEMENTED) }
pub async fn list_timezones() -> Result<Json<Vec<String>>, StatusCode> { Err(StatusCode::NOT_IMPLEMENTED) }
