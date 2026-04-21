//! System settings API — KV-backed persistence + apply hooks.

use crate::AppState;
use aifw_core::system_apply::{apply_banner, apply_console, apply_general, apply_ssh, collect_info, ApplyReport, BannerInput, ConsoleInput, GeneralInput, SshInput, SystemInfo};
use aifw_core::system_apply_helpers::{validate_baud, validate_domain, validate_hostname, validate_ssh_port};
use aifw_core::ConsoleKind;
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

// ---------- Console ----------

#[derive(Debug, Serialize, Deserialize)]
pub struct ConsoleDto {
    pub kind: ConsoleKind,
    pub baud: u32,
}

pub async fn get_console(State(state): State<AppState>) -> Result<Json<ConsoleDto>, StatusCode> {
    let kind_str = get_kv(&state.pool, "console_kind").await.unwrap_or_else(|| "video".to_string());
    let kind = match kind_str.as_str() {
        "serial" => ConsoleKind::Serial,
        "dual"   => ConsoleKind::Dual,
        _        => ConsoleKind::Video,
    };
    let baud = get_kv(&state.pool, "console_baud").await.and_then(|v| v.parse().ok()).unwrap_or(115200);
    Ok(Json(ConsoleDto { kind, baud }))
}

pub async fn put_console(
    State(state): State<AppState>,
    Json(req): Json<ConsoleDto>,
) -> Result<Json<ApplyReport>, (StatusCode, String)> {
    validate_baud(req.baud).map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let kind_str = match req.kind {
        ConsoleKind::Video  => "video",
        ConsoleKind::Serial => "serial",
        ConsoleKind::Dual   => "dual",
    };
    set_kv(&state.pool, "console_kind", kind_str).await;
    set_kv(&state.pool, "console_baud", &req.baud.to_string()).await;

    let report = apply_console(&ConsoleInput { kind: req.kind, baud: req.baud }).await;
    Ok(Json(report))
}

// ---------- Info ----------

pub async fn get_info() -> Result<Json<SystemInfo>, StatusCode> {
    Ok(Json(collect_info().await))
}

pub async fn list_timezones() -> Result<Json<Vec<String>>, StatusCode> {
    Ok(Json(enumerate_timezones()))
}

#[cfg(target_os = "freebsd")]
fn enumerate_timezones() -> Vec<String> {
    use std::path::PathBuf;
    fn walk(base: &std::path::Path, prefix: &str, out: &mut Vec<String>) {
        let Ok(entries) = std::fs::read_dir(base) else { return };
        for e in entries.flatten() {
            let path = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            if name.starts_with('.') { continue; }
            // Skip non-zone files
            if ["posix", "right", "Etc"].contains(&name.as_str()) && prefix.is_empty() {
                // keep Etc for UTC
                if name != "Etc" { continue; }
            }
            let joined = if prefix.is_empty() { name.clone() } else { format!("{}/{}", prefix, name) };
            let ft = match e.file_type() { Ok(t) => t, Err(_) => continue };
            if ft.is_dir() {
                walk(&path, &joined, out);
            } else if ft.is_file() {
                out.push(joined);
            }
        }
    }
    let mut out = Vec::new();
    walk(&PathBuf::from("/usr/share/zoneinfo"), "", &mut out);
    if !out.iter().any(|z| z == "UTC") { out.push("UTC".to_string()); }
    out.sort();
    out.dedup();
    out
}

#[cfg(not(target_os = "freebsd"))]
fn enumerate_timezones() -> Vec<String> {
    // Fixed short list for Linux dev so the UI has something to render.
    ["UTC", "America/Chicago", "America/Los_Angeles", "America/New_York",
     "Europe/London", "Europe/Berlin", "Asia/Tokyo", "Australia/Sydney"]
        .iter().map(|s| s.to_string()).collect()
}
