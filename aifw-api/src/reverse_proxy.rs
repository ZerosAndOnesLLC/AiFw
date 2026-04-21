use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::sqlite::SqlitePool;
use tokio::process::Command;

use crate::AppState;

// ============================================================
// Helper
// ============================================================

fn internal() -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}

// ============================================================
// Types — Status & Config
// ============================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct ReverseProxyStatus {
    pub running: bool,
    pub version: String,
    pub entrypoints: u32,
    pub http_routers: u32,
    pub http_services: u32,
    pub http_middlewares: u32,
    pub tcp_routers: u32,
    pub udp_routers: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GlobalConfig {
    pub enabled: bool,
    pub log_level: String,
    pub access_log_enabled: bool,
    pub access_log_path: String,
    pub access_log_format: String,
    pub metrics_enabled: bool,
    pub metrics_address: String,
    pub api_dashboard: bool,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            log_level: "INFO".to_string(),
            access_log_enabled: true,
            access_log_path: "/var/log/trafficcop/access.log".to_string(),
            access_log_format: "common".to_string(),
            metrics_enabled: false,
            metrics_address: "127.0.0.1:8082".to_string(),
            api_dashboard: false,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

// ============================================================
// Types — Row structs (DB entities)
// ============================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct EntryPointRow {
    pub id: String,
    pub name: String,
    pub address: String,
    pub config_json: String,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HttpRouterRow {
    pub id: String,
    pub name: String,
    pub rule: String,
    pub service: String,
    pub entry_points: String,
    pub middlewares: String,
    pub priority: i64,
    pub tls_json: Option<String>,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HttpServiceRow {
    pub id: String,
    pub name: String,
    pub service_type: String,
    pub config_json: String,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HttpMiddlewareRow {
    pub id: String,
    pub name: String,
    pub middleware_type: String,
    pub config_json: String,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TcpRouterRow {
    pub id: String,
    pub name: String,
    pub rule: String,
    pub service: String,
    pub entry_points: String,
    pub priority: i64,
    pub tls_json: Option<String>,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TcpServiceRow {
    pub id: String,
    pub name: String,
    pub service_type: String,
    pub config_json: String,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UdpRouterRow {
    pub id: String,
    pub name: String,
    pub rule: String,
    pub service: String,
    pub entry_points: String,
    pub priority: i64,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UdpServiceRow {
    pub id: String,
    pub name: String,
    pub service_type: String,
    pub config_json: String,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TlsCertRow {
    pub id: String,
    pub name: String,
    pub cert_file: String,
    pub key_file: String,
    pub stores_json: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TlsOptionsRow {
    pub id: String,
    pub name: String,
    pub config_json: String,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CertResolverRow {
    pub id: String,
    pub name: String,
    pub config_json: String,
    pub created_at: String,
}

// ============================================================
// Types — Request structs (create/update)
// ============================================================

#[derive(Debug, Deserialize)]
pub struct EntryPointReq {
    pub name: String,
    pub address: String,
    #[serde(default = "default_empty_json_obj")]
    pub config_json: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct HttpRouterReq {
    pub name: String,
    pub rule: String,
    pub service: String,
    #[serde(default = "default_empty_json_arr")]
    pub entry_points: String,
    #[serde(default = "default_empty_json_arr")]
    pub middlewares: String,
    #[serde(default)]
    pub priority: i64,
    pub tls_json: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct HttpServiceReq {
    pub name: String,
    pub service_type: String,
    pub config_json: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct HttpMiddlewareReq {
    pub name: String,
    pub middleware_type: String,
    pub config_json: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct TcpRouterReq {
    pub name: String,
    pub rule: String,
    pub service: String,
    #[serde(default = "default_empty_json_arr")]
    pub entry_points: String,
    #[serde(default)]
    pub priority: i64,
    pub tls_json: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct TcpServiceReq {
    pub name: String,
    #[serde(default = "default_load_balancer")]
    pub service_type: String,
    pub config_json: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct UdpRouterReq {
    pub name: String,
    pub rule: String,
    pub service: String,
    #[serde(default = "default_empty_json_arr")]
    pub entry_points: String,
    #[serde(default)]
    pub priority: i64,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct UdpServiceReq {
    pub name: String,
    #[serde(default = "default_load_balancer")]
    pub service_type: String,
    pub config_json: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct TlsCertReq {
    pub name: String,
    pub cert_file: String,
    pub key_file: String,
    #[serde(default = "default_empty_json_arr")]
    pub stores_json: String,
}

#[derive(Debug, Deserialize)]
pub struct TlsOptionsReq {
    pub name: String,
    pub config_json: String,
}

#[derive(Debug, Deserialize)]
pub struct CertResolverReq {
    pub name: String,
    pub config_json: String,
}

// ============================================================
// Types — Query params
// ============================================================

#[derive(Debug, Deserialize)]
pub struct LogParams {
    pub lines: Option<usize>,
    pub search: Option<String>,
    pub log_type: Option<String>, // "access" (default) or "server"
}

// ============================================================
// Default helpers for serde
// ============================================================

fn default_true() -> bool {
    true
}

fn default_empty_json_obj() -> String {
    "{}".to_string()
}

fn default_empty_json_arr() -> String {
    "[]".to_string()
}

fn default_load_balancer() -> String {
    "loadBalancer".to_string()
}

// ============================================================
// DB Migration
// ============================================================

pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tc_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tc_entrypoints (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            address TEXT NOT NULL,
            config_json TEXT NOT NULL DEFAULT '{}',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tc_http_routers (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            rule TEXT NOT NULL,
            service TEXT NOT NULL,
            entry_points TEXT NOT NULL DEFAULT '[]',
            middlewares TEXT NOT NULL DEFAULT '[]',
            priority INTEGER NOT NULL DEFAULT 0,
            tls_json TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tc_http_services (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            service_type TEXT NOT NULL,
            config_json TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tc_http_middlewares (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            middleware_type TEXT NOT NULL,
            config_json TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tc_tcp_routers (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            rule TEXT NOT NULL,
            service TEXT NOT NULL,
            entry_points TEXT NOT NULL DEFAULT '[]',
            priority INTEGER NOT NULL DEFAULT 0,
            tls_json TEXT,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tc_tcp_services (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            service_type TEXT NOT NULL DEFAULT 'loadBalancer',
            config_json TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tc_udp_routers (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            rule TEXT NOT NULL,
            service TEXT NOT NULL,
            entry_points TEXT NOT NULL DEFAULT '[]',
            priority INTEGER NOT NULL DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tc_udp_services (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            service_type TEXT NOT NULL DEFAULT 'loadBalancer',
            config_json TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tc_tls_certs (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            cert_file TEXT NOT NULL,
            key_file TEXT NOT NULL,
            stores_json TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL
        )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tc_tls_options (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            config_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS tc_cert_resolvers (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            config_json TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================
// Config helpers
// ============================================================

async fn load_global_config(pool: &SqlitePool) -> GlobalConfig {
    let rows = sqlx::query_as::<_, (String, String)>("SELECT key, value FROM tc_config")
        .fetch_all(pool)
        .await
        .unwrap_or_default();
    let mut config = GlobalConfig::default();
    for (key, value) in rows {
        match key.as_str() {
            "enabled" => config.enabled = value == "true",
            "log_level" => config.log_level = value,
            "access_log_enabled" => config.access_log_enabled = value == "true",
            "access_log_path" => config.access_log_path = value,
            "access_log_format" => config.access_log_format = value,
            "metrics_enabled" => config.metrics_enabled = value == "true",
            "metrics_address" => config.metrics_address = value,
            "api_dashboard" => config.api_dashboard = value == "true",
            _ => {}
        }
    }
    config
}

async fn save_config_key(pool: &SqlitePool, key: &str, value: &str) {
    let _ = sqlx::query("INSERT OR REPLACE INTO tc_config (key, value) VALUES (?1, ?2)")
        .bind(key)
        .bind(value)
        .execute(pool)
        .await;
}

// ============================================================
// DB fetch helpers (used by generate_trafficcop_config)
// ============================================================

async fn fetch_entrypoints(pool: &SqlitePool) -> Vec<EntryPointRow> {
    sqlx::query_as::<_, (String, String, String, String, bool, String)>(
        "SELECT id, name, address, config_json, enabled, created_at FROM tc_entrypoints WHERE enabled = 1 ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(id, name, address, config_json, enabled, created_at)| EntryPointRow {
        id,
        name,
        address,
        config_json,
        enabled,
        created_at,
    })
    .collect()
}

async fn fetch_http_routers(pool: &SqlitePool) -> Vec<HttpRouterRow> {
    sqlx::query_as::<_, (String, String, String, String, String, String, i64, Option<String>, bool, String)>(
        "SELECT id, name, rule, service, entry_points, middlewares, priority, tls_json, enabled, created_at FROM tc_http_routers WHERE enabled = 1 ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(id, name, rule, service, entry_points, middlewares, priority, tls_json, enabled, created_at)| HttpRouterRow {
        id,
        name,
        rule,
        service,
        entry_points,
        middlewares,
        priority,
        tls_json,
        enabled,
        created_at,
    })
    .collect()
}

async fn fetch_http_services(pool: &SqlitePool) -> Vec<HttpServiceRow> {
    sqlx::query_as::<_, (String, String, String, String, bool, String)>(
        "SELECT id, name, service_type, config_json, enabled, created_at FROM tc_http_services WHERE enabled = 1 ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(id, name, service_type, config_json, enabled, created_at)| HttpServiceRow {
        id,
        name,
        service_type,
        config_json,
        enabled,
        created_at,
    })
    .collect()
}

async fn fetch_http_middlewares(pool: &SqlitePool) -> Vec<HttpMiddlewareRow> {
    sqlx::query_as::<_, (String, String, String, String, bool, String)>(
        "SELECT id, name, middleware_type, config_json, enabled, created_at FROM tc_http_middlewares WHERE enabled = 1 ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(id, name, middleware_type, config_json, enabled, created_at)| HttpMiddlewareRow {
        id,
        name,
        middleware_type,
        config_json,
        enabled,
        created_at,
    })
    .collect()
}

async fn fetch_tcp_routers(pool: &SqlitePool) -> Vec<TcpRouterRow> {
    sqlx::query_as::<_, (String, String, String, String, String, i64, Option<String>, bool, String)>(
        "SELECT id, name, rule, service, entry_points, priority, tls_json, enabled, created_at FROM tc_tcp_routers WHERE enabled = 1 ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(id, name, rule, service, entry_points, priority, tls_json, enabled, created_at)| TcpRouterRow {
        id,
        name,
        rule,
        service,
        entry_points,
        priority,
        tls_json,
        enabled,
        created_at,
    })
    .collect()
}

async fn fetch_tcp_services(pool: &SqlitePool) -> Vec<TcpServiceRow> {
    sqlx::query_as::<_, (String, String, String, String, bool, String)>(
        "SELECT id, name, service_type, config_json, enabled, created_at FROM tc_tcp_services WHERE enabled = 1 ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(id, name, service_type, config_json, enabled, created_at)| TcpServiceRow {
        id,
        name,
        service_type,
        config_json,
        enabled,
        created_at,
    })
    .collect()
}

async fn fetch_udp_routers(pool: &SqlitePool) -> Vec<UdpRouterRow> {
    sqlx::query_as::<_, (String, String, String, String, String, i64, bool, String)>(
        "SELECT id, name, rule, service, entry_points, priority, enabled, created_at FROM tc_udp_routers WHERE enabled = 1 ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(id, name, rule, service, entry_points, priority, enabled, created_at)| UdpRouterRow {
        id,
        name,
        rule,
        service,
        entry_points,
        priority,
        enabled,
        created_at,
    })
    .collect()
}

async fn fetch_udp_services(pool: &SqlitePool) -> Vec<UdpServiceRow> {
    sqlx::query_as::<_, (String, String, String, String, bool, String)>(
        "SELECT id, name, service_type, config_json, enabled, created_at FROM tc_udp_services WHERE enabled = 1 ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(id, name, service_type, config_json, enabled, created_at)| UdpServiceRow {
        id,
        name,
        service_type,
        config_json,
        enabled,
        created_at,
    })
    .collect()
}

async fn fetch_tls_certs(pool: &SqlitePool) -> Vec<TlsCertRow> {
    sqlx::query_as::<_, (String, String, String, String, String, String)>(
        "SELECT id, name, cert_file, key_file, stores_json, created_at FROM tc_tls_certs ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(id, name, cert_file, key_file, stores_json, created_at)| TlsCertRow {
        id,
        name,
        cert_file,
        key_file,
        stores_json,
        created_at,
    })
    .collect()
}

async fn fetch_tls_options(pool: &SqlitePool) -> Vec<TlsOptionsRow> {
    sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT id, name, config_json, created_at FROM tc_tls_options ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(id, name, config_json, created_at)| TlsOptionsRow {
        id,
        name,
        config_json,
        created_at,
    })
    .collect()
}

async fn fetch_cert_resolvers(pool: &SqlitePool) -> Vec<CertResolverRow> {
    sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT id, name, config_json, created_at FROM tc_cert_resolvers ORDER BY name",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(id, name, config_json, created_at)| CertResolverRow {
        id,
        name,
        config_json,
        created_at,
    })
    .collect()
}

// ============================================================
// YAML config generation
// ============================================================

pub async fn generate_trafficcop_config(pool: &SqlitePool) -> Result<String, sqlx::Error> {
    let global = load_global_config(pool).await;
    let entrypoints = fetch_entrypoints(pool).await;
    let http_routers = fetch_http_routers(pool).await;
    let http_services = fetch_http_services(pool).await;
    let http_middlewares = fetch_http_middlewares(pool).await;
    let tcp_routers = fetch_tcp_routers(pool).await;
    let tcp_services = fetch_tcp_services(pool).await;
    let udp_routers = fetch_udp_routers(pool).await;
    let udp_services = fetch_udp_services(pool).await;
    let tls_certs = fetch_tls_certs(pool).await;
    let tls_options = fetch_tls_options(pool).await;
    let cert_resolvers = fetch_cert_resolvers(pool).await;

    let mut root = serde_json::Map::new();

    // --- Global: log ---
    let mut log = serde_json::Map::new();
    log.insert("level".to_string(), json!(global.log_level));
    root.insert("log".to_string(), serde_json::Value::Object(log));

    // --- Global: accessLog ---
    if global.access_log_enabled {
        let mut access_log = serde_json::Map::new();
        access_log.insert("filePath".to_string(), json!(global.access_log_path));
        access_log.insert("format".to_string(), json!(global.access_log_format));
        root.insert(
            "accessLog".to_string(),
            serde_json::Value::Object(access_log),
        );
    }

    // --- Global: api ---
    if global.api_dashboard {
        let mut api = serde_json::Map::new();
        api.insert("dashboard".to_string(), json!(true));
        root.insert("api".to_string(), serde_json::Value::Object(api));
    }

    // --- Global: metrics ---
    if global.metrics_enabled {
        let mut metrics = serde_json::Map::new();
        let mut prometheus = serde_json::Map::new();
        prometheus.insert("entryPoint".to_string(), json!("metrics"));
        prometheus.insert("addEntryPointsLabels".to_string(), json!(true));
        prometheus.insert("addServicesLabels".to_string(), json!(true));
        metrics.insert(
            "prometheus".to_string(),
            serde_json::Value::Object(prometheus),
        );
        root.insert("metrics".to_string(), serde_json::Value::Object(metrics));
    }

    // --- Entry points ---
    let mut eps = serde_json::Map::new();
    for ep in &entrypoints {
        let mut ep_val: serde_json::Value =
            serde_json::from_str(&ep.config_json).unwrap_or(json!({}));
        ep_val["address"] = json!(ep.address);
        eps.insert(ep.name.clone(), ep_val);
    }
    if global.metrics_enabled {
        eps.insert(
            "metrics".to_string(),
            json!({ "address": global.metrics_address }),
        );
    }
    if !eps.is_empty() {
        root.insert("entryPoints".to_string(), serde_json::Value::Object(eps));
    }

    // --- HTTP section ---
    let mut http = serde_json::Map::new();

    // HTTP routers
    let mut routers = serde_json::Map::new();
    for r in &http_routers {
        let entry_points: Vec<String> = serde_json::from_str(&r.entry_points).unwrap_or_default();
        let middlewares: Vec<String> = serde_json::from_str(&r.middlewares).unwrap_or_default();
        let mut rv = json!({
            "rule": r.rule,
            "service": r.service,
        });
        if !entry_points.is_empty() {
            rv["entryPoints"] = json!(entry_points);
        }
        if !middlewares.is_empty() {
            rv["middlewares"] = json!(middlewares);
        }
        if r.priority != 0 {
            rv["priority"] = json!(r.priority);
        }
        if let Some(tls) = &r.tls_json
            && let Ok(tls_val) = serde_json::from_str::<serde_json::Value>(tls)
        {
            rv["tls"] = tls_val;
        }
        routers.insert(r.name.clone(), rv);
    }
    if !routers.is_empty() {
        http.insert("routers".to_string(), serde_json::Value::Object(routers));
    }

    // HTTP services
    let mut services = serde_json::Map::new();
    for s in &http_services {
        let config: serde_json::Value = serde_json::from_str(&s.config_json).unwrap_or(json!({}));
        let mut sv = serde_json::Map::new();
        sv.insert(s.service_type.clone(), config);
        services.insert(s.name.clone(), serde_json::Value::Object(sv));
    }
    if !services.is_empty() {
        http.insert("services".to_string(), serde_json::Value::Object(services));
    }

    // HTTP middlewares
    let mut mws = serde_json::Map::new();
    for m in &http_middlewares {
        let config: serde_json::Value = serde_json::from_str(&m.config_json).unwrap_or(json!({}));
        let mut mv = serde_json::Map::new();
        mv.insert(m.middleware_type.clone(), config);
        mws.insert(m.name.clone(), serde_json::Value::Object(mv));
    }
    if !mws.is_empty() {
        http.insert("middlewares".to_string(), serde_json::Value::Object(mws));
    }

    if !http.is_empty() {
        root.insert("http".to_string(), serde_json::Value::Object(http));
    }

    // --- TCP section ---
    let mut tcp = serde_json::Map::new();

    // TCP routers
    let mut tcp_router_map = serde_json::Map::new();
    for r in &tcp_routers {
        let entry_points: Vec<String> = serde_json::from_str(&r.entry_points).unwrap_or_default();
        let mut rv = json!({
            "rule": r.rule,
            "service": r.service,
        });
        if !entry_points.is_empty() {
            rv["entryPoints"] = json!(entry_points);
        }
        if r.priority != 0 {
            rv["priority"] = json!(r.priority);
        }
        if let Some(tls) = &r.tls_json
            && let Ok(tls_val) = serde_json::from_str::<serde_json::Value>(tls)
        {
            rv["tls"] = tls_val;
        }
        tcp_router_map.insert(r.name.clone(), rv);
    }
    if !tcp_router_map.is_empty() {
        tcp.insert(
            "routers".to_string(),
            serde_json::Value::Object(tcp_router_map),
        );
    }

    // TCP services
    let mut tcp_service_map = serde_json::Map::new();
    for s in &tcp_services {
        let config: serde_json::Value = serde_json::from_str(&s.config_json).unwrap_or(json!({}));
        let mut sv = serde_json::Map::new();
        sv.insert(s.service_type.clone(), config);
        tcp_service_map.insert(s.name.clone(), serde_json::Value::Object(sv));
    }
    if !tcp_service_map.is_empty() {
        tcp.insert(
            "services".to_string(),
            serde_json::Value::Object(tcp_service_map),
        );
    }

    if !tcp.is_empty() {
        root.insert("tcp".to_string(), serde_json::Value::Object(tcp));
    }

    // --- UDP section ---
    let mut udp = serde_json::Map::new();

    // UDP routers
    let mut udp_router_map = serde_json::Map::new();
    for r in &udp_routers {
        let entry_points: Vec<String> = serde_json::from_str(&r.entry_points).unwrap_or_default();
        let mut rv = json!({
            "rule": r.rule,
            "service": r.service,
        });
        if !entry_points.is_empty() {
            rv["entryPoints"] = json!(entry_points);
        }
        if r.priority != 0 {
            rv["priority"] = json!(r.priority);
        }
        udp_router_map.insert(r.name.clone(), rv);
    }
    if !udp_router_map.is_empty() {
        udp.insert(
            "routers".to_string(),
            serde_json::Value::Object(udp_router_map),
        );
    }

    // UDP services
    let mut udp_service_map = serde_json::Map::new();
    for s in &udp_services {
        let config: serde_json::Value = serde_json::from_str(&s.config_json).unwrap_or(json!({}));
        let mut sv = serde_json::Map::new();
        sv.insert(s.service_type.clone(), config);
        udp_service_map.insert(s.name.clone(), serde_json::Value::Object(sv));
    }
    if !udp_service_map.is_empty() {
        udp.insert(
            "services".to_string(),
            serde_json::Value::Object(udp_service_map),
        );
    }

    if !udp.is_empty() {
        root.insert("udp".to_string(), serde_json::Value::Object(udp));
    }

    // --- TLS section ---
    let mut tls = serde_json::Map::new();

    // TLS certificates
    let mut certs_arr = Vec::new();
    for c in &tls_certs {
        let stores: Vec<String> = serde_json::from_str(&c.stores_json).unwrap_or_default();
        let mut cert_val = json!({
            "certFile": c.cert_file,
            "keyFile": c.key_file,
        });
        if !stores.is_empty() {
            cert_val["stores"] = json!(stores);
        }
        certs_arr.push(cert_val);
    }
    if !certs_arr.is_empty() {
        tls.insert("certificates".to_string(), json!(certs_arr));
    }

    // TLS options
    let mut tls_opts = serde_json::Map::new();
    for o in &tls_options {
        let config: serde_json::Value = serde_json::from_str(&o.config_json).unwrap_or(json!({}));
        tls_opts.insert(o.name.clone(), config);
    }
    if !tls_opts.is_empty() {
        tls.insert("options".to_string(), serde_json::Value::Object(tls_opts));
    }

    if !tls.is_empty() {
        root.insert("tls".to_string(), serde_json::Value::Object(tls));
    }

    // --- Certificate resolvers ---
    let mut resolvers = serde_json::Map::new();
    for r in &cert_resolvers {
        let config: serde_json::Value = serde_json::from_str(&r.config_json).unwrap_or(json!({}));
        resolvers.insert(r.name.clone(), config);
    }
    if !resolvers.is_empty() {
        root.insert(
            "certificatesResolvers".to_string(),
            serde_json::Value::Object(resolvers),
        );
    }

    let yaml = serde_yaml_ng::to_string(&serde_json::Value::Object(root))
        .unwrap_or_else(|_| "{}".to_string());

    Ok(yaml)
}

// ============================================================
// Service control handlers
// ============================================================

async fn run_trafficcop_service(action: &str) -> Json<MessageResponse> {
    let output = Command::new("/usr/local/bin/sudo")
        .args(["/usr/sbin/service", "trafficcop", action])
        .output()
        .await;
    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            let msg = if o.status.success() {
                format!("TrafficCop {}: {}", action, stdout.trim())
            } else {
                format!(
                    "TrafficCop {} failed: {} {}",
                    action,
                    stdout.trim(),
                    stderr.trim()
                )
            };
            Json(MessageResponse { message: msg })
        }
        Err(e) => Json(MessageResponse {
            message: format!("Failed to {} TrafficCop: {}", action, e),
        }),
    }
}

pub async fn rp_status(
    State(state): State<AppState>,
) -> Result<Json<ReverseProxyStatus>, StatusCode> {
    let running = Command::new("/usr/local/bin/sudo")
        .args(["/usr/sbin/service", "trafficcop", "status"])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    // `trafficcop --version` prints e.g. "trafficcop 1.4.2"
    let version = Command::new("/usr/local/sbin/trafficcop")
        .arg("--version")
        .output()
        .await
        .ok()
        .and_then(|o| {
            o.status
                .success()
                .then(|| String::from_utf8_lossy(&o.stdout).trim().to_string())
        })
        .and_then(|s| s.split_whitespace().nth(1).map(str::to_string))
        .unwrap_or_else(|| "unknown".to_string());

    let entrypoints =
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM tc_entrypoints WHERE enabled = 1")
            .fetch_one(&state.pool)
            .await
            .map(|r| r.0 as u32)
            .unwrap_or(0);

    let http_routers =
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM tc_http_routers WHERE enabled = 1")
            .fetch_one(&state.pool)
            .await
            .map(|r| r.0 as u32)
            .unwrap_or(0);

    let http_services =
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM tc_http_services WHERE enabled = 1")
            .fetch_one(&state.pool)
            .await
            .map(|r| r.0 as u32)
            .unwrap_or(0);

    let http_middlewares =
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM tc_http_middlewares WHERE enabled = 1")
            .fetch_one(&state.pool)
            .await
            .map(|r| r.0 as u32)
            .unwrap_or(0);

    let tcp_routers =
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM tc_tcp_routers WHERE enabled = 1")
            .fetch_one(&state.pool)
            .await
            .map(|r| r.0 as u32)
            .unwrap_or(0);

    let udp_routers =
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM tc_udp_routers WHERE enabled = 1")
            .fetch_one(&state.pool)
            .await
            .map(|r| r.0 as u32)
            .unwrap_or(0);

    Ok(Json(ReverseProxyStatus {
        running,
        version,
        entrypoints,
        http_routers,
        http_services,
        http_middlewares,
        tcp_routers,
        udp_routers,
    }))
}

pub async fn rp_start() -> Result<Json<MessageResponse>, StatusCode> {
    Ok(run_trafficcop_service("start").await)
}

pub async fn rp_stop() -> Result<Json<MessageResponse>, StatusCode> {
    Ok(run_trafficcop_service("stop").await)
}

pub async fn rp_restart() -> Result<Json<MessageResponse>, StatusCode> {
    Ok(run_trafficcop_service("restart").await)
}

// ============================================================
// Config handlers
// ============================================================

pub async fn get_config(State(state): State<AppState>) -> Result<Json<GlobalConfig>, StatusCode> {
    Ok(Json(load_global_config(&state.pool).await))
}

pub async fn update_config(
    State(state): State<AppState>,
    Json(config): Json<GlobalConfig>,
) -> Result<Json<MessageResponse>, StatusCode> {
    save_config_key(
        &state.pool,
        "enabled",
        if config.enabled { "true" } else { "false" },
    )
    .await;
    save_config_key(&state.pool, "log_level", &config.log_level).await;
    save_config_key(
        &state.pool,
        "access_log_enabled",
        if config.access_log_enabled {
            "true"
        } else {
            "false"
        },
    )
    .await;
    save_config_key(&state.pool, "access_log_path", &config.access_log_path).await;
    save_config_key(&state.pool, "access_log_format", &config.access_log_format).await;
    save_config_key(
        &state.pool,
        "metrics_enabled",
        if config.metrics_enabled {
            "true"
        } else {
            "false"
        },
    )
    .await;
    save_config_key(&state.pool, "metrics_address", &config.metrics_address).await;
    save_config_key(
        &state.pool,
        "api_dashboard",
        if config.api_dashboard {
            "true"
        } else {
            "false"
        },
    )
    .await;
    Ok(Json(MessageResponse {
        message: "TrafficCop config updated".to_string(),
    }))
}

pub async fn apply_config(
    State(state): State<AppState>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let global = load_global_config(&state.pool).await;
    let yaml = generate_trafficcop_config(&state.pool)
        .await
        .map_err(|_| internal())?;

    // Write YAML config via sudo tee
    let config_path = "/usr/local/etc/trafficcop/config.yaml";
    let mut child = Command::new("/usr/local/bin/sudo")
        .args(["tee", config_path])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .map_err(|_| internal())?;

    if let Some(ref mut stdin) = child.stdin {
        use tokio::io::AsyncWriteExt;
        let _ = stdin.write_all(yaml.as_bytes()).await;
    }
    let _ = child.wait().await;

    if global.enabled {
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["/usr/sbin/sysrc", "trafficcop_enable=YES"])
            .output()
            .await;
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["/usr/sbin/service", "trafficcop", "restart"])
            .output()
            .await;
        Ok(Json(MessageResponse {
            message: "TrafficCop config applied and service restarted".to_string(),
        }))
    } else {
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["/usr/sbin/service", "trafficcop", "stop"])
            .output()
            .await;
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["/usr/sbin/sysrc", "trafficcop_enable=NO"])
            .output()
            .await;
        Ok(Json(MessageResponse {
            message: "TrafficCop config saved, service stopped".to_string(),
        }))
    }
}

pub async fn validate_config(
    State(state): State<AppState>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let yaml = generate_trafficcop_config(&state.pool)
        .await
        .map_err(|_| internal())?;

    let tmp_path = format!("/tmp/trafficcop-validate-{}.yaml", uuid::Uuid::new_v4());
    tokio::fs::write(&tmp_path, &yaml)
        .await
        .map_err(|_| internal())?;

    let output = Command::new("trafficcop")
        .args(["--validate", "--configFile", &tmp_path])
        .output()
        .await;

    let _ = tokio::fs::remove_file(&tmp_path).await;

    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            if o.status.success() {
                Ok(Json(MessageResponse {
                    message: format!("Configuration valid. {}", stdout.trim()),
                }))
            } else {
                Ok(Json(MessageResponse {
                    message: format!("Configuration invalid: {} {}", stdout.trim(), stderr.trim()),
                }))
            }
        }
        Err(e) => Ok(Json(MessageResponse {
            message: format!("Failed to run validation: {}", e),
        })),
    }
}

// ============================================================
// Logs handler
// ============================================================

pub async fn rp_logs(Query(params): Query<LogParams>) -> Result<Json<Vec<String>>, StatusCode> {
    let lines_param = params.lines.unwrap_or(200);
    let search = params.search.clone().unwrap_or_default();
    let log_type = params
        .log_type
        .clone()
        .unwrap_or_else(|| "access".to_string());

    let log_path = if log_type == "server" {
        "/var/log/trafficcop/trafficcop.log"
    } else {
        "/var/log/trafficcop/access.log"
    };

    let log_lines = crate::log_tail::tail_filtered(
        &[log_path],
        if search.is_empty() {
            None
        } else {
            Some(&search)
        },
        5000,
        lines_param,
    )
    .await;

    Ok(Json(log_lines))
}

// ============================================================
// CRUD — Entry Points
// ============================================================

pub async fn list_entrypoints(
    State(state): State<AppState>,
) -> Result<Json<Vec<EntryPointRow>>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, String, String, String, bool, String)>(
        "SELECT id, name, address, config_json, enabled, created_at FROM tc_entrypoints WHERE 1=1 ORDER BY name",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| internal())?;

    let items: Vec<EntryPointRow> = rows
        .into_iter()
        .map(
            |(id, name, address, config_json, enabled, created_at)| EntryPointRow {
                id,
                name,
                address,
                config_json,
                enabled,
                created_at,
            },
        )
        .collect();

    Ok(Json(items))
}

pub async fn create_entrypoint(
    State(state): State<AppState>,
    Json(req): Json<EntryPointReq>,
) -> Result<Json<EntryPointRow>, StatusCode> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO tc_entrypoints (id, name, address, config_json, enabled, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.address)
    .bind(&req.config_json)
    .bind(req.enabled)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    Ok(Json(EntryPointRow {
        id,
        name: req.name,
        address: req.address,
        config_json: req.config_json,
        enabled: req.enabled,
        created_at: now,
    }))
}

pub async fn update_entrypoint(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<EntryPointReq>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query(
        "UPDATE tc_entrypoints SET name=?1, address=?2, config_json=?3, enabled=?4 WHERE id=?5",
    )
    .bind(&req.name)
    .bind(&req.address)
    .bind(&req.config_json)
    .bind(req.enabled)
    .bind(&id)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(MessageResponse {
        message: "Updated".to_string(),
    }))
}

pub async fn delete_entrypoint(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query("DELETE FROM tc_entrypoints WHERE id = ?1")
        .bind(&id)
        .execute(&state.pool)
        .await
        .map_err(|_| internal())?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(MessageResponse {
        message: "Deleted".to_string(),
    }))
}

// ============================================================
// CRUD — HTTP Routers
// ============================================================

pub async fn list_http_routers(
    State(state): State<AppState>,
) -> Result<Json<Vec<HttpRouterRow>>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, String, String, String, String, String, i64, Option<String>, bool, String)>(
        "SELECT id, name, rule, service, entry_points, middlewares, priority, tls_json, enabled, created_at FROM tc_http_routers WHERE 1=1 ORDER BY name",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| internal())?;

    let items: Vec<HttpRouterRow> = rows
        .into_iter()
        .map(
            |(
                id,
                name,
                rule,
                service,
                entry_points,
                middlewares,
                priority,
                tls_json,
                enabled,
                created_at,
            )| HttpRouterRow {
                id,
                name,
                rule,
                service,
                entry_points,
                middlewares,
                priority,
                tls_json,
                enabled,
                created_at,
            },
        )
        .collect();

    Ok(Json(items))
}

pub async fn create_http_router(
    State(state): State<AppState>,
    Json(req): Json<HttpRouterReq>,
) -> Result<Json<HttpRouterRow>, StatusCode> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO tc_http_routers (id, name, rule, service, entry_points, middlewares, priority, tls_json, enabled, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.rule)
    .bind(&req.service)
    .bind(&req.entry_points)
    .bind(&req.middlewares)
    .bind(req.priority)
    .bind(req.tls_json.as_deref())
    .bind(req.enabled)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    Ok(Json(HttpRouterRow {
        id,
        name: req.name,
        rule: req.rule,
        service: req.service,
        entry_points: req.entry_points,
        middlewares: req.middlewares,
        priority: req.priority,
        tls_json: req.tls_json,
        enabled: req.enabled,
        created_at: now,
    }))
}

pub async fn update_http_router(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<HttpRouterReq>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query(
        "UPDATE tc_http_routers SET name=?1, rule=?2, service=?3, entry_points=?4, middlewares=?5, priority=?6, tls_json=?7, enabled=?8 WHERE id=?9",
    )
    .bind(&req.name)
    .bind(&req.rule)
    .bind(&req.service)
    .bind(&req.entry_points)
    .bind(&req.middlewares)
    .bind(req.priority)
    .bind(req.tls_json.as_deref())
    .bind(req.enabled)
    .bind(&id)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(MessageResponse {
        message: "Updated".to_string(),
    }))
}

pub async fn delete_http_router(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query("DELETE FROM tc_http_routers WHERE id = ?1")
        .bind(&id)
        .execute(&state.pool)
        .await
        .map_err(|_| internal())?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(MessageResponse {
        message: "Deleted".to_string(),
    }))
}

// ============================================================
// CRUD — HTTP Services
// ============================================================

pub async fn list_http_services(
    State(state): State<AppState>,
) -> Result<Json<Vec<HttpServiceRow>>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, String, String, String, bool, String)>(
        "SELECT id, name, service_type, config_json, enabled, created_at FROM tc_http_services WHERE 1=1 ORDER BY name",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| internal())?;

    let items: Vec<HttpServiceRow> = rows
        .into_iter()
        .map(
            |(id, name, service_type, config_json, enabled, created_at)| HttpServiceRow {
                id,
                name,
                service_type,
                config_json,
                enabled,
                created_at,
            },
        )
        .collect();

    Ok(Json(items))
}

pub async fn create_http_service(
    State(state): State<AppState>,
    Json(req): Json<HttpServiceReq>,
) -> Result<Json<HttpServiceRow>, StatusCode> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO tc_http_services (id, name, service_type, config_json, enabled, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.service_type)
    .bind(&req.config_json)
    .bind(req.enabled)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    Ok(Json(HttpServiceRow {
        id,
        name: req.name,
        service_type: req.service_type,
        config_json: req.config_json,
        enabled: req.enabled,
        created_at: now,
    }))
}

pub async fn update_http_service(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<HttpServiceReq>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query(
        "UPDATE tc_http_services SET name=?1, service_type=?2, config_json=?3, enabled=?4 WHERE id=?5",
    )
    .bind(&req.name)
    .bind(&req.service_type)
    .bind(&req.config_json)
    .bind(req.enabled)
    .bind(&id)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(MessageResponse {
        message: "Updated".to_string(),
    }))
}

pub async fn delete_http_service(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query("DELETE FROM tc_http_services WHERE id = ?1")
        .bind(&id)
        .execute(&state.pool)
        .await
        .map_err(|_| internal())?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(MessageResponse {
        message: "Deleted".to_string(),
    }))
}

// ============================================================
// CRUD — HTTP Middlewares
// ============================================================

pub async fn list_http_middlewares(
    State(state): State<AppState>,
) -> Result<Json<Vec<HttpMiddlewareRow>>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, String, String, String, bool, String)>(
        "SELECT id, name, middleware_type, config_json, enabled, created_at FROM tc_http_middlewares WHERE 1=1 ORDER BY name",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| internal())?;

    let items: Vec<HttpMiddlewareRow> = rows
        .into_iter()
        .map(
            |(id, name, middleware_type, config_json, enabled, created_at)| HttpMiddlewareRow {
                id,
                name,
                middleware_type,
                config_json,
                enabled,
                created_at,
            },
        )
        .collect();

    Ok(Json(items))
}

pub async fn create_http_middleware(
    State(state): State<AppState>,
    Json(req): Json<HttpMiddlewareReq>,
) -> Result<Json<HttpMiddlewareRow>, StatusCode> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO tc_http_middlewares (id, name, middleware_type, config_json, enabled, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.middleware_type)
    .bind(&req.config_json)
    .bind(req.enabled)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    Ok(Json(HttpMiddlewareRow {
        id,
        name: req.name,
        middleware_type: req.middleware_type,
        config_json: req.config_json,
        enabled: req.enabled,
        created_at: now,
    }))
}

pub async fn update_http_middleware(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<HttpMiddlewareReq>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query(
        "UPDATE tc_http_middlewares SET name=?1, middleware_type=?2, config_json=?3, enabled=?4 WHERE id=?5",
    )
    .bind(&req.name)
    .bind(&req.middleware_type)
    .bind(&req.config_json)
    .bind(req.enabled)
    .bind(&id)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(MessageResponse {
        message: "Updated".to_string(),
    }))
}

pub async fn delete_http_middleware(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query("DELETE FROM tc_http_middlewares WHERE id = ?1")
        .bind(&id)
        .execute(&state.pool)
        .await
        .map_err(|_| internal())?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(MessageResponse {
        message: "Deleted".to_string(),
    }))
}

// ============================================================
// CRUD — TCP Routers
// ============================================================

pub async fn list_tcp_routers(
    State(state): State<AppState>,
) -> Result<Json<Vec<TcpRouterRow>>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, String, String, String, String, i64, Option<String>, bool, String)>(
        "SELECT id, name, rule, service, entry_points, priority, tls_json, enabled, created_at FROM tc_tcp_routers WHERE 1=1 ORDER BY name",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| internal())?;

    let items: Vec<TcpRouterRow> = rows
        .into_iter()
        .map(
            |(id, name, rule, service, entry_points, priority, tls_json, enabled, created_at)| {
                TcpRouterRow {
                    id,
                    name,
                    rule,
                    service,
                    entry_points,
                    priority,
                    tls_json,
                    enabled,
                    created_at,
                }
            },
        )
        .collect();

    Ok(Json(items))
}

pub async fn create_tcp_router(
    State(state): State<AppState>,
    Json(req): Json<TcpRouterReq>,
) -> Result<Json<TcpRouterRow>, StatusCode> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO tc_tcp_routers (id, name, rule, service, entry_points, priority, tls_json, enabled, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.rule)
    .bind(&req.service)
    .bind(&req.entry_points)
    .bind(req.priority)
    .bind(req.tls_json.as_deref())
    .bind(req.enabled)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    Ok(Json(TcpRouterRow {
        id,
        name: req.name,
        rule: req.rule,
        service: req.service,
        entry_points: req.entry_points,
        priority: req.priority,
        tls_json: req.tls_json,
        enabled: req.enabled,
        created_at: now,
    }))
}

pub async fn update_tcp_router(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<TcpRouterReq>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query(
        "UPDATE tc_tcp_routers SET name=?1, rule=?2, service=?3, entry_points=?4, priority=?5, tls_json=?6, enabled=?7 WHERE id=?8",
    )
    .bind(&req.name)
    .bind(&req.rule)
    .bind(&req.service)
    .bind(&req.entry_points)
    .bind(req.priority)
    .bind(req.tls_json.as_deref())
    .bind(req.enabled)
    .bind(&id)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(MessageResponse {
        message: "Updated".to_string(),
    }))
}

pub async fn delete_tcp_router(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query("DELETE FROM tc_tcp_routers WHERE id = ?1")
        .bind(&id)
        .execute(&state.pool)
        .await
        .map_err(|_| internal())?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(MessageResponse {
        message: "Deleted".to_string(),
    }))
}

// ============================================================
// CRUD — TCP Services
// ============================================================

pub async fn list_tcp_services(
    State(state): State<AppState>,
) -> Result<Json<Vec<TcpServiceRow>>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, String, String, String, bool, String)>(
        "SELECT id, name, service_type, config_json, enabled, created_at FROM tc_tcp_services WHERE 1=1 ORDER BY name",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| internal())?;

    let items: Vec<TcpServiceRow> = rows
        .into_iter()
        .map(
            |(id, name, service_type, config_json, enabled, created_at)| TcpServiceRow {
                id,
                name,
                service_type,
                config_json,
                enabled,
                created_at,
            },
        )
        .collect();

    Ok(Json(items))
}

pub async fn create_tcp_service(
    State(state): State<AppState>,
    Json(req): Json<TcpServiceReq>,
) -> Result<Json<TcpServiceRow>, StatusCode> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO tc_tcp_services (id, name, service_type, config_json, enabled, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.service_type)
    .bind(&req.config_json)
    .bind(req.enabled)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    Ok(Json(TcpServiceRow {
        id,
        name: req.name,
        service_type: req.service_type,
        config_json: req.config_json,
        enabled: req.enabled,
        created_at: now,
    }))
}

pub async fn update_tcp_service(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<TcpServiceReq>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query(
        "UPDATE tc_tcp_services SET name=?1, service_type=?2, config_json=?3, enabled=?4 WHERE id=?5",
    )
    .bind(&req.name)
    .bind(&req.service_type)
    .bind(&req.config_json)
    .bind(req.enabled)
    .bind(&id)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(MessageResponse {
        message: "Updated".to_string(),
    }))
}

pub async fn delete_tcp_service(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query("DELETE FROM tc_tcp_services WHERE id = ?1")
        .bind(&id)
        .execute(&state.pool)
        .await
        .map_err(|_| internal())?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(MessageResponse {
        message: "Deleted".to_string(),
    }))
}

// ============================================================
// CRUD — UDP Routers
// ============================================================

pub async fn list_udp_routers(
    State(state): State<AppState>,
) -> Result<Json<Vec<UdpRouterRow>>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, String, String, String, String, i64, bool, String)>(
        "SELECT id, name, rule, service, entry_points, priority, enabled, created_at FROM tc_udp_routers WHERE 1=1 ORDER BY name",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| internal())?;

    let items: Vec<UdpRouterRow> = rows
        .into_iter()
        .map(
            |(id, name, rule, service, entry_points, priority, enabled, created_at)| UdpRouterRow {
                id,
                name,
                rule,
                service,
                entry_points,
                priority,
                enabled,
                created_at,
            },
        )
        .collect();

    Ok(Json(items))
}

pub async fn create_udp_router(
    State(state): State<AppState>,
    Json(req): Json<UdpRouterReq>,
) -> Result<Json<UdpRouterRow>, StatusCode> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO tc_udp_routers (id, name, rule, service, entry_points, priority, enabled, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.rule)
    .bind(&req.service)
    .bind(&req.entry_points)
    .bind(req.priority)
    .bind(req.enabled)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    Ok(Json(UdpRouterRow {
        id,
        name: req.name,
        rule: req.rule,
        service: req.service,
        entry_points: req.entry_points,
        priority: req.priority,
        enabled: req.enabled,
        created_at: now,
    }))
}

pub async fn update_udp_router(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UdpRouterReq>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query(
        "UPDATE tc_udp_routers SET name=?1, rule=?2, service=?3, entry_points=?4, priority=?5, enabled=?6 WHERE id=?7",
    )
    .bind(&req.name)
    .bind(&req.rule)
    .bind(&req.service)
    .bind(&req.entry_points)
    .bind(req.priority)
    .bind(req.enabled)
    .bind(&id)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(MessageResponse {
        message: "Updated".to_string(),
    }))
}

pub async fn delete_udp_router(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query("DELETE FROM tc_udp_routers WHERE id = ?1")
        .bind(&id)
        .execute(&state.pool)
        .await
        .map_err(|_| internal())?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(MessageResponse {
        message: "Deleted".to_string(),
    }))
}

// ============================================================
// CRUD — UDP Services
// ============================================================

pub async fn list_udp_services(
    State(state): State<AppState>,
) -> Result<Json<Vec<UdpServiceRow>>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, String, String, String, bool, String)>(
        "SELECT id, name, service_type, config_json, enabled, created_at FROM tc_udp_services WHERE 1=1 ORDER BY name",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| internal())?;

    let items: Vec<UdpServiceRow> = rows
        .into_iter()
        .map(
            |(id, name, service_type, config_json, enabled, created_at)| UdpServiceRow {
                id,
                name,
                service_type,
                config_json,
                enabled,
                created_at,
            },
        )
        .collect();

    Ok(Json(items))
}

pub async fn create_udp_service(
    State(state): State<AppState>,
    Json(req): Json<UdpServiceReq>,
) -> Result<Json<UdpServiceRow>, StatusCode> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO tc_udp_services (id, name, service_type, config_json, enabled, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.service_type)
    .bind(&req.config_json)
    .bind(req.enabled)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    Ok(Json(UdpServiceRow {
        id,
        name: req.name,
        service_type: req.service_type,
        config_json: req.config_json,
        enabled: req.enabled,
        created_at: now,
    }))
}

pub async fn update_udp_service(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UdpServiceReq>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query(
        "UPDATE tc_udp_services SET name=?1, service_type=?2, config_json=?3, enabled=?4 WHERE id=?5",
    )
    .bind(&req.name)
    .bind(&req.service_type)
    .bind(&req.config_json)
    .bind(req.enabled)
    .bind(&id)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(MessageResponse {
        message: "Updated".to_string(),
    }))
}

pub async fn delete_udp_service(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query("DELETE FROM tc_udp_services WHERE id = ?1")
        .bind(&id)
        .execute(&state.pool)
        .await
        .map_err(|_| internal())?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(MessageResponse {
        message: "Deleted".to_string(),
    }))
}

// ============================================================
// CRUD — TLS Certificates
// ============================================================

pub async fn list_tls_certs(
    State(state): State<AppState>,
) -> Result<Json<Vec<TlsCertRow>>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, String, String, String, String, String)>(
        "SELECT id, name, cert_file, key_file, stores_json, created_at FROM tc_tls_certs WHERE 1=1 ORDER BY name",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| internal())?;

    let items: Vec<TlsCertRow> = rows
        .into_iter()
        .map(
            |(id, name, cert_file, key_file, stores_json, created_at)| TlsCertRow {
                id,
                name,
                cert_file,
                key_file,
                stores_json,
                created_at,
            },
        )
        .collect();

    Ok(Json(items))
}

pub async fn create_tls_cert(
    State(state): State<AppState>,
    Json(req): Json<TlsCertReq>,
) -> Result<Json<TlsCertRow>, StatusCode> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO tc_tls_certs (id, name, cert_file, key_file, stores_json, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.cert_file)
    .bind(&req.key_file)
    .bind(&req.stores_json)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    Ok(Json(TlsCertRow {
        id,
        name: req.name,
        cert_file: req.cert_file,
        key_file: req.key_file,
        stores_json: req.stores_json,
        created_at: now,
    }))
}

pub async fn update_tls_cert(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<TlsCertReq>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query(
        "UPDATE tc_tls_certs SET name=?1, cert_file=?2, key_file=?3, stores_json=?4 WHERE id=?5",
    )
    .bind(&req.name)
    .bind(&req.cert_file)
    .bind(&req.key_file)
    .bind(&req.stores_json)
    .bind(&id)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(MessageResponse {
        message: "Updated".to_string(),
    }))
}

pub async fn delete_tls_cert(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query("DELETE FROM tc_tls_certs WHERE id = ?1")
        .bind(&id)
        .execute(&state.pool)
        .await
        .map_err(|_| internal())?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(MessageResponse {
        message: "Deleted".to_string(),
    }))
}

// ============================================================
// CRUD — TLS Options
// ============================================================

pub async fn list_tls_options(
    State(state): State<AppState>,
) -> Result<Json<Vec<TlsOptionsRow>>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT id, name, config_json, created_at FROM tc_tls_options WHERE 1=1 ORDER BY name",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| internal())?;

    let items: Vec<TlsOptionsRow> = rows
        .into_iter()
        .map(|(id, name, config_json, created_at)| TlsOptionsRow {
            id,
            name,
            config_json,
            created_at,
        })
        .collect();

    Ok(Json(items))
}

pub async fn create_tls_option(
    State(state): State<AppState>,
    Json(req): Json<TlsOptionsReq>,
) -> Result<Json<TlsOptionsRow>, StatusCode> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO tc_tls_options (id, name, config_json, created_at) VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.config_json)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    Ok(Json(TlsOptionsRow {
        id,
        name: req.name,
        config_json: req.config_json,
        created_at: now,
    }))
}

pub async fn update_tls_option(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<TlsOptionsReq>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query("UPDATE tc_tls_options SET name=?1, config_json=?2 WHERE id=?3")
        .bind(&req.name)
        .bind(&req.config_json)
        .bind(&id)
        .execute(&state.pool)
        .await
        .map_err(|_| internal())?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(MessageResponse {
        message: "Updated".to_string(),
    }))
}

pub async fn delete_tls_option(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query("DELETE FROM tc_tls_options WHERE id = ?1")
        .bind(&id)
        .execute(&state.pool)
        .await
        .map_err(|_| internal())?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(MessageResponse {
        message: "Deleted".to_string(),
    }))
}

// ============================================================
// CRUD — Certificate Resolvers
// ============================================================

pub async fn list_cert_resolvers(
    State(state): State<AppState>,
) -> Result<Json<Vec<CertResolverRow>>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT id, name, config_json, created_at FROM tc_cert_resolvers WHERE 1=1 ORDER BY name",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| internal())?;

    let items: Vec<CertResolverRow> = rows
        .into_iter()
        .map(|(id, name, config_json, created_at)| CertResolverRow {
            id,
            name,
            config_json,
            created_at,
        })
        .collect();

    Ok(Json(items))
}

pub async fn create_cert_resolver(
    State(state): State<AppState>,
    Json(req): Json<CertResolverReq>,
) -> Result<Json<CertResolverRow>, StatusCode> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT INTO tc_cert_resolvers (id, name, config_json, created_at) VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(&id)
    .bind(&req.name)
    .bind(&req.config_json)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    Ok(Json(CertResolverRow {
        id,
        name: req.name,
        config_json: req.config_json,
        created_at: now,
    }))
}

pub async fn update_cert_resolver(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CertResolverReq>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query("UPDATE tc_cert_resolvers SET name=?1, config_json=?2 WHERE id=?3")
        .bind(&req.name)
        .bind(&req.config_json)
        .bind(&id)
        .execute(&state.pool)
        .await
        .map_err(|_| internal())?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(MessageResponse {
        message: "Updated".to_string(),
    }))
}

pub async fn delete_cert_resolver(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query("DELETE FROM tc_cert_resolvers WHERE id = ?1")
        .bind(&id)
        .execute(&state.pool)
        .await
        .map_err(|_| internal())?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }

    Ok(Json(MessageResponse {
        message: "Deleted".to_string(),
    }))
}
