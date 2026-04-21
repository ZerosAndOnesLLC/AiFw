use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use tokio::process::Command;
use uuid::Uuid;

use crate::AppState;

const RTIME_CONFIG_PATH: &str = "/usr/local/etc/rtime/rtime.toml";
const RTIME_LOG_PATH: &str = "/var/log/rtime/rtime.log";

fn internal() -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}

// ============================================================
// Types
// ============================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ApiResponse<T: Serialize> {
    pub data: T,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TimeConfig {
    pub enabled: bool,
    pub log_level: String,
    // Clock
    pub clock_discipline: bool,
    pub clock_step_threshold_ms: f64,
    pub clock_panic_threshold_ms: f64,
    // NTP server
    pub ntp_enabled: bool,
    pub ntp_listen: String,
    pub ntp_interfaces: Vec<String>,
    pub ntp_rate_limit: f64,
    pub ntp_rate_burst: u32,
    // NTS
    pub nts_enabled: bool,
    pub nts_ke_listen: String,
    pub nts_certificate: String,
    pub nts_private_key: String,
    // PTP
    pub ptp_enabled: bool,
    pub ptp_domain: u8,
    pub ptp_interface: String,
    pub ptp_transport: String,
    pub ptp_priority1: u8,
    pub ptp_priority2: u8,
    pub ptp_delay_mechanism: String,
    // Metrics
    pub metrics_enabled: bool,
    pub metrics_listen: String,
    // Management
    pub management_enabled: bool,
    pub management_listen: String,
}

impl Default for TimeConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            log_level: "info".to_string(),
            clock_discipline: true,
            clock_step_threshold_ms: 128.0,
            clock_panic_threshold_ms: 1000.0,
            ntp_enabled: true,
            ntp_listen: "0.0.0.0:123".to_string(),
            ntp_interfaces: vec![],
            ntp_rate_limit: 16.0,
            ntp_rate_burst: 32,
            nts_enabled: false,
            nts_ke_listen: "0.0.0.0:4460".to_string(),
            nts_certificate: String::new(),
            nts_private_key: String::new(),
            ptp_enabled: false,
            ptp_domain: 0,
            ptp_interface: "em0".to_string(),
            ptp_transport: "udp-ipv4".to_string(),
            ptp_priority1: 128,
            ptp_priority2: 128,
            ptp_delay_mechanism: "e2e".to_string(),
            metrics_enabled: true,
            metrics_listen: "127.0.0.1:9100".to_string(),
            management_enabled: true,
            management_listen: "127.0.0.1:9200".to_string(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NtpSource {
    pub id: String,
    pub address: String,
    pub nts: bool,
    pub min_poll: i8,
    pub max_poll: i8,
    pub enabled: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateNtpSource {
    pub address: String,
    pub nts: Option<bool>,
    pub min_poll: Option<i8>,
    pub max_poll: Option<i8>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct TimeStatus {
    pub running: bool,
    pub version: String,
    pub sources_count: usize,
}

// ============================================================
// Database
// ============================================================

pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS time_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS ntp_sources (
            id TEXT PRIMARY KEY,
            address TEXT NOT NULL,
            nts INTEGER NOT NULL DEFAULT 0,
            min_poll INTEGER NOT NULL DEFAULT 4,
            max_poll INTEGER NOT NULL DEFAULT 10,
            enabled INTEGER NOT NULL DEFAULT 1
        )
    "#,
    )
    .execute(pool)
    .await?;

    // Seed default NTP sources if empty
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ntp_sources")
        .fetch_one(pool)
        .await?;
    if count.0 == 0 {
        for (addr, nts) in [
            ("time.cloudflare.com", true),
            ("time.google.com", false),
            ("pool.ntp.org", false),
            ("time.apple.com", false),
        ] {
            let _ = sqlx::query("INSERT INTO ntp_sources (id, address, nts, min_poll, max_poll, enabled) VALUES (?, ?, ?, 4, 10, 1)")
                .bind(Uuid::new_v4().to_string())
                .bind(addr)
                .bind(nts as i32)
                .execute(pool).await;
        }
    }

    Ok(())
}

async fn save_key(pool: &SqlitePool, key: &str, value: &str) {
    let _ = sqlx::query("INSERT INTO time_config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value")
        .bind(key).bind(value).execute(pool).await;
}

async fn load_config(pool: &SqlitePool) -> TimeConfig {
    let d = TimeConfig::default();
    let rows = sqlx::query_as::<_, (String, String)>("SELECT key, value FROM time_config")
        .fetch_all(pool)
        .await
        .unwrap_or_default();
    let mut m = std::collections::HashMap::new();
    for (k, v) in rows {
        m.insert(k, v);
    }

    let s = |key: &str| -> Option<&String> { m.get(key) };
    let b = |key: &str, def: bool| -> bool { s(key).map(|v| v == "true").unwrap_or(def) };

    TimeConfig {
        enabled: b("enabled", d.enabled),
        log_level: s("log_level").cloned().unwrap_or(d.log_level),
        clock_discipline: b("clock_discipline", d.clock_discipline),
        clock_step_threshold_ms: s("clock_step_threshold_ms")
            .and_then(|v| v.parse().ok())
            .unwrap_or(d.clock_step_threshold_ms),
        clock_panic_threshold_ms: s("clock_panic_threshold_ms")
            .and_then(|v| v.parse().ok())
            .unwrap_or(d.clock_panic_threshold_ms),
        ntp_enabled: b("ntp_enabled", d.ntp_enabled),
        ntp_listen: s("ntp_listen").cloned().unwrap_or(d.ntp_listen),
        ntp_interfaces: s("ntp_interfaces")
            .map(|v| {
                v.split(',')
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect()
            })
            .unwrap_or(d.ntp_interfaces),
        ntp_rate_limit: s("ntp_rate_limit")
            .and_then(|v| v.parse().ok())
            .unwrap_or(d.ntp_rate_limit),
        ntp_rate_burst: s("ntp_rate_burst")
            .and_then(|v| v.parse().ok())
            .unwrap_or(d.ntp_rate_burst),
        nts_enabled: b("nts_enabled", d.nts_enabled),
        nts_ke_listen: s("nts_ke_listen").cloned().unwrap_or(d.nts_ke_listen),
        nts_certificate: s("nts_certificate").cloned().unwrap_or(d.nts_certificate),
        nts_private_key: s("nts_private_key").cloned().unwrap_or(d.nts_private_key),
        ptp_enabled: b("ptp_enabled", d.ptp_enabled),
        ptp_domain: s("ptp_domain")
            .and_then(|v| v.parse().ok())
            .unwrap_or(d.ptp_domain),
        ptp_interface: s("ptp_interface").cloned().unwrap_or(d.ptp_interface),
        ptp_transport: s("ptp_transport").cloned().unwrap_or(d.ptp_transport),
        ptp_priority1: s("ptp_priority1")
            .and_then(|v| v.parse().ok())
            .unwrap_or(d.ptp_priority1),
        ptp_priority2: s("ptp_priority2")
            .and_then(|v| v.parse().ok())
            .unwrap_or(d.ptp_priority2),
        ptp_delay_mechanism: s("ptp_delay_mechanism")
            .cloned()
            .unwrap_or(d.ptp_delay_mechanism),
        metrics_enabled: b("metrics_enabled", d.metrics_enabled),
        metrics_listen: s("metrics_listen").cloned().unwrap_or(d.metrics_listen),
        management_enabled: b("management_enabled", d.management_enabled),
        management_listen: s("management_listen")
            .cloned()
            .unwrap_or(d.management_listen),
    }
}

// ============================================================
// Handlers — Config
// ============================================================

pub async fn get_config(State(state): State<AppState>) -> Result<Json<TimeConfig>, StatusCode> {
    Ok(Json(load_config(&state.pool).await))
}

pub async fn update_config(
    State(state): State<AppState>,
    Json(c): Json<TimeConfig>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let p = &state.pool;
    save_key(p, "enabled", if c.enabled { "true" } else { "false" }).await;
    save_key(p, "log_level", &c.log_level).await;
    save_key(
        p,
        "clock_discipline",
        if c.clock_discipline { "true" } else { "false" },
    )
    .await;
    save_key(
        p,
        "clock_step_threshold_ms",
        &c.clock_step_threshold_ms.to_string(),
    )
    .await;
    save_key(
        p,
        "clock_panic_threshold_ms",
        &c.clock_panic_threshold_ms.to_string(),
    )
    .await;
    save_key(
        p,
        "ntp_enabled",
        if c.ntp_enabled { "true" } else { "false" },
    )
    .await;
    save_key(p, "ntp_listen", &c.ntp_listen).await;
    save_key(p, "ntp_interfaces", &c.ntp_interfaces.join(",")).await;
    save_key(p, "ntp_rate_limit", &c.ntp_rate_limit.to_string()).await;
    save_key(p, "ntp_rate_burst", &c.ntp_rate_burst.to_string()).await;
    save_key(
        p,
        "nts_enabled",
        if c.nts_enabled { "true" } else { "false" },
    )
    .await;
    save_key(p, "nts_ke_listen", &c.nts_ke_listen).await;
    save_key(p, "nts_certificate", &c.nts_certificate).await;
    save_key(p, "nts_private_key", &c.nts_private_key).await;
    save_key(
        p,
        "ptp_enabled",
        if c.ptp_enabled { "true" } else { "false" },
    )
    .await;
    save_key(p, "ptp_domain", &c.ptp_domain.to_string()).await;
    save_key(p, "ptp_interface", &c.ptp_interface).await;
    save_key(p, "ptp_transport", &c.ptp_transport).await;
    save_key(p, "ptp_priority1", &c.ptp_priority1.to_string()).await;
    save_key(p, "ptp_priority2", &c.ptp_priority2.to_string()).await;
    save_key(p, "ptp_delay_mechanism", &c.ptp_delay_mechanism).await;
    save_key(
        p,
        "metrics_enabled",
        if c.metrics_enabled { "true" } else { "false" },
    )
    .await;
    save_key(p, "metrics_listen", &c.metrics_listen).await;
    save_key(
        p,
        "management_enabled",
        if c.management_enabled {
            "true"
        } else {
            "false"
        },
    )
    .await;
    save_key(p, "management_listen", &c.management_listen).await;
    Ok(Json(MessageResponse {
        message: "Time service config updated".to_string(),
    }))
}

// ============================================================
// Handlers — NTP Sources CRUD
// ============================================================

pub async fn list_sources(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<NtpSource>>>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, String, i32, i32, i32, i32)>(
        "SELECT id, address, nts, min_poll, max_poll, enabled FROM ntp_sources ORDER BY address",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| internal())?;

    let sources: Vec<NtpSource> = rows
        .into_iter()
        .map(
            |(id, address, nts, min_poll, max_poll, enabled)| NtpSource {
                id,
                address,
                nts: nts != 0,
                min_poll: min_poll as i8,
                max_poll: max_poll as i8,
                enabled: enabled != 0,
            },
        )
        .collect();

    Ok(Json(ApiResponse { data: sources }))
}

pub async fn create_source(
    State(state): State<AppState>,
    Json(req): Json<CreateNtpSource>,
) -> Result<(StatusCode, Json<ApiResponse<NtpSource>>), StatusCode> {
    let id = Uuid::new_v4().to_string();
    let nts = req.nts.unwrap_or(false);
    let min_poll = req.min_poll.unwrap_or(4);
    let max_poll = req.max_poll.unwrap_or(10);
    let enabled = req.enabled.unwrap_or(true);

    sqlx::query("INSERT INTO ntp_sources (id, address, nts, min_poll, max_poll, enabled) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(&id).bind(&req.address).bind(nts as i32).bind(min_poll as i32).bind(max_poll as i32).bind(enabled as i32)
        .execute(&state.pool).await.map_err(|_| internal())?;

    let source = NtpSource {
        id,
        address: req.address,
        nts,
        min_poll,
        max_poll,
        enabled,
    };
    Ok((StatusCode::CREATED, Json(ApiResponse { data: source })))
}

pub async fn update_source(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateNtpSource>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let nts = req.nts.unwrap_or(false);
    let min_poll = req.min_poll.unwrap_or(4);
    let max_poll = req.max_poll.unwrap_or(10);
    let enabled = req.enabled.unwrap_or(true);

    sqlx::query(
        "UPDATE ntp_sources SET address=?, nts=?, min_poll=?, max_poll=?, enabled=? WHERE id=?",
    )
    .bind(&req.address)
    .bind(nts as i32)
    .bind(min_poll as i32)
    .bind(max_poll as i32)
    .bind(enabled as i32)
    .bind(&id)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    Ok(Json(MessageResponse {
        message: format!("Source {} updated", id),
    }))
}

pub async fn delete_source(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    sqlx::query("DELETE FROM ntp_sources WHERE id = ?")
        .bind(&id)
        .execute(&state.pool)
        .await
        .map_err(|_| internal())?;
    Ok(Json(MessageResponse {
        message: format!("Source {} deleted", id),
    }))
}

// ============================================================
// Handlers — Service control
// ============================================================

async fn run_service(action: &str) -> Json<MessageResponse> {
    if action == "start" || action == "restart" {
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["/usr/sbin/sysrc", "rtime_enable=YES"])
            .output()
            .await;
    }
    let output = Command::new("/usr/local/bin/sudo")
        .args(["/usr/sbin/service", "rtime", action])
        .output()
        .await;
    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            let msg = if o.status.success() {
                format!("Time service {}: {}", action, stdout.trim())
            } else {
                format!(
                    "Time service {} failed: {} {}",
                    action,
                    stdout.trim(),
                    stderr.trim()
                )
            };
            Json(MessageResponse { message: msg })
        }
        Err(e) => Json(MessageResponse {
            message: format!("Failed to {} time service: {}", action, e),
        }),
    }
}

pub async fn time_status(State(state): State<AppState>) -> Result<Json<TimeStatus>, StatusCode> {
    let running = Command::new("/usr/local/bin/sudo")
        .args(["/usr/sbin/service", "rtime", "status"])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    let version = if running {
        "rTime (running)".to_string()
    } else {
        "rTime (stopped)".to_string()
    };

    let sources = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM ntp_sources WHERE enabled = 1")
        .fetch_one(&state.pool)
        .await
        .map(|r| r.0 as usize)
        .unwrap_or(0);

    Ok(Json(TimeStatus {
        running,
        version,
        sources_count: sources,
    }))
}

pub async fn time_start(
    State(state): State<AppState>,
) -> Result<Json<MessageResponse>, StatusCode> {
    ensure_config(&state.pool).await;
    Ok(run_service("start").await)
}

pub async fn time_stop() -> Result<Json<MessageResponse>, StatusCode> {
    Ok(run_service("stop").await)
}

pub async fn time_restart(
    State(state): State<AppState>,
) -> Result<Json<MessageResponse>, StatusCode> {
    ensure_config(&state.pool).await;
    Ok(run_service("restart").await)
}

async fn ensure_config(pool: &SqlitePool) {
    if tokio::fs::metadata(RTIME_CONFIG_PATH).await.is_err() {
        let toml = generate_rtime_config(pool).await;
        let _ = tokio::fs::create_dir_all("/usr/local/etc/rtime").await;
        let _ = tokio::fs::create_dir_all("/var/log/rtime").await;
        let _ = tokio::fs::write(RTIME_CONFIG_PATH, &toml).await;
    }
}

// ============================================================
// Handlers — Apply
// ============================================================

pub async fn apply_config(
    State(state): State<AppState>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let config = load_config(&state.pool).await;
    let toml = generate_rtime_config(&state.pool).await;

    let _ = tokio::fs::create_dir_all("/usr/local/etc/rtime").await;
    let _ = tokio::fs::create_dir_all("/var/log/rtime").await;

    tokio::fs::write(RTIME_CONFIG_PATH, &toml)
        .await
        .map_err(|_| internal())?;

    let _ = Command::new("/usr/local/bin/sudo")
        .args(["chown", "-R", "aifw:aifw", "/usr/local/etc/rtime"])
        .output()
        .await;
    let _ = Command::new("/usr/local/bin/sudo")
        .args(["chown", "-R", "aifw:aifw", "/var/log/rtime"])
        .output()
        .await;

    if config.enabled {
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["/usr/sbin/sysrc", "rtime_enable=YES"])
            .output()
            .await;
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["/usr/sbin/service", "rtime", "restart"])
            .output()
            .await;

        Ok(Json(MessageResponse {
            message: "Time config applied and rTime restarted".to_string(),
        }))
    } else {
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["/usr/sbin/service", "rtime", "stop"])
            .output()
            .await;
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["/usr/sbin/sysrc", "rtime_enable=NO"])
            .output()
            .await;
        Ok(Json(MessageResponse {
            message: "Time config saved, rTime stopped".to_string(),
        }))
    }
}

// ============================================================
// Handlers — Logs
// ============================================================

pub async fn time_logs(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<ApiResponse<Vec<String>>>, StatusCode> {
    let lines_param = params
        .get("lines")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(200);
    let search = params.get("search").cloned().unwrap_or_default();

    let log_lines = crate::log_tail::tail_filtered(
        &[RTIME_LOG_PATH, "/var/log/rtime.log"],
        if search.is_empty() {
            None
        } else {
            Some(&search)
        },
        5000,
        lines_param,
    )
    .await;

    Ok(Json(ApiResponse { data: log_lines }))
}

// ============================================================
// TOML Generation
// ============================================================

async fn generate_rtime_config(pool: &SqlitePool) -> String {
    let c = load_config(pool).await;

    let sources = sqlx::query_as::<_, (String, i32, i32, i32)>(
        "SELECT address, nts, min_poll, max_poll FROM ntp_sources WHERE enabled = 1 ORDER BY address"
    ).fetch_all(pool).await.unwrap_or_default();

    let mut toml = String::new();

    // [general]
    toml.push_str("[general]\n");
    toml.push_str(&format!("log_level = \"{}\"\n\n", c.log_level));

    // [clock]
    toml.push_str("[clock]\n");
    toml.push_str(&format!("discipline = {}\n", c.clock_discipline));
    toml.push_str(&format!(
        "step_threshold_ms = {}\n",
        c.clock_step_threshold_ms
    ));
    toml.push_str(&format!(
        "panic_threshold_ms = {}\n",
        c.clock_panic_threshold_ms
    ));
    toml.push_str("interface = \"system\"\n\n");

    // [ntp]
    toml.push_str("[ntp]\n");
    toml.push_str(&format!("enabled = {}\n", c.ntp_enabled));
    toml.push_str(&format!("listen = \"{}\"\n", c.ntp_listen));
    toml.push_str(&format!("rate_limit = {}\n", c.ntp_rate_limit));
    toml.push_str(&format!("rate_burst = {}\n\n", c.ntp_rate_burst));

    // [[ntp.sources]]
    for (address, nts, min_poll, max_poll) in &sources {
        toml.push_str("[[ntp.sources]]\n");
        toml.push_str(&format!("address = \"{}\"\n", address));
        if *nts != 0 {
            toml.push_str("nts = true\n");
        }
        toml.push_str(&format!("min_poll = {}\n", min_poll));
        toml.push_str(&format!("max_poll = {}\n\n", max_poll));
    }

    // [ntp.nts]
    toml.push_str("[ntp.nts]\n");
    toml.push_str(&format!("enabled = {}\n", c.nts_enabled));
    toml.push_str(&format!("ke_listen = \"{}\"\n", c.nts_ke_listen));
    if !c.nts_certificate.is_empty() {
        toml.push_str(&format!("certificate = \"{}\"\n", c.nts_certificate));
    }
    if !c.nts_private_key.is_empty() {
        toml.push_str(&format!("private_key = \"{}\"\n", c.nts_private_key));
    }
    toml.push('\n');

    // [ptp]
    toml.push_str("[ptp]\n");
    toml.push_str(&format!("enabled = {}\n", c.ptp_enabled));
    toml.push_str(&format!("domain = {}\n", c.ptp_domain));
    toml.push_str(&format!("interface = \"{}\"\n", c.ptp_interface));
    toml.push_str(&format!("transport = \"{}\"\n", c.ptp_transport));
    toml.push_str(&format!("priority1 = {}\n", c.ptp_priority1));
    toml.push_str(&format!("priority2 = {}\n", c.ptp_priority2));
    toml.push_str(&format!(
        "delay_mechanism = \"{}\"\n\n",
        c.ptp_delay_mechanism
    ));

    // [metrics]
    toml.push_str("[metrics]\n");
    toml.push_str(&format!("enabled = {}\n", c.metrics_enabled));
    toml.push_str(&format!("listen = \"{}\"\n\n", c.metrics_listen));

    // [management]
    toml.push_str("[management]\n");
    toml.push_str(&format!("enabled = {}\n", c.management_enabled));
    toml.push_str(&format!("listen = \"{}\"\n", c.management_listen));

    toml
}
