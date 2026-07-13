//! Key/value settings surfaces backed by the `auth_config` table: Valkey
//! connection, dashboard history sizing, the generic `metrics` /
//! `api_server` sections, IDS alert-buffer limits, and TLS policy.

use super::*;

pub async fn get_valkey_settings(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let enabled = sqlx::query_as::<_, (String,)>(
        "SELECT value FROM auth_config WHERE key = 'valkey_enabled'",
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    .map(|r| r.0 == "true")
    .unwrap_or(true);
    let url =
        sqlx::query_as::<_, (String,)>("SELECT value FROM auth_config WHERE key = 'valkey_url'")
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten()
            .map(|r| r.0)
            .unwrap_or_else(|| "redis://127.0.0.1:6379".to_string());
    let retention = sqlx::query_as::<_, (String,)>(
        "SELECT value FROM auth_config WHERE key = 'valkey_retention_minutes'",
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    .and_then(|r| r.0.parse::<i64>().ok())
    .unwrap_or(30);
    let status = if state.redis.is_some() {
        "connected"
    } else if !enabled {
        "disabled"
    } else {
        "disconnected"
    };

    Ok(Json(serde_json::json!({
        "enabled": enabled,
        "url": url,
        "retention_minutes": retention,
        "status": status,
    })))
}

#[derive(Debug, Deserialize)]
pub struct UpdateValkeyRequest {
    pub enabled: Option<bool>,
    pub url: Option<String>,
    pub retention_minutes: Option<i64>,
}

pub async fn update_valkey_settings(
    State(state): State<AppState>,
    Json(req): Json<UpdateValkeyRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if let Some(enabled) = req.enabled {
        let _ = sqlx::query(
            "INSERT OR REPLACE INTO auth_config (key, value) VALUES ('valkey_enabled', ?1)",
        )
        .bind(if enabled { "true" } else { "false" })
        .execute(&state.pool)
        .await;
    }
    if let Some(ref url) = req.url {
        let _ = sqlx::query(
            "INSERT OR REPLACE INTO auth_config (key, value) VALUES ('valkey_url', ?1)",
        )
        .bind(url)
        .execute(&state.pool)
        .await;
    }
    if let Some(retention) = req.retention_minutes {
        let _ = sqlx::query("INSERT OR REPLACE INTO auth_config (key, value) VALUES ('valkey_retention_minutes', ?1)")
            .bind(retention.to_string()).execute(&state.pool).await;
    }

    let status = if state.redis.is_some() {
        "connected"
    } else {
        "disconnected"
    };
    Ok(Json(serde_json::json!({
        "message": "Valkey settings saved. Restart API to apply connection changes.",
        "status": status,
    })))
}

// --- Dashboard History Settings ---

/// Average bytes per slim history entry (status + system + interfaces +
/// services + ids JSON). Measured at ~2.6 KB on a production VM; round up
/// to 3000 so the RAM-budget conversion under-allocates rather than over.
/// The previous 2048 estimate caused a 256 MB budget to land at 340 MB of
/// actual RSS (#274).
const HISTORY_ENTRY_BYTES: usize = 3000;

/// Hard upper bound on the ring buffer size. 24 hours of 1-Hz samples at
/// ~2.6 KB each is ~225 MB — already enormous for an in-process buffer.
/// Anything beyond this should be in Valkey/Redis, not RAM. The previous
/// 30-day clamp let operators ask for 6+ GB and silently get it.
pub const HISTORY_SECONDS_HARD_MAX: usize = 86400;

pub async fn get_dashboard_history_settings(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let current = state
        .metrics_history_max
        .load(std::sync::atomic::Ordering::Relaxed);
    let buf_len = state.metrics_history.read().await.len();
    let estimated_ram_mb = (current as f64 * HISTORY_ENTRY_BYTES as f64) / (1024.0 * 1024.0);
    let mode = sqlx::query_as::<_, (String,)>(
        "SELECT value FROM auth_config WHERE key = 'dashboard_history_mode'",
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    .map(|r| r.0)
    .unwrap_or_else(|| "duration".to_string());
    let ram_limit_mb = sqlx::query_as::<_, (String,)>(
        "SELECT value FROM auth_config WHERE key = 'dashboard_history_ram_mb'",
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    .and_then(|r| r.0.parse::<f64>().ok())
    .unwrap_or(0.0);

    Ok(Json(serde_json::json!({
        "history_seconds": current,
        "current_entries": buf_len,
        "estimated_ram_mb": (estimated_ram_mb * 10.0).round() / 10.0,
        "mode": mode,
        "ram_limit_mb": ram_limit_mb,
    })))
}

pub async fn update_dashboard_history_settings(
    State(state): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mode = req
        .get("mode")
        .and_then(|v| v.as_str())
        .unwrap_or("duration");

    let seconds = match mode {
        "ram" => {
            // User specifies MB budget — we calculate how many entries fit
            let ram_mb = req
                .get("ram_limit_mb")
                .and_then(|v| v.as_f64())
                .ok_or(StatusCode::BAD_REQUEST)?;
            // Clamp: 1 MB to 256 MB
            let ram_mb = ram_mb.clamp(1.0, 256.0);
            let entries = ((ram_mb * 1024.0 * 1024.0) / HISTORY_ENTRY_BYTES as f64) as usize;
            let _ = sqlx::query("INSERT OR REPLACE INTO auth_config (key, value) VALUES ('dashboard_history_ram_mb', ?1)")
                .bind(ram_mb.to_string())
                .execute(&state.pool).await;
            entries
        }
        _ => {
            // User specifies duration in seconds

            req.get("history_seconds")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize)
                .ok_or(StatusCode::BAD_REQUEST)?
        }
    };

    // Clamp: min 5 minutes (300), max HISTORY_SECONDS_HARD_MAX (24h)
    let clamped = seconds.clamp(300, HISTORY_SECONDS_HARD_MAX);

    let _ = sqlx::query(
        "INSERT OR REPLACE INTO auth_config (key, value) VALUES ('dashboard_history_seconds', ?1)",
    )
    .bind(clamped.to_string())
    .execute(&state.pool)
    .await;
    let _ = sqlx::query(
        "INSERT OR REPLACE INTO auth_config (key, value) VALUES ('dashboard_history_mode', ?1)",
    )
    .bind(mode)
    .execute(&state.pool)
    .await;

    state
        .metrics_history_max
        .store(clamped, std::sync::atomic::Ordering::Relaxed);

    // Trim the in-memory buffer immediately if reduced
    {
        let mut buf = state.metrics_history.write().await;
        while buf.len() > clamped {
            buf.pop_front();
        }
    }

    let estimated_ram_mb = (clamped as f64 * HISTORY_ENTRY_BYTES as f64) / (1024.0 * 1024.0);
    Ok(Json(serde_json::json!({
        "message": "Dashboard history updated",
        "history_seconds": clamped,
        "estimated_ram_mb": (estimated_ram_mb * 10.0).round() / 10.0,
        "mode": mode,
    })))
}

// --- Generic Settings (metrics, api server) ---
// These persist key-value pairs to auth_config for settings that are display-only
// or applied on next restart.

pub async fn get_generic_settings(
    State(state): State<AppState>,
    axum::extract::Path(section): axum::extract::Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let prefix = format!("{section}_");
    let rows: Vec<(String, String)> =
        sqlx::query_as("SELECT key, value FROM auth_config WHERE key LIKE ?1")
            .bind(format!("{prefix}%"))
            .fetch_all(&state.pool)
            .await
            .map_err(|_| internal())?;
    let mut map = serde_json::Map::new();
    for (k, v) in rows {
        let short_key = k.strip_prefix(&prefix).unwrap_or(&k);
        map.insert(short_key.to_string(), serde_json::Value::String(v));
    }
    Ok(Json(serde_json::Value::Object(map)))
}

pub async fn update_generic_settings(
    State(state): State<AppState>,
    axum::extract::Path(section): axum::extract::Path<String>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let valid_sections = ["metrics", "api_server"];
    if !valid_sections.contains(&section.as_str()) {
        return Err(bad_request());
    }
    if let Some(obj) = req.as_object() {
        for (k, v) in obj {
            let db_key = format!("{section}_{k}");
            let val = match v {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            let _ = sqlx::query("INSERT OR REPLACE INTO auth_config (key, value) VALUES (?1, ?2)")
                .bind(&db_key)
                .bind(&val)
                .execute(&state.pool)
                .await;
        }
    }
    Ok(Json(MessageResponse {
        message: format!("{section} settings saved"),
    }))
}

// --- IDS Alert Buffer Settings ---
//
// The alert buffer itself now lives in the aifw-ids process. These endpoints
// just persist the configured limits in `auth_config`; aifw-ids reads them at
// startup. Live re-tuning would need an IPC method we haven't added yet —
// changes take effect after the next aifw-ids restart.

pub async fn get_ids_alert_settings(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let max_mb: usize = sqlx::query_as::<_, (String,)>(
        "SELECT value FROM auth_config WHERE key = 'ids_alert_max_mb'",
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    .and_then(|r| r.0.parse().ok())
    .unwrap_or(64);
    let max_age: usize = sqlx::query_as::<_, (String,)>(
        "SELECT value FROM auth_config WHERE key = 'ids_alert_max_age_secs'",
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    .and_then(|r| r.0.parse().ok())
    .unwrap_or(86400);
    Ok(Json(serde_json::json!({
        "max_mb": max_mb,
        "max_age_secs": max_age,
    })))
}

pub async fn update_ids_alert_settings(
    State(state): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if let Some(mb) = req.get("max_mb").and_then(|v| v.as_u64()) {
        let mb = (mb as usize).clamp(8, 512);
        let _ = sqlx::query(
            "INSERT OR REPLACE INTO auth_config (key, value) VALUES ('ids_alert_max_mb', ?1)",
        )
        .bind(mb.to_string())
        .execute(&state.pool)
        .await;
    }
    if let Some(secs) = req.get("max_age_secs").and_then(|v| v.as_u64()) {
        let secs = (secs as usize).clamp(3600, 604800); // 1h to 7 days
        let _ = sqlx::query(
            "INSERT OR REPLACE INTO auth_config (key, value) VALUES ('ids_alert_max_age_secs', ?1)",
        )
        .bind(secs.to_string())
        .execute(&state.pool)
        .await;
    }
    Ok(Json(serde_json::json!({
        "message": "IDS alert settings updated — restart aifw-ids to apply",
    })))
}

// --- TLS Policy Settings ---

pub async fn get_tls_settings(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let pool = &state.pool;
    let min_ver = sqlx::query_as::<_, (String,)>(
        "SELECT value FROM auth_config WHERE key = 'tls_min_version'",
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .map(|r| r.0)
    .unwrap_or_else(|| "tls12".to_string());
    let block_expired = sqlx::query_as::<_, (String,)>(
        "SELECT value FROM auth_config WHERE key = 'tls_block_expired'",
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .map(|r| r.0 == "true")
    .unwrap_or(true);
    let block_weak = sqlx::query_as::<_, (String,)>(
        "SELECT value FROM auth_config WHERE key = 'tls_block_weak_keys'",
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .map(|r| r.0 == "true")
    .unwrap_or(true);
    Ok(Json(serde_json::json!({
        "min_version": min_ver,
        "block_expired": block_expired,
        "block_weak_keys": block_weak,
    })))
}

pub async fn update_tls_settings(
    State(state): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<MessageResponse>, StatusCode> {
    if let Some(v) = req.get("min_version").and_then(|v| v.as_str()) {
        let _ = sqlx::query(
            "INSERT OR REPLACE INTO auth_config (key, value) VALUES ('tls_min_version', ?1)",
        )
        .bind(v)
        .execute(&state.pool)
        .await;
    }
    if let Some(v) = req.get("block_expired").and_then(|v| v.as_bool()) {
        let _ = sqlx::query(
            "INSERT OR REPLACE INTO auth_config (key, value) VALUES ('tls_block_expired', ?1)",
        )
        .bind(if v { "true" } else { "false" })
        .execute(&state.pool)
        .await;
    }
    if let Some(v) = req.get("block_weak_keys").and_then(|v| v.as_bool()) {
        let _ = sqlx::query(
            "INSERT OR REPLACE INTO auth_config (key, value) VALUES ('tls_block_weak_keys', ?1)",
        )
        .bind(if v { "true" } else { "false" })
        .execute(&state.pool)
        .await;
    }
    Ok(Json(MessageResponse {
        message: "TLS policy saved".to_string(),
    }))
}
