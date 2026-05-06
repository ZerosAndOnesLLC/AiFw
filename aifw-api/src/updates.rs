use aifw_core::updater::{self, AifwUpdateInfo};
use axum::{Json, extract::State, http::StatusCode};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use tokio::process::Command;

use crate::AppState;

#[derive(Debug, Serialize)]
pub struct UpdateStatus {
    pub os_version: String,
    pub last_check: Option<String>,
    pub pending_os_updates: bool,
    pub pending_pkg_count: u32,
    pub pending_packages: Vec<String>,
    pub needs_reboot: bool,
    pub checking: bool,
    pub installing: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct MaintenanceWindow {
    pub enabled: bool,
    pub day_of_week: String, // mon,tue,wed...
    pub time: String,        // HH:MM (24h)
    pub auto_install: bool,
    pub auto_reboot: bool,
    pub auto_check: bool,
    #[serde(default)]
    pub auto_update_aifw: bool,
}

impl Default for MaintenanceWindow {
    fn default() -> Self {
        Self {
            enabled: false,
            day_of_week: "sun".to_string(),
            time: "03:00".to_string(),
            auto_install: false,
            auto_reboot: false,
            auto_check: true,
            auto_update_aifw: false,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct UpdateHistoryEntry {
    pub id: String,
    pub action: String,
    pub details: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub data: T,
}
#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

/// Response for install/rollback. `restart_required: true` tells the UI to
/// prompt the user before bouncing services — installs no longer auto-restart.
/// `reboot_recommended: true` (parsed from release notes) flips the modal's
/// primary action from "Restart services" to "Reboot now."
#[derive(Debug, Serialize)]
pub struct UpdateInstallResponse {
    pub message: String,
    pub restart_required: bool,
    #[serde(default)]
    pub reboot_recommended: bool,
    #[serde(default)]
    pub reboot_reason: Option<String>,
}

fn internal() -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}

// ============================================================
// DB
// ============================================================

pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS update_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    "#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS update_history (
            id TEXT PRIMARY KEY,
            action TEXT NOT NULL,
            details TEXT NOT NULL,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    "#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

async fn log_update(pool: &SqlitePool, action: &str, details: &str, status: &str) {
    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let _ = sqlx::query("INSERT INTO update_history (id, action, details, status, created_at) VALUES (?1,?2,?3,?4,?5)")
        .bind(&id).bind(action).bind(details).bind(status).bind(&now)
        .execute(pool).await;
}

async fn load_schedule(pool: &SqlitePool) -> MaintenanceWindow {
    let rows = sqlx::query_as::<_, (String, String)>("SELECT key, value FROM update_config")
        .fetch_all(pool)
        .await
        .unwrap_or_default();
    let mut mw = MaintenanceWindow::default();
    for (k, v) in rows {
        match k.as_str() {
            "mw_enabled" => mw.enabled = v == "true",
            "mw_day" => mw.day_of_week = v,
            "mw_time" => mw.time = v,
            "mw_auto_install" => mw.auto_install = v == "true",
            "mw_auto_reboot" => mw.auto_reboot = v == "true",
            "mw_auto_check" => mw.auto_check = v == "true",
            "mw_auto_update_aifw" => mw.auto_update_aifw = v == "true",
            _ => {}
        }
    }
    mw
}

async fn save_config(pool: &SqlitePool, key: &str, value: &str) {
    let _ = sqlx::query("INSERT OR REPLACE INTO update_config (key, value) VALUES (?1, ?2)")
        .bind(key)
        .bind(value)
        .execute(pool)
        .await;
}

// ============================================================
// Handlers
// ============================================================

pub async fn update_status(
    State(state): State<AppState>,
) -> Result<Json<UpdateStatus>, StatusCode> {
    let os_version = Command::new("freebsd-version")
        .output()
        .await
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    let last_check =
        sqlx::query_as::<_, (String,)>("SELECT value FROM update_config WHERE key = 'last_check'")
            .fetch_optional(&state.pool)
            .await
            .ok()
            .flatten()
            .map(|r| r.0);

    // Check for pending pkg updates
    let pkg_out = Command::new("/usr/local/bin/sudo")
        .args(["/usr/sbin/pkg", "upgrade", "-n"])
        .output()
        .await
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let mut pending_packages = Vec::new();
    let mut in_list = false;
    for line in pkg_out.lines() {
        if line.contains("to be UPGRADED") || line.contains("to be INSTALLED") {
            in_list = true;
            continue;
        }
        if in_list && line.trim().is_empty() {
            in_list = false;
        }
        if in_list {
            let trimmed = line.trim();
            if !trimmed.is_empty() {
                pending_packages.push(trimmed.to_string());
            }
        }
    }

    let pending_os = Command::new("/usr/local/bin/sudo")
        .args(["/usr/sbin/freebsd-update", "updatesready"])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false);

    let needs_reboot = std::path::Path::new("/var/run/reboot-required").exists()
        || Command::new("/usr/local/bin/sudo")
            .args(["/usr/sbin/freebsd-update", "updatesready"])
            .output()
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);

    Ok(Json(UpdateStatus {
        os_version,
        last_check,
        pending_os_updates: pending_os,
        pending_pkg_count: pending_packages.len() as u32,
        pending_packages,
        needs_reboot,
        checking: false,
        installing: false,
    }))
}

pub async fn check_updates(
    State(state): State<AppState>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let now = Utc::now().to_rfc3339();
    save_config(&state.pool, "last_check", &now).await;

    // Check pkg updates
    let pkg_result = Command::new("/usr/local/bin/sudo")
        .args(["/usr/sbin/pkg", "update"])
        .output()
        .await;
    let pkg_msg = match pkg_result {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            if o.status.success() {
                format!(
                    "Package catalog updated. {}",
                    stdout.lines().last().unwrap_or("")
                )
            } else {
                format!(
                    "Package update failed: {}",
                    String::from_utf8_lossy(&o.stderr)
                )
            }
        }
        Err(e) => format!("Failed to check packages: {}", e),
    };

    // Check OS updates
    let os_result = Command::new("/usr/local/bin/sudo")
        .args([
            "/usr/sbin/freebsd-update",
            "fetch",
            "--not-running-from-cron",
        ])
        .output()
        .await;
    let os_msg = match os_result {
        Ok(o) => {
            if o.status.success() {
                "OS update check complete.".to_string()
            } else {
                format!(
                    "OS update check: {}",
                    String::from_utf8_lossy(&o.stderr)
                        .lines()
                        .next()
                        .unwrap_or("")
                )
            }
        }
        Err(e) => format!("OS update check failed: {}", e),
    };

    let msg = format!("{} {}", pkg_msg.trim(), os_msg.trim());
    log_update(&state.pool, "check", &msg, "completed").await;

    Ok(Json(MessageResponse { message: msg }))
}

pub async fn install_updates(
    State(state): State<AppState>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let mut results = Vec::new();

    // Install pkg updates
    let pkg_result = Command::new("/usr/local/bin/sudo")
        .args(["/usr/sbin/pkg", "upgrade", "-y"])
        .output()
        .await;
    match pkg_result {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout);
            let count = stdout
                .lines()
                .filter(|l| l.contains("Upgrading") || l.contains("Installing"))
                .count();
            results.push(format!("{} packages updated", count));
        }
        Err(e) => results.push(format!("pkg upgrade failed: {}", e)),
    }

    // Install OS updates
    let os_result = Command::new("/usr/local/bin/sudo")
        .args(["/usr/sbin/freebsd-update", "install"])
        .output()
        .await;
    match os_result {
        Ok(o) => {
            if o.status.success() {
                results.push("OS updates installed".to_string());
            } else {
                results.push("No OS updates to install".to_string());
            }
        }
        Err(e) => results.push(format!("OS update failed: {}", e)),
    }

    let msg = results.join(". ");
    log_update(&state.pool, "install", &msg, "completed").await;

    Ok(Json(MessageResponse { message: msg }))
}

pub async fn reboot_system() -> Result<Json<MessageResponse>, StatusCode> {
    // Schedule reboot in 10 seconds
    let _ = Command::new("/usr/local/bin/sudo")
        .args([
            "/sbin/shutdown",
            "-r",
            "+10s",
            "AiFw scheduled reboot for updates",
        ])
        .output()
        .await;
    Ok(Json(MessageResponse {
        message: "System rebooting in 10 seconds".to_string(),
    }))
}

pub async fn shutdown_system() -> Result<Json<MessageResponse>, StatusCode> {
    // Schedule power-off in 10 seconds
    let _ = Command::new("/usr/local/bin/sudo")
        .args([
            "/sbin/shutdown",
            "-p",
            "+10s",
            "AiFw shutdown requested via admin UI",
        ])
        .output()
        .await;
    Ok(Json(MessageResponse {
        message: "System shutting down in 10 seconds".to_string(),
    }))
}

pub async fn get_schedule(
    State(state): State<AppState>,
) -> Result<Json<MaintenanceWindow>, StatusCode> {
    Ok(Json(load_schedule(&state.pool).await))
}

pub async fn update_schedule(
    State(state): State<AppState>,
    Json(mw): Json<MaintenanceWindow>,
) -> Result<Json<MessageResponse>, StatusCode> {
    save_config(
        &state.pool,
        "mw_enabled",
        if mw.enabled { "true" } else { "false" },
    )
    .await;
    save_config(&state.pool, "mw_day", &mw.day_of_week).await;
    save_config(&state.pool, "mw_time", &mw.time).await;
    save_config(
        &state.pool,
        "mw_auto_install",
        if mw.auto_install { "true" } else { "false" },
    )
    .await;
    save_config(
        &state.pool,
        "mw_auto_reboot",
        if mw.auto_reboot { "true" } else { "false" },
    )
    .await;
    save_config(
        &state.pool,
        "mw_auto_check",
        if mw.auto_check { "true" } else { "false" },
    )
    .await;
    save_config(
        &state.pool,
        "mw_auto_update_aifw",
        if mw.auto_update_aifw { "true" } else { "false" },
    )
    .await;

    // Write cron job if enabled
    if mw.enabled {
        let parts: Vec<&str> = mw.time.split(':').collect();
        let hour = parts.first().unwrap_or(&"3");
        let minute = parts.get(1).unwrap_or(&"0");
        let dow = match mw.day_of_week.to_lowercase().as_str() {
            "mon" => "1",
            "tue" => "2",
            "wed" => "3",
            "thu" => "4",
            "fri" => "5",
            "sat" => "6",
            "sun" | _ => "0",
        };
        let mut cron_cmd = String::from("/usr/local/sbin/aifw update os-check");
        if mw.auto_install {
            cron_cmd.push_str(" && /usr/local/sbin/aifw update os-install");
        }
        if mw.auto_update_aifw {
            cron_cmd.push_str(
                "; /usr/local/sbin/aifw update check && /usr/local/sbin/aifw update install",
            );
        }
        if mw.auto_reboot {
            cron_cmd.push_str(" && /sbin/shutdown -r +1m 'AiFw maintenance reboot'");
        }
        let cron_line = format!("{} {} * * {} {}\n", minute, hour, dow, cron_cmd);
        let _ = tokio::fs::write("/var/cron/tabs/aifw-updates", &cron_line).await;
    } else {
        let _ = tokio::fs::remove_file("/var/cron/tabs/aifw-updates").await;
    }

    log_update(
        &state.pool,
        "schedule",
        &format!(
            "Maintenance window {} ({})",
            if mw.enabled { "enabled" } else { "disabled" },
            mw.day_of_week
        ),
        "configured",
    )
    .await;
    Ok(Json(MessageResponse {
        message: "Maintenance window updated".to_string(),
    }))
}

pub async fn update_history(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<UpdateHistoryEntry>>>, StatusCode> {
    let rows = sqlx::query_as::<_, (String,String,String,String,String)>(
        "SELECT id, action, details, status, created_at FROM update_history ORDER BY created_at DESC LIMIT 50"
    ).fetch_all(&state.pool).await.map_err(|_| internal())?;
    let entries: Vec<UpdateHistoryEntry> = rows
        .into_iter()
        .map(|(id, a, d, s, c)| UpdateHistoryEntry {
            id,
            action: a,
            details: d,
            status: s,
            created_at: c,
        })
        .collect();
    Ok(Json(ApiResponse { data: entries }))
}

// ============================================================
// AiFw Self-Update
// ============================================================

pub async fn aifw_update_status(
    State(state): State<AppState>,
) -> Result<Json<AifwUpdateInfo>, StatusCode> {
    // Return cached info if we have it, otherwise just show current version
    let cached = sqlx::query_as::<_, (String,)>(
        "SELECT value FROM update_config WHERE key = 'aifw_cached_info'",
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();

    if let Some((json,)) = cached
        && let Ok(mut info) = serde_json::from_str::<AifwUpdateInfo>(&json)
    {
        // Refresh fields that change without a re-check: the on-disk version
        // (post-install), the running binary's compiled-in version, and the
        // restart-pending derivation. These are cheap and the cached info
        // can be hours old.
        info.current_version = updater::get_current_version().await;
        info.running_version = updater::running_version().to_string();
        info.restart_pending = updater::restart_pending().await;
        return Ok(Json(info));
    }

    Ok(Json(AifwUpdateInfo {
        current_version: updater::get_current_version().await,
        latest_version: String::new(),
        update_available: false,
        release_notes: String::new(),
        published_at: String::new(),
        tarball_url: None,
        checksum_url: None,
        has_backup: std::path::Path::new("/usr/local/share/aifw/backup/version").exists(),
        backup_version: tokio::fs::read_to_string("/usr/local/share/aifw/backup/version")
            .await
            .ok()
            .map(|v| v.trim().to_string()),
        restart_pending: updater::restart_pending().await,
        running_version: updater::running_version().to_string(),
        reboot_recommended: false,
        reboot_reason: None,
    }))
}

pub async fn aifw_check_update(
    State(state): State<AppState>,
) -> Result<Json<AifwUpdateInfo>, StatusCode> {
    let info = updater::check_for_update().await.map_err(|e| {
        tracing::error!("AiFw update check failed: {}", e);
        internal()
    })?;

    // Cache the result
    if let Ok(json) = serde_json::to_string(&info) {
        save_config(&state.pool, "aifw_cached_info", &json).await;
    }
    save_config(&state.pool, "aifw_last_check", &Utc::now().to_rfc3339()).await;

    let status = if info.update_available {
        format!(
            "v{} available (current: v{})",
            info.latest_version, info.current_version
        )
    } else {
        format!("v{} is the latest", info.current_version)
    };
    log_update(&state.pool, "aifw_check", &status, "completed").await;

    Ok(Json(info))
}

pub async fn aifw_install_update(
    State(state): State<AppState>,
) -> Result<Json<UpdateInstallResponse>, StatusCode> {
    // Get cached update info
    let cached = sqlx::query_as::<_, (String,)>(
        "SELECT value FROM update_config WHERE key = 'aifw_cached_info'",
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();

    let info = if let Some((json,)) = cached {
        serde_json::from_str::<AifwUpdateInfo>(&json).map_err(|_| internal())?
    } else {
        // No cached info, check now
        updater::check_for_update().await.map_err(|e| {
            tracing::error!("AiFw update check failed: {}", e);
            internal()
        })?
    };

    if !info.update_available {
        return Ok(Json(UpdateInstallResponse {
            message: "Already running the latest version".to_string(),
            restart_required: false,
            reboot_recommended: false,
            reboot_reason: None,
        }));
    }

    let msg = updater::download_and_install(&info).await.map_err(|e| {
        tracing::error!("AiFw update install failed: {}", e);
        let pool = state.pool.clone();
        let err = e.to_string();
        tokio::spawn(async move {
            log_update(&pool, "aifw_install", &err, "failed").await;
        });
        internal()
    })?;

    log_update(&state.pool, "aifw_install", &msg, "completed").await;

    // Clear cached info
    save_config(&state.pool, "aifw_cached_info", "").await;

    // Do NOT auto-restart. The UI/CLI prompt the operator and call
    // POST /updates/aifw/restart explicitly. Forward the reboot hint
    // we parsed at check-time so the modal can highlight Reboot when
    // the release notes asked for it.
    Ok(Json(UpdateInstallResponse {
        message: msg,
        restart_required: true,
        reboot_recommended: info.reboot_recommended,
        reboot_reason: info.reboot_reason,
    }))
}

pub async fn aifw_rollback(
    State(state): State<AppState>,
) -> Result<Json<UpdateInstallResponse>, StatusCode> {
    let msg = updater::rollback().await.map_err(|e| {
        tracing::error!("AiFw rollback failed: {}", e);
        internal()
    })?;

    log_update(&state.pool, "aifw_rollback", &msg, "completed").await;
    save_config(&state.pool, "aifw_cached_info", "").await;

    // Do NOT auto-restart. The UI/CLI prompt the operator and call
    // POST /updates/aifw/restart explicitly. Rollback never needs a
    // reboot — by definition we're going back to a version we already
    // ran here.
    Ok(Json(UpdateInstallResponse {
        message: msg,
        restart_required: true,
        reboot_recommended: false,
        reboot_reason: None,
    }))
}

/// Operator-confirmed system reboot. Schedules `shutdown -r now` after a
/// short delay so the HTTP response can leave the box; the UI then
/// switches to its reboot-watching overlay.
pub async fn aifw_reboot(
    State(state): State<AppState>,
) -> Result<Json<MessageResponse>, StatusCode> {
    log_update(
        &state.pool,
        "aifw_reboot",
        "operator-triggered reboot",
        "scheduled",
    )
    .await;
    updater::schedule_reboot().await.map_err(|e| {
        tracing::error!("AiFw reboot schedule failed: {}", e);
        internal()
    })?;
    Ok(Json(MessageResponse {
        message: "System rebooting in 1 minute. Cancel with `shutdown -c` on the console.".to_string(),
    }))
}

/// Install AiFw from an uploaded local tarball.
///
/// Accepts a multipart/form-data body with fields:
///   - `tarball`  — the .tar.xz file bytes (required)
///   - `sha256`   — checksum file content (optional; skip to bypass verification)
///   - `restart`  — "true" to auto-restart services after install (optional)
///
/// The tarball is streamed to a temp directory, optionally verified, and then
/// processed through the same extract+install path as remote installs.
/// Body cap: 500 MB (enforced by the route-level DefaultBodyLimit layer in
/// build_router).
pub async fn install_aifw_update_local(
    State(state): State<AppState>,
    mut multipart: axum::extract::Multipart,
) -> Result<Json<MessageResponse>, StatusCode> {
    let tmp_dir = format!("/tmp/aifw-update-local-{}", std::process::id());
    if let Err(e) = tokio::fs::create_dir_all(&tmp_dir).await {
        tracing::warn!(?e, "failed to create tmp dir for local upload");
        return Err(internal());
    }

    let mut tarball_path: Option<std::path::PathBuf> = None;
    let mut expected_hash: Option<String> = None;
    let mut auto_restart = false;

    while let Some(mut field) = multipart
        .next_field()
        .await
        .map_err(|e| {
            tracing::warn!(?e, "multipart next_field error");
            StatusCode::BAD_REQUEST
        })?
    {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "tarball" => {
                use tokio::io::AsyncWriteExt;
                let path = std::path::PathBuf::from(format!("{}/update.tar.xz", tmp_dir));
                let mut file = tokio::fs::File::create(&path)
                    .await
                    .map_err(|_| internal())?;
                while let Some(chunk) = field
                    .chunk()
                    .await
                    .map_err(|_| StatusCode::BAD_REQUEST)?
                {
                    file.write_all(&chunk).await.map_err(|_| internal())?;
                }
                file.flush().await.ok();
                tarball_path = Some(path);
            }
            "sha256" => {
                let v = field.text().await.map_err(|_| StatusCode::BAD_REQUEST)?;
                // Accept both FreeBSD sha256 format ("SHA256 (file) = <hex>")
                // and sha256sum format ("<hex>  filename") — extract_hash handles
                // both, but here we just store the raw content and let
                // install_from_path's caller (us) strip to the hex.
                // Lines look like: "<hex>  aifw-update-...tar.xz"
                // We extract just the hex portion so install_from_path gets a
                // clean expected hash.
                let hash = aifw_core::updater::extract_hash_pub(&v);
                if !hash.is_empty() {
                    expected_hash = Some(hash);
                }
            }
            "restart" => {
                let v = field.text().await.ok();
                auto_restart = v.as_deref() == Some("true");
            }
            _ => {
                // Drain unknown fields
                while field.chunk().await.map_err(|_| StatusCode::BAD_REQUEST)?.is_some() {}
            }
        }
    }

    let path = tarball_path.ok_or_else(|| {
        tracing::warn!("install-local: no tarball field in multipart");
        StatusCode::BAD_REQUEST
    })?;

    // Sanity-check size — refuse pathologically large uploads even if the
    // body-limit layer already capped them.
    let meta = tokio::fs::metadata(&path)
        .await
        .map_err(|_| internal())?;
    if meta.len() > 500 * 1024 * 1024 {
        let _ = tokio::fs::remove_dir_all(&tmp_dir).await;
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let result = aifw_core::updater::install_from_path(
        &path,
        expected_hash.as_deref(),
    )
    .await;

    let _ = tokio::fs::remove_dir_all(&tmp_dir).await;

    match result {
        Ok(version) => {
            let msg = format!("installed {}", version);
            let _ = log_update(&state.pool, "install_local", &msg, "ok").await;
            if auto_restart {
                aifw_core::updater::restart_services().await;
            }
            Ok(Json(MessageResponse { message: msg }))
        }
        Err(e) => {
            let _ = log_update(
                &state.pool,
                "install_local",
                &format!("{e}"),
                "error",
            )
            .await;
            tracing::warn!(?e, "install-local failed");
            Err(internal())
        }
    }
}

/// Operator-confirmed restart of all AiFw services. Returns immediately —
/// `restart_services()` spawns a 2-second-delayed background task so the
/// HTTP response leaves the box before aifw-api itself goes down.
pub async fn aifw_restart_services(
    State(state): State<AppState>,
) -> Result<Json<MessageResponse>, StatusCode> {
    log_update(
        &state.pool,
        "aifw_restart",
        "operator-triggered service restart",
        "started",
    )
    .await;
    updater::restart_services().await;
    Ok(Json(MessageResponse {
        message: "Services restarting...".to_string(),
    }))
}
