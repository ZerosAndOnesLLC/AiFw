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

/// Build a 500 whose body carries the underlying reason (#504). The updater
/// used to return a bare `internal()` on every failure, so an operator saw
/// only "HTTP 500" while the real cause sat in the logs — the exact wall
/// that made #469 hard to diagnose.
///
/// When `detail` matches a privilege-refusal signature (a sudo helper the
/// unprivileged `aifw` user isn't granted, or a non-executable helper that
/// sudo reports as "command not found"), append the console-as-root
/// workaround so the operator has an immediate next step.
fn install_error(context: &str, detail: &str) -> (StatusCode, String) {
    let mut msg = format!("{context}: {detail}");
    if is_privilege_refusal(detail) {
        msg.push_str(
            "\n\nThis looks like the unprivileged updater being denied by sudo. \
             Run the update from the console as root instead: \
             `aifw update install --pre --restart`, then reboot.",
        );
    }
    (StatusCode::INTERNAL_SERVER_ERROR, msg)
}

/// Detect the stderr fingerprints FreeBSD sudo emits when the `aifw` user
/// lacks a grant, or when a helper exists but isn't executable. Mirrors the
/// `sudo_refused` check in `aifw_core::sudo`.
fn is_privilege_refusal(detail: &str) -> bool {
    let d = detail.to_lowercase();
    d.contains("not allowed to")
        || d.contains("password is required")
        || d.contains("command not found")
        || d.contains("permission denied")
        || d.contains("operation not permitted")
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

/// Whether the operator opted this box into the pre-release update channel.
/// Off by default so field appliances only ever see stable releases.
async fn prereleases_enabled(pool: &SqlitePool) -> bool {
    sqlx::query_as::<_, (String,)>(
        "SELECT value FROM update_config WHERE key = 'aifw_include_prereleases'",
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
    .map(|(v,)| v == "true")
    .unwrap_or(false)
}

#[derive(Deserialize)]
pub struct PrereleaseToggle {
    pub enabled: bool,
}

/// Enable/disable the pre-release update channel for THIS appliance. Lets a
/// test box pull GitHub pre-releases via the normal in-app updater without
/// those releases being promoted to stable "latest" for everyone else.
pub async fn set_prerelease_channel(
    State(state): State<AppState>,
    Json(body): Json<PrereleaseToggle>,
) -> Result<Json<MessageResponse>, StatusCode> {
    save_config(
        &state.pool,
        "aifw_include_prereleases",
        if body.enabled { "true" } else { "false" },
    )
    .await;
    // Drop any cached check so the next status/check reflects the new channel.
    save_config(&state.pool, "aifw_cached_info", "").await;
    Ok(Json(MessageResponse {
        message: format!(
            "Pre-release channel {}",
            if body.enabled { "enabled" } else { "disabled" }
        ),
    }))
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
    let pkg_out = aifw_core::sudo::pkg("upgrade", &["-n"])
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

    // #633: while a release upgrade is in flight, patch-level freebsd-update
    // calls share (and clobber) its state directory — stand down entirely.
    let upgrade_in_flight = os_upgrade_in_flight(&state.pool).await;

    let pending_os = !upgrade_in_flight
        && aifw_core::sudo::freebsd_update("updatesready", &[])
            .await
            .map(|o| o.status.success())
            .unwrap_or(false);

    let needs_reboot = std::path::Path::new("/var/run/reboot-required").exists()
        || (!upgrade_in_flight
            && aifw_core::sudo::freebsd_update("updatesready", &[])
                .await
                .map(|o| o.status.success())
                .unwrap_or(false));

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
    let pkg_result = aifw_core::sudo::pkg("update", &[]).await;
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

    // Check OS updates. #633: a patch-level fetch REPLACES freebsd-update's
    // staged state — running one between the kernel reboot and finalize of
    // a release upgrade silently destroyed the staged release on a live
    // appliance. Stand down while an upgrade is in flight.
    let os_msg = if os_upgrade_in_flight(&state.pool).await {
        "OS release upgrade in progress — patch-level OS checks paused until it completes."
            .to_string()
    } else {
        match aifw_core::sudo::freebsd_update("fetch", &["--not-running-from-cron"]).await {
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
        }
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
    let pkg_result = aifw_core::sudo::pkg("upgrade", &["-y"]).await;
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

    // Install OS updates. #633: stand down while a release upgrade is in
    // flight — a patch install against the shared state dir would consume
    // or corrupt the staged release.
    if os_upgrade_in_flight(&state.pool).await {
        results.push(
            "OS release upgrade in progress — patch-level OS installs paused until it completes."
                .to_string(),
        );
        let msg = results.join(". ");
        log_update(&state.pool, "install", &msg, "completed").await;
        return Ok(Json(MessageResponse { message: msg }));
    }
    let os_result = aifw_core::sudo::freebsd_update("install", &[]).await;
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

// ============================================================
// OS release upgrade (#613)
// ============================================================

/// Persistent state of an OS release upgrade, stored in `update_config`
/// so it survives the reboot in the middle of the flow.
///
/// Phases: `fetching` (freebsd-update -r X upgrade) → `installing`
/// (kernel install) → `reboot_required` → `finalizing` (post-reboot
/// userland install passes, driven by `resume_os_upgrade`) → `done`,
/// or `failed` with the reason in `detail`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsUpgradeState {
    pub target: String,
    pub phase: String,
    pub detail: String,
    pub started_at: String,
    pub updated_at: String,
}

const OS_UPGRADE_KEY: &str = "os_upgrade_state";

async fn load_os_upgrade(pool: &SqlitePool) -> Option<OsUpgradeState> {
    let row = sqlx::query_as::<_, (String,)>("SELECT value FROM update_config WHERE key = ?1")
        .bind(OS_UPGRADE_KEY)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()?;
    serde_json::from_str(&row.0).ok()
}

/// True while a release upgrade owns freebsd-update's state directory —
/// from fetch through the post-reboot finalize. Patch-level freebsd-update
/// operations must stand down in this window (#633): they share the state
/// dir and a routine fetch destroys the staged release.
async fn os_upgrade_in_flight(pool: &SqlitePool) -> bool {
    load_os_upgrade(pool)
        .await
        .map(|s| {
            matches!(
                s.phase.as_str(),
                "fetching" | "installing" | "reboot_required" | "finalizing"
            )
        })
        .unwrap_or(false)
}

async fn store_os_upgrade(pool: &SqlitePool, state: &OsUpgradeState) {
    if let Ok(json) = serde_json::to_string(state) {
        save_config(pool, OS_UPGRADE_KEY, &json).await;
    }
}

async fn set_os_upgrade_phase(
    pool: &SqlitePool,
    state: &mut OsUpgradeState,
    phase: &str,
    detail: String,
) {
    state.phase = phase.to_string();
    state.detail = detail;
    state.updated_at = Utc::now().to_rfc3339();
    store_os_upgrade(pool, state).await;
}

/// Last chunk of a command's output, for progress/error surfacing.
fn output_tail(out: &std::process::Output) -> String {
    let text = if out.stderr.is_empty() {
        String::from_utf8_lossy(&out.stdout)
    } else {
        String::from_utf8_lossy(&out.stderr)
    };
    let trimmed = text.trim();
    match trimmed.char_indices().nth_back(499) {
        Some((idx, _)) => trimmed[idx..].to_string(),
        None => trimmed.to_string(),
    }
}

#[derive(Debug, Deserialize)]
pub struct OsUpgradeRequest {
    /// Bare target release, e.g. "15.1"
    pub target: String,
}

#[derive(Debug, Serialize)]
pub struct OsUpgradeStatus {
    /// FreeBSD userland release currently running, if detectable
    pub current_os: Option<String>,
    pub state: Option<OsUpgradeState>,
}

pub async fn os_upgrade_status(
    State(state): State<AppState>,
) -> Result<Json<OsUpgradeStatus>, StatusCode> {
    Ok(Json(OsUpgradeStatus {
        current_os: updater::current_os_release().await,
        state: load_os_upgrade(&state.pool).await,
    }))
}

pub async fn start_os_upgrade(
    State(state): State<AppState>,
    Json(req): Json<OsUpgradeRequest>,
) -> Result<Json<MessageResponse>, (StatusCode, String)> {
    let target = req.target.trim().to_string();
    // Same format the sudo helper enforces; reject early with a clear 400.
    let valid = {
        let mut parts = target.split('.');
        let maj = parts.next().and_then(|p| p.parse::<u32>().ok());
        let min = parts.next().and_then(|p| p.parse::<u32>().ok());
        maj.is_some() && min.is_some() && parts.next().is_none()
    };
    if !valid {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("target must be a bare release like \"15.1\", got \"{target}\""),
        ));
    }
    let current = updater::current_os_release().await.ok_or((
        StatusCode::BAD_REQUEST,
        "cannot determine the running FreeBSD release".to_string(),
    ))?;
    if updater::os_satisfies(&current, &target) {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("already on {current}; {target} is not newer"),
        ));
    }
    if let Some(existing) = load_os_upgrade(&state.pool).await
        && matches!(
            existing.phase.as_str(),
            "fetching" | "installing" | "finalizing"
        )
    {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "an OS upgrade to {} is already {} — wait for it to finish",
                existing.target, existing.phase
            ),
        ));
    }

    let now = Utc::now().to_rfc3339();
    let mut job = OsUpgradeState {
        target: target.clone(),
        phase: "fetching".to_string(),
        detail: format!("downloading FreeBSD {target} from {current}"),
        started_at: now.clone(),
        updated_at: now,
    };
    store_os_upgrade(&state.pool, &job).await;
    log_update(
        &state.pool,
        "os_upgrade",
        &format!("started: {current} → {target}"),
        "running",
    )
    .await;

    let pool = state.pool.clone();
    tokio::spawn(async move {
        // #641 pre-flight: stripped ISO installs are missing base files
        // that freebsd-update's component detection samples — without
        // them it decides world/base isn't installed and upgrades ONLY
        // the kernel, silently. Restore them from the running release's
        // own base.txz first. Markers cover the two biggest stripped
        // trees; the repair itself is idempotent.
        let base_stripped =
            !updater::missing_canaries(&["/rescue/sh", "/usr/share/man/man1/ls.1.gz"]).is_empty();
        if base_stripped {
            set_os_upgrade_phase(
                &pool,
                &mut job,
                "fetching",
                "restoring base system files stripped by the installer (one-time, ~160 MB)".into(),
            )
            .await;
            match aifw_core::sudo::freebsd_update_repair_base().await {
                Ok(o) if o.status.success() => {
                    log_update(&pool, "os_upgrade", "base repair complete", "running").await;
                }
                Ok(o) => {
                    let tail = output_tail(&o);
                    set_os_upgrade_phase(
                        &pool,
                        &mut job,
                        "failed",
                        format!("base repair failed: {tail}"),
                    )
                    .await;
                    log_update(
                        &pool,
                        "os_upgrade",
                        &format!("base repair failed: {tail}"),
                        "failed",
                    )
                    .await;
                    return;
                }
                Err(e) => {
                    set_os_upgrade_phase(
                        &pool,
                        &mut job,
                        "failed",
                        format!("base repair failed: {e}"),
                    )
                    .await;
                    log_update(
                        &pool,
                        "os_upgrade",
                        &format!("base repair failed: {e}"),
                        "failed",
                    )
                    .await;
                    return;
                }
            }
        }
        // #636: every upgrade run starts from a pristine state directory.
        // freebsd-update's state is its only memory and a stale or
        // corrupted one (a previous interrupted run, interleaved patch
        // operations) wedges the run in ways a general user can't escape.
        // Reset is always safe — the fetch below rebuilds everything.
        if let Ok(o) = aifw_core::sudo::freebsd_update_reset().await
            && !o.status.success()
        {
            tracing::warn!(
                "freebsd-update state reset failed (continuing): {}",
                String::from_utf8_lossy(&o.stderr).trim()
            );
        }
        // Phase 1: fetch + stage the release (the long part, minutes).
        match aifw_core::sudo::freebsd_update_upgrade(&job.target).await {
            Ok(o) if o.status.success() => {
                set_os_upgrade_phase(
                    &pool,
                    &mut job,
                    "installing",
                    "installing the new kernel".into(),
                )
                .await;
            }
            Ok(o) => {
                let tail = output_tail(&o);
                set_os_upgrade_phase(&pool, &mut job, "failed", format!("fetch failed: {tail}"))
                    .await;
                log_update(
                    &pool,
                    "os_upgrade",
                    &format!("fetch failed: {tail}"),
                    "failed",
                )
                .await;
                return;
            }
            Err(e) => {
                set_os_upgrade_phase(&pool, &mut job, "failed", format!("fetch failed: {e}")).await;
                log_update(&pool, "os_upgrade", &format!("fetch failed: {e}"), "failed").await;
                return;
            }
        }
        // Phase 2: first `install` pass writes the new kernel; the rest
        // waits for a reboot.
        match aifw_core::sudo::freebsd_update("install", &[]).await {
            Ok(o) if o.status.success() => {
                let detail = format!(
                    "kernel for {} installed — reboot to continue; the remaining install runs automatically after boot",
                    job.target
                );
                set_os_upgrade_phase(&pool, &mut job, "reboot_required", detail).await;
                log_update(
                    &pool,
                    "os_upgrade",
                    "kernel installed, reboot required",
                    "running",
                )
                .await;
            }
            Ok(o) => {
                let tail = output_tail(&o);
                set_os_upgrade_phase(
                    &pool,
                    &mut job,
                    "failed",
                    format!("kernel install failed: {tail}"),
                )
                .await;
                log_update(
                    &pool,
                    "os_upgrade",
                    &format!("kernel install failed: {tail}"),
                    "failed",
                )
                .await;
            }
            Err(e) => {
                set_os_upgrade_phase(
                    &pool,
                    &mut job,
                    "failed",
                    format!("kernel install failed: {e}"),
                )
                .await;
                log_update(
                    &pool,
                    "os_upgrade",
                    &format!("kernel install failed: {e}"),
                    "failed",
                )
                .await;
            }
        }
    });

    Ok(Json(MessageResponse {
        message: format!("OS upgrade to {target} started"),
    }))
}

/// Pick up an OS upgrade across restarts. Called once at aifw-api startup.
///
/// - After the mid-upgrade reboot (phase `reboot_required`, now running the
///   target release): run the remaining `freebsd-update install` passes and
///   mark the upgrade done.
/// - A phase of `fetching`/`installing` at startup means the process died
///   mid-run (crash, power loss): mark failed so the operator can retry.
pub async fn resume_os_upgrade(pool: SqlitePool) {
    let Some(mut job) = load_os_upgrade(&pool).await else {
        return;
    };
    match job.phase.as_str() {
        "reboot_required" => {
            // #628: gate on the RUNNING KERNEL, not the userland. After the
            // mid-upgrade reboot the kernel is on the target release while
            // the userland is still old — the userland only catches up when
            // the install passes below run, so a userland gate deadlocks
            // the flow at "reboot required" forever.
            let Some(kernel) = updater::running_kernel_release().await else {
                return;
            };
            if !updater::os_satisfies(&kernel, &job.target) {
                // Not rebooted into the new kernel yet — nothing to do.
                return;
            }
            set_os_upgrade_phase(
                &pool,
                &mut job,
                "finalizing",
                "installing the new userland".into(),
            )
            .await;
            tokio::spawn(async move {
                // freebsd-update needs up to three install passes after the
                // reboot (world, then old-library cleanup). It exits
                // non-zero with "No updates are available" once done.
                for pass in 1..=3u32 {
                    match aifw_core::sudo::freebsd_update("install", &[]).await {
                        Ok(o) if o.status.success() => {
                            tracing::info!(pass, "os upgrade: install pass complete");
                        }
                        Ok(o) => {
                            let tail = output_tail(&o);
                            if tail.contains("No updates are available") {
                                break;
                            }
                            set_os_upgrade_phase(
                                &pool,
                                &mut job,
                                "failed",
                                format!("post-reboot install failed: {tail}"),
                            )
                            .await;
                            log_update(
                                &pool,
                                "os_upgrade",
                                &format!("post-reboot install failed: {tail}"),
                                "failed",
                            )
                            .await;
                            return;
                        }
                        Err(e) => {
                            set_os_upgrade_phase(
                                &pool,
                                &mut job,
                                "failed",
                                format!("post-reboot install failed: {e}"),
                            )
                            .await;
                            log_update(
                                &pool,
                                "os_upgrade",
                                &format!("post-reboot install failed: {e}"),
                                "failed",
                            )
                            .await;
                            return;
                        }
                    }
                }
                // #632: done is VERIFIED, never inferred. "No updates are
                // available" with an old userland means the staged upgrade
                // data was lost (a patch-level fetch shares freebsd-update's
                // state dir, #633) — the appliance showed "Complete /
                // running FreeBSD 15.1" while actually still on 15.0.
                let userland_ok = match updater::current_os_release().await {
                    Some(u) => updater::os_satisfies(&u, &job.target),
                    None => false,
                };
                // #636: version alone can't see a mangled install that
                // deleted files — canary-check the essentials too.
                let missing = updater::missing_canaries(&updater::OS_CANARY_FILES);
                if userland_ok && !missing.is_empty() {
                    let detail = format!(
                        "upgrade left essential files damaged ({}) — use Retry to re-run the upgrade cleanly",
                        missing.join(", ")
                    );
                    set_os_upgrade_phase(&pool, &mut job, "failed", detail.clone()).await;
                    log_update(&pool, "os_upgrade", &detail, "failed").await;
                    return;
                }
                if userland_ok {
                    let done_detail = format!(
                        "running FreeBSD {} — AiFw updates are unblocked",
                        job.target
                    );
                    let done_log = format!("completed: now on {}", job.target);
                    set_os_upgrade_phase(&pool, &mut job, "done", done_detail).await;
                    log_update(&pool, "os_upgrade", &done_log, "completed").await;
                    // #624: drop the cached update info — the release that
                    // was OS-blocked before the upgrade is installable now,
                    // and the next page load should say so without the
                    // operator remembering to re-check.
                    save_config(&pool, "aifw_cached_info", "").await;
                } else {
                    let detail = format!(
                        "install passes ran but the userland is not on {} — the staged \
                         upgrade data was lost; run the upgrade again",
                        job.target
                    );
                    set_os_upgrade_phase(&pool, &mut job, "failed", detail.clone()).await;
                    log_update(&pool, "os_upgrade", &detail, "failed").await;
                }
            });
        }
        "fetching" | "installing" | "finalizing" => {
            let detail = format!(
                "interrupted during {} (service restarted mid-upgrade) — start the upgrade again to retry",
                job.phase
            );
            set_os_upgrade_phase(&pool, &mut job, "failed", detail.clone()).await;
            log_update(&pool, "os_upgrade", &detail, "failed").await;
        }
        "done" => {
            // #632: demote a recorded "done" that reality contradicts. An
            // appliance that hit the false-done bug carries phase=done with
            // an old userland; without this it can never retry from the UI.
            if let Some(u) = updater::current_os_release().await
                && !updater::os_satisfies(&u, &job.target)
            {
                let detail = format!(
                    "recorded as complete but the userland is {u}, not {} — the staged \
                     upgrade data was lost; run the upgrade again",
                    job.target
                );
                set_os_upgrade_phase(&pool, &mut job, "failed", detail.clone()).await;
                log_update(&pool, "os_upgrade", &detail, "failed").await;
            }
        }
        _ => {}
    }
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
            _ => "0", // sun or any other value
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
        // Always reflect the live toggle state, even if the cached check
        // predates a channel change.
        info.include_prereleases = prereleases_enabled(&state.pool).await;
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
        checksum_signature_url: None,
        has_backup: std::path::Path::new("/usr/local/share/aifw/backup/version").exists(),
        backup_version: tokio::fs::read_to_string("/usr/local/share/aifw/backup/version")
            .await
            .ok()
            .map(|v| v.trim().to_string()),
        restart_pending: updater::restart_pending().await,
        running_version: updater::running_version().to_string(),
        reboot_recommended: false,
        reboot_reason: None,
        include_prereleases: prereleases_enabled(&state.pool).await,
        required_os: None,
        os_upgrade_required: false,
        blocked_version: None,
        blocked_requires_os: None,
    }))
}

pub async fn aifw_check_update(
    State(state): State<AppState>,
) -> Result<Json<AifwUpdateInfo>, StatusCode> {
    let pre = prereleases_enabled(&state.pool).await;
    let info = updater::check_for_update(pre).await.map_err(|e| {
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
) -> Result<Json<UpdateInstallResponse>, (StatusCode, String)> {
    // Get cached update info
    let cached = sqlx::query_as::<_, (String,)>(
        "SELECT value FROM update_config WHERE key = 'aifw_cached_info'",
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten();

    let info = if let Some((json,)) = cached {
        serde_json::from_str::<AifwUpdateInfo>(&json)
            .map_err(|e| install_error("cached update info is corrupt", &e.to_string()))?
    } else {
        // No cached info, check now
        let pre = prereleases_enabled(&state.pool).await;
        updater::check_for_update(pre).await.map_err(|e| {
            tracing::error!("AiFw update check failed: {}", e);
            install_error("update check failed", &e.to_string())
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

    // OS dependency gate (#612): fail before downloading when the release
    // says it needs a newer FreeBSD. The tarball-level gate in the updater
    // still backstops releases without the notes stamp.
    if info.os_upgrade_required {
        let required = info.required_os.clone().unwrap_or_default();
        let current = updater::current_os_release()
            .await
            .unwrap_or_else(|| "unknown".to_string());
        return Err((
            StatusCode::PRECONDITION_FAILED,
            format!(
                "AiFw v{} requires FreeBSD {required} but this system runs {current}. \
                 Upgrade the OS first (System → Updates → Operating system), then install the AiFw update.",
                info.latest_version
            ),
        ));
    }

    let msg = updater::download_and_install(&info).await.map_err(|e| {
        tracing::error!("AiFw update install failed: {}", e);
        let pool = state.pool.clone();
        let err = e.to_string();
        tokio::spawn(async move {
            log_update(&pool, "aifw_install", &err, "failed").await;
        });
        install_error("update install failed", &e.to_string())
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
) -> Result<Json<UpdateInstallResponse>, (StatusCode, String)> {
    let msg = updater::rollback().await.map_err(|e| {
        tracing::error!("AiFw rollback failed: {}", e);
        install_error("rollback failed", &e.to_string())
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
        message: "System rebooting in 1 minute. Cancel with `shutdown -c` on the console."
            .to_string(),
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
) -> Result<Json<MessageResponse>, (StatusCode, String)> {
    let bad = |m: &str| (StatusCode::BAD_REQUEST, m.to_string());
    let oops = |m: &str| (StatusCode::INTERNAL_SERVER_ERROR, m.to_string());

    let tmp_dir = format!("/tmp/aifw-update-local-{}", std::process::id());
    if let Err(e) = tokio::fs::create_dir_all(&tmp_dir).await {
        tracing::warn!(?e, "failed to create tmp dir for local upload");
        return Err(oops("failed to create temp dir for upload"));
    }

    let mut tarball_path: Option<std::path::PathBuf> = None;
    let mut expected_hash: Option<String> = None;
    let mut auto_restart = false;

    while let Some(mut field) = multipart.next_field().await.map_err(|e| {
        tracing::warn!(?e, "multipart next_field error");
        bad("malformed multipart upload")
    })? {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "tarball" => {
                use tokio::io::AsyncWriteExt;
                let path = std::path::PathBuf::from(format!("{}/update.tar.xz", tmp_dir));
                let mut file = tokio::fs::File::create(&path)
                    .await
                    .map_err(|_| oops("failed to open temp file for upload"))?;
                while let Some(chunk) = field
                    .chunk()
                    .await
                    .map_err(|_| bad("upload stream error"))?
                {
                    file.write_all(&chunk)
                        .await
                        .map_err(|_| oops("failed to write uploaded tarball"))?;
                }
                if let Err(e) = file.flush().await {
                    tracing::warn!(?e, "failed to flush uploaded tarball to disk");
                }
                tarball_path = Some(path);
            }
            "sha256" => {
                let v = field
                    .text()
                    .await
                    .map_err(|_| bad("invalid sha256 field"))?;
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
                while field
                    .chunk()
                    .await
                    .map_err(|_| bad("upload stream error"))?
                    .is_some()
                {}
            }
        }
    }

    let path = tarball_path.ok_or_else(|| {
        tracing::warn!("install-local: no tarball field in multipart");
        bad("no tarball field in upload")
    })?;

    // Sanity-check size — refuse pathologically large uploads even if the
    // body-limit layer already capped them.
    let meta = tokio::fs::metadata(&path)
        .await
        .map_err(|_| oops("could not stat uploaded tarball"))?;
    if meta.len() > 500 * 1024 * 1024 {
        let _ = tokio::fs::remove_dir_all(&tmp_dir).await;
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            "tarball exceeds the 500 MB limit".to_string(),
        ));
    }

    let result = aifw_core::updater::install_from_path(&path, expected_hash.as_deref()).await;

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
            let _ = log_update(&state.pool, "install_local", &format!("{e}"), "error").await;
            tracing::warn!(?e, "install-local failed");
            // #504: surface the real reason (+ root-console hint) instead of 500.
            Err(install_error("update install failed", &e.to_string()))
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

#[cfg(test)]
mod install_error_tests {
    use super::{install_error, is_privilege_refusal};
    use axum::http::StatusCode;

    #[test]
    fn detects_sudo_refusal_signatures() {
        assert!(is_privilege_refusal(
            "tar extract failed: sudo: user aifw is not allowed to run aifw-sudo-tar"
        ));
        assert!(is_privilege_refusal("sudo: a password is required"));
        assert!(is_privilege_refusal("aifw-sudo-tar: Command not found"));
        assert!(is_privilege_refusal("open: Permission denied"));
    }

    #[test]
    fn ignores_unrelated_errors() {
        assert!(!is_privilege_refusal("Download failed: connection reset"));
        assert!(!is_privilege_refusal("Checksum verification failed"));
    }

    #[test]
    fn privilege_refusal_appends_console_hint() {
        let (code, body) = install_error(
            "update install failed",
            "tar extract failed: aifw is not allowed to run aifw-sudo-tar",
        );
        assert_eq!(code, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(body.contains("update install failed"));
        assert!(body.contains("aifw-sudo-tar")); // original detail preserved
        assert!(body.contains("console as root"));
        assert!(body.contains("aifw update install"));
    }

    #[test]
    fn plain_error_has_no_hint() {
        let (_, body) = install_error("update check failed", "connection reset");
        assert!(body.contains("connection reset"));
        assert!(!body.contains("console as root"));
    }
}
