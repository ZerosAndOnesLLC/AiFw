//! Log-rotation settings API (#205) — thin shims over
//! `aifw_core::log_rotation`. Routes live in `router::settings_read` /
//! `settings_write` (Permission::SettingsRead / SettingsWrite).

use aifw_core::log_rotation as lr;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

use crate::AppState;

/// `GET /api/v1/settings/log-rotation` response.
#[derive(Serialize)]
pub struct LogRotationView {
    /// Stored policy.
    pub config: lr::LogRotationConfig,
    /// Per-log on-disk status.
    pub logs: Vec<lr::LogStatus>,
    /// Path of the rendered newsyslog fragment.
    pub conf_path: &'static str,
    /// Bounds for the UI form.
    pub limits: Limits,
}

/// Validation bounds mirrored from the core module.
#[derive(Serialize)]
pub struct Limits {
    pub min_size_mb: u32,
    pub max_size_mb: u32,
    pub max_keep: u32,
}

fn limits() -> Limits {
    Limits {
        min_size_mb: lr::MIN_SIZE_MB,
        max_size_mb: lr::MAX_SIZE_MB,
        max_keep: lr::MAX_KEEP,
    }
}

async fn view(state: &AppState) -> LogRotationView {
    LogRotationView {
        config: lr::load(&state.pool).await,
        logs: lr::status().await,
        conf_path: lr::CONF_PATH,
        limits: limits(),
    }
}

/// `GET /api/v1/settings/log-rotation` — policy + current log sizes.
pub async fn get_log_rotation(State(state): State<AppState>) -> Json<LogRotationView> {
    Json(view(&state).await)
}

/// `PUT /api/v1/settings/log-rotation` — validate, persist, regenerate the
/// newsyslog fragment and run one pass so an over-limit log rotates now
/// instead of at the next hourly cron tick.
pub async fn put_log_rotation(
    State(state): State<AppState>,
    Json(cfg): Json<lr::LogRotationConfig>,
) -> Result<Json<LogRotationView>, (StatusCode, String)> {
    cfg.validate().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    lr::save(&state.pool, &cfg)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if cfg!(target_os = "freebsd") {
        lr::write_conf(&cfg)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if let Err(e) = lr::run_now().await {
            // Config is saved and the fragment is on disk; cron will pick it
            // up. Surface the failure in the log rather than failing the save.
            tracing::warn!(error = %e, "log_rotation: immediate newsyslog pass failed");
        }
    }
    Ok(Json(view(&state).await))
}

/// Body for `POST /api/v1/settings/log-rotation/rotate`.
#[derive(Deserialize, Default)]
pub struct RotateRequest {
    /// Force-rotate just this managed log; omitted = run a normal pass over
    /// every managed log (rotates only those over their limit).
    #[serde(default)]
    pub path: Option<String>,
}

/// Result of a manual rotation.
#[derive(Serialize)]
pub struct RotateResponse {
    pub ok: bool,
    pub message: String,
    pub logs: Vec<lr::LogStatus>,
}

/// `POST /api/v1/settings/log-rotation/rotate` — rotate now.
pub async fn rotate_logs(
    State(_state): State<AppState>,
    body: Option<Json<RotateRequest>>,
) -> Result<Json<RotateResponse>, (StatusCode, String)> {
    let req = body.map(|Json(b)| b).unwrap_or_default();
    if !cfg!(target_os = "freebsd") {
        return Err((
            StatusCode::NOT_IMPLEMENTED,
            "log rotation is only available on the FreeBSD appliance".into(),
        ));
    }
    let result = match req.path.as_deref() {
        Some(p) => lr::rotate_now(p).await,
        None => lr::run_now().await,
    };
    match result {
        Ok(message) => Ok(Json(RotateResponse {
            ok: true,
            message,
            logs: lr::status().await,
        })),
        Err(aifw_core::CoreError::Validation(e)) => Err((StatusCode::BAD_REQUEST, e)),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string())),
    }
}
