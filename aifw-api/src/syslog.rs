//! Remote syslog settings API — thin shims over `aifw_common::syslog`.
//!
//! Routes are registered in `router::settings_read` / `router::settings_write`,
//! which enforce `Permission::SettingsRead` / `SettingsWrite`.

use aifw_common::syslog as sys;
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::Serialize;

use crate::AppState;

/// `GET /api/v1/settings/syslog` — current remote syslog configuration.
pub async fn get_syslog_config(State(state): State<AppState>) -> Json<sys::SyslogConfig> {
    Json(sys::load(&state.pool).await)
}

/// `PUT /api/v1/settings/syslog` — validate, persist, and apply immediately
/// in this process. aifw-daemon and aifw-ids pick the change up via their
/// 60s config pollers.
pub async fn put_syslog_config(
    State(state): State<AppState>,
    Json(cfg): Json<sys::SyslogConfig>,
) -> Result<Json<sys::SyslogConfig>, (StatusCode, String)> {
    cfg.validate().map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    sys::save(&state.pool, &cfg)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    state.syslog.apply(cfg.clone());
    // Reconcile pflogd with disable_local right away (best-effort; the
    // daemon also reconciles on its 60s poll). Off the request path.
    tokio::spawn(async move {
        aifw_core::local_log::apply_local_log_policy(&cfg).await;
    });
    Ok(Json(sys::load(&state.pool).await))
}

/// Result of a one-shot test delivery.
#[derive(Serialize)]
pub struct TestResponse {
    ok: bool,
    message: String,
}

/// `POST /api/v1/settings/syslog/test` — send one test message. An unsaved
/// draft config in the body wins over the stored one so the UI can test
/// before saving; with no body, an empty body, or JSON `null` the saved
/// config is used (the outer `Option` absorbs the missing-body rejection).
pub async fn test_syslog(
    State(state): State<AppState>,
    body: Option<Json<Option<sys::SyslogConfig>>>,
) -> Json<TestResponse> {
    let cfg = match body.and_then(|Json(b)| b) {
        Some(c) if !c.host.trim().is_empty() => c,
        _ => sys::load(&state.pool).await,
    };
    match sys::test_send(&cfg, "AiFw remote syslog test message").await {
        Ok(()) => Json(TestResponse {
            ok: true,
            message: format!(
                "test message sent to {}:{} over {}",
                cfg.host,
                cfg.port,
                cfg.transport.as_str()
            ),
        }),
        Err(e) => Json(TestResponse {
            ok: false,
            message: e.to_string(),
        }),
    }
}

/// `GET /api/v1/settings/syslog/status` — delivery counters per AiFw
/// process. Rows for aifw-daemon / aifw-ids come from the `syslog_stats`
/// table (refreshed by their 60s pollers); the API process's row is its
/// live in-memory snapshot.
pub async fn syslog_status(State(state): State<AppState>) -> Json<Vec<sys::ProcessSyslogStats>> {
    let mut rows = sys::read_stats(&state.pool).await.unwrap_or_else(|e| {
        tracing::warn!(error = %e, "failed to read persisted syslog stats");
        Vec::new()
    });
    rows.retain(|r| r.process != "aifw-api");
    rows.push(sys::ProcessSyslogStats::from_snapshot(
        "aifw-api",
        &state.syslog.stats(),
    ));
    rows.sort_by(|a, b| a.process.cmp(&b.process));
    Json(rows)
}
