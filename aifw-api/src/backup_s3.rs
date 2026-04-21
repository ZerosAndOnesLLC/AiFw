//! HTTP handlers for S3 backup sync + SMTP notifications.
//!
//! All the actual work lives in `aifw_core::s3_backup` and
//! `aifw_core::smtp_notify`. These handlers are thin shims that
//! unmask secrets for display, validate inputs, and return JSON.

use aifw_core::s3_backup as s3;
use aifw_core::smtp_notify as smtp;
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::AppState;

fn internal(e: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
}

// ============================================================================
// S3 — config
// ============================================================================

/// Response variant of [`s3::S3Config`] that masks the secret. The UI sends
/// `None` to leave unchanged, `Some("")` to clear, and the real secret only
/// when explicitly editing it.
#[derive(Serialize)]
pub struct S3ConfigResponse {
    pub enabled: bool,
    pub bucket: String,
    pub region: String,
    pub endpoint: Option<String>,
    pub prefix: String,
    pub path_style: bool,
    pub access_key_id: Option<String>,
    pub has_secret: bool,
}

impl From<s3::S3Config> for S3ConfigResponse {
    fn from(c: s3::S3Config) -> Self {
        S3ConfigResponse {
            enabled: c.enabled,
            bucket: c.bucket,
            region: c.region,
            endpoint: c.endpoint,
            prefix: c.prefix,
            path_style: c.path_style,
            access_key_id: c.access_key_id,
            has_secret: c.secret_access_key.is_some(),
        }
    }
}

pub async fn get_s3_config(State(state): State<AppState>) -> Json<S3ConfigResponse> {
    Json(s3::load(&state.pool).await.into())
}

pub async fn put_s3_config(
    State(state): State<AppState>,
    Json(cfg): Json<s3::S3Config>,
) -> Result<Json<S3ConfigResponse>, (StatusCode, String)> {
    if cfg.enabled && cfg.bucket.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "bucket is required when enabled".into(),
        ));
    }
    s3::save(&state.pool, &cfg)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(s3::load(&state.pool).await.into()))
}

pub async fn test_s3(
    State(state): State<AppState>,
    Json(req): Json<Option<s3::S3Config>>,
) -> Json<s3::TestResult> {
    // If the UI supplies a draft config (unsaved), test that. Otherwise test
    // the persisted config — lets you "Save & Test" in two clicks.
    let cfg = match req {
        Some(draft) if !draft.bucket.is_empty() => {
            // Merge secret from DB if UI sent empty (means "unchanged").
            let mut merged = draft;
            if merged.secret_access_key.is_none() {
                let existing = s3::load(&state.pool).await;
                merged.secret_access_key = existing.secret_access_key;
            }
            merged
        }
        _ => s3::load(&state.pool).await,
    };
    Json(s3::test_connection(&cfg).await)
}

// ============================================================================
// S3 — list / import
// ============================================================================

#[derive(Deserialize)]
pub struct ListQuery {
    pub max: Option<usize>,
}

pub async fn list_s3(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<ListQuery>,
) -> Result<Json<Vec<s3::RemoteObject>>, (StatusCode, String)> {
    let cfg = s3::load(&state.pool).await;
    if !cfg.enabled {
        return Err((StatusCode::BAD_REQUEST, "S3 backup is not enabled".into()));
    }
    let list = s3::list(&cfg, q.max.unwrap_or(500).min(5000))
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
    Ok(Json(list))
}

#[derive(Deserialize)]
pub struct ImportRequest {
    pub key: String,
    pub comment: Option<String>,
}

#[derive(Serialize)]
pub struct ImportResponse {
    pub version: i64,
    pub message: String,
}

/// Pull an archived config from S3 and save it as a new local version.
/// Does NOT apply it — the operator can then diff or restore via the
/// existing `/config/restore` endpoint.
pub async fn import_s3(
    State(state): State<AppState>,
    Json(req): Json<ImportRequest>,
) -> Result<Json<ImportResponse>, (StatusCode, String)> {
    let cfg = s3::load(&state.pool).await;
    if !cfg.enabled {
        return Err((StatusCode::BAD_REQUEST, "S3 backup is not enabled".into()));
    }
    let json = s3::fetch(&cfg, &req.key)
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, e))?;
    let fw_cfg: aifw_core::config::FirewallConfig = serde_json::from_str(&json).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            format!("not a valid config JSON: {e}"),
        )
    })?;

    let mgr = aifw_core::config_manager::ConfigManager::new(state.pool.clone());
    mgr.migrate().await.map_err(internal)?;
    let comment = req
        .comment
        .unwrap_or_else(|| format!("imported from s3://{}/{}", cfg.bucket, req.key));
    let version = mgr
        .save_version(&fw_cfg, "s3-import", Some(&comment))
        .await
        .map_err(internal)?;
    Ok(Json(ImportResponse {
        version,
        message: format!(
            "Imported as version {version}. Review via /backup then restore if desired."
        ),
    }))
}

// ============================================================================
// SMTP — config
// ============================================================================

#[derive(Serialize)]
pub struct SmtpConfigResponse {
    pub enabled: bool,
    pub host: String,
    pub port: u16,
    pub tls: String,
    pub username: Option<String>,
    pub has_password: bool,
    pub from_address: String,
    pub recipients: String,
    pub enabled_events: Vec<String>,
}

fn events_to_vec(mask: u32) -> Vec<String> {
    let all = [
        ("backup_saved", smtp::Event::BackupSaved),
        ("s3_upload_ok", smtp::Event::S3UploadOk),
        ("s3_upload_failed", smtp::Event::S3UploadFailed),
        ("restore_ok", smtp::Event::RestoreOk),
        ("restore_failed", smtp::Event::RestoreFailed),
        ("pruned", smtp::Event::Pruned),
        ("cert_renewed_ok", smtp::Event::CertRenewedOk),
        ("cert_renew_failed", smtp::Event::CertRenewFailed),
        ("cert_expiring_soon", smtp::Event::CertExpiringSoon),
    ];
    all.iter()
        .filter(|(_, ev)| {
            // bit() is crate-private — round-trip via enabled mask check:
            let mut c = smtp::SmtpConfig::default();
            c.enabled = true;
            c.enabled_events = mask;
            c.is_event_enabled(*ev)
        })
        .map(|(k, _)| k.to_string())
        .collect()
}

impl From<smtp::SmtpConfig> for SmtpConfigResponse {
    fn from(c: smtp::SmtpConfig) -> Self {
        SmtpConfigResponse {
            enabled: c.enabled,
            host: c.host,
            port: c.port,
            tls: match c.tls {
                smtp::TlsMode::None => "none",
                smtp::TlsMode::StartTls => "starttls",
                smtp::TlsMode::ImplicitTls => "implicit",
            }
            .into(),
            username: c.username,
            has_password: c.password.is_some(),
            from_address: c.from_address,
            recipients: c.recipients,
            enabled_events: events_to_vec(c.enabled_events),
        }
    }
}

pub async fn get_smtp_config(State(state): State<AppState>) -> Json<SmtpConfigResponse> {
    Json(smtp::load(&state.pool).await.into())
}

/// UI-friendly request body: `enabled_events` arrives as a string list
/// (matching the GET response shape) and we translate to the internal
/// bitmask here.
#[derive(Deserialize)]
pub struct SmtpConfigRequest {
    pub enabled: bool,
    #[serde(default)]
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default)]
    pub tls: String,
    pub username: Option<String>,
    pub password: Option<String>,
    #[serde(default)]
    pub from_address: String,
    #[serde(default)]
    pub recipients: String,
    #[serde(default)]
    pub enabled_events: Vec<String>,
}

fn default_port() -> u16 {
    587
}

fn tls_from_str(s: &str) -> smtp::TlsMode {
    match s.to_ascii_lowercase().as_str() {
        "none" => smtp::TlsMode::None,
        "implicit" | "tls" | "implicittls" => smtp::TlsMode::ImplicitTls,
        _ => smtp::TlsMode::StartTls,
    }
}

fn events_to_mask(events: &[String]) -> u32 {
    let mut mask = 0u32;
    for e in events {
        mask |= match e.as_str() {
            "backup_saved" => 1 << 0,
            "s3_upload_ok" => 1 << 1,
            "s3_upload_failed" => 1 << 2,
            "restore_ok" => 1 << 3,
            "restore_failed" => 1 << 4,
            "pruned" => 1 << 5,
            "cert_renewed_ok" => 1 << 6,
            "cert_renew_failed" => 1 << 7,
            "cert_expiring_soon" => 1 << 8,
            _ => 0,
        };
    }
    mask
}

fn request_to_smtp(req: SmtpConfigRequest) -> smtp::SmtpConfig {
    smtp::SmtpConfig {
        enabled: req.enabled,
        host: req.host,
        port: req.port,
        tls: tls_from_str(&req.tls),
        username: req.username,
        password: req.password,
        from_address: if req.from_address.is_empty() {
            "aifw@localhost".into()
        } else {
            req.from_address
        },
        recipients: req.recipients,
        enabled_events: events_to_mask(&req.enabled_events),
    }
}

pub async fn put_smtp_config(
    State(state): State<AppState>,
    Json(req): Json<SmtpConfigRequest>,
) -> Result<Json<SmtpConfigResponse>, (StatusCode, String)> {
    let cfg = request_to_smtp(req);
    if cfg.enabled {
        if cfg.host.trim().is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "host is required when enabled".into(),
            ));
        }
        if cfg.recipients.trim().is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                "at least one recipient is required".into(),
            ));
        }
    }
    smtp::save(&state.pool, &cfg)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(smtp::load(&state.pool).await.into()))
}

#[derive(Serialize)]
pub struct TestResponse {
    pub ok: bool,
    pub message: String,
}

pub async fn test_smtp(
    State(state): State<AppState>,
    Json(req): Json<Option<SmtpConfigRequest>>,
) -> Json<TestResponse> {
    let cfg = match req {
        Some(draft) if !draft.host.is_empty() => {
            let mut merged = request_to_smtp(draft);
            if merged.password.is_none() {
                let existing = smtp::load(&state.pool).await;
                merged.password = existing.password;
            }
            merged
        }
        _ => smtp::load(&state.pool).await,
    };
    match smtp::test_send(&cfg).await {
        Ok(_) => Json(TestResponse {
            ok: true,
            message: "test email sent".into(),
        }),
        Err(e) => Json(TestResponse {
            ok: false,
            message: e,
        }),
    }
}

// ============================================================================
// Unused-but-required path extractor stub so axum's route tooling compiles
// if/when we add a /restore-by-path variant. Keeping it out of public API.
// ============================================================================
#[allow(dead_code)]
pub(crate) async fn _path_noop(Path(_p): Path<String>) {}
