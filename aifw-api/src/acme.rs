//! HTTP handlers for the ACME / Let's Encrypt subsystem.
//!
//! All real work lives in `aifw_core::acme*`. These handlers do CRUD over
//! the four tables, expose `issue/renew/publish/test` actions, and gate
//! private-key downloads behind `acme:write`.

use crate::AppState;
use aifw_core::acme::{
    self, AcmeCert, AcmeDnsProvider, AcmeExportTarget, ChallengeType, DnsProviderKind,
    ExportTargetKind, LE_PRODUCTION,
};
use aifw_core::{acme_dns, acme_engine, acme_export};
use axum::{extract::{Path, State}, http::{header, StatusCode}, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};

fn bad(e: impl std::fmt::Display) -> (StatusCode, String) { (StatusCode::BAD_REQUEST, e.to_string()) }
fn server(e: impl std::fmt::Display) -> (StatusCode, String) { (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()) }

// =============================================================================
// Account
// =============================================================================

#[derive(Serialize)]
pub struct AccountResponse {
    pub id: Option<i64>,
    pub directory_url: String,
    pub contact_email: String,
    pub registered: bool,
}

pub async fn get_account(State(state): State<AppState>) -> Json<AccountResponse> {
    match acme::load_default_account(&state.pool).await {
        Some(a) => Json(AccountResponse {
            id: Some(a.id),
            directory_url: a.directory_url,
            contact_email: a.contact_email,
            registered: a.key_pem.is_some(),
        }),
        None => Json(AccountResponse {
            id: None,
            directory_url: LE_PRODUCTION.into(),
            contact_email: String::new(),
            registered: false,
        }),
    }
}

#[derive(Deserialize)]
pub struct PutAccountRequest {
    pub directory_url: Option<String>,
    pub contact_email: String,
}

pub async fn put_account(
    State(state): State<AppState>,
    Json(req): Json<PutAccountRequest>,
) -> Result<Json<AccountResponse>, (StatusCode, String)> {
    let dir = req.directory_url.unwrap_or_else(|| LE_PRODUCTION.into());
    if !req.contact_email.contains('@') {
        return Err(bad("contact_email must be a valid email address"));
    }
    // Save row WITHOUT ACME-side registration — that happens lazily on
    // the first cert issue. Lets the operator configure the account
    // before they know which cert they want.
    acme::save_account(&state.pool, &dir, &req.contact_email, None)
        .await.map_err(server)?;
    Ok(get_account(State(state)).await)
}

// =============================================================================
// Certs
// =============================================================================

#[derive(Serialize)]
pub struct CertSummary {
    pub id: i64,
    pub common_name: String,
    pub sans: Vec<String>,
    pub challenge_type: String,
    pub dns_provider_id: Option<i64>,
    pub status: String,
    pub auto_renew: bool,
    pub renew_days_before_expiry: i32,
    pub issued_at: Option<String>,
    pub expires_at: Option<String>,
    pub days_until_expiry: Option<i64>,
    pub last_renew_attempt: Option<String>,
    pub last_renew_error: Option<String>,
    pub has_cert: bool,
}

impl From<AcmeCert> for CertSummary {
    fn from(c: AcmeCert) -> Self {
        let days = c.days_until_expiry();
        CertSummary {
            id: c.id,
            common_name: c.common_name,
            sans: c.sans,
            challenge_type: c.challenge_type.as_str().into(),
            dns_provider_id: c.dns_provider_id,
            status: c.status.as_str().into(),
            auto_renew: c.auto_renew,
            renew_days_before_expiry: c.renew_days_before_expiry,
            issued_at: c.issued_at.map(|t| t.to_rfc3339()),
            expires_at: c.expires_at.map(|t| t.to_rfc3339()),
            days_until_expiry: days,
            last_renew_attempt: c.last_renew_attempt.map(|t| t.to_rfc3339()),
            last_renew_error: c.last_renew_error,
            has_cert: c.cert_pem.is_some(),
        }
    }
}

pub async fn list_certs(State(state): State<AppState>) -> Json<Vec<CertSummary>> {
    Json(acme::load_all_certs(&state.pool).await.into_iter().map(Into::into).collect())
}

pub async fn get_cert(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<CertSummary>, (StatusCode, String)> {
    let c = acme::load_cert(&state.pool, id).await
        .ok_or_else(|| (StatusCode::NOT_FOUND, "not found".into()))?;
    Ok(Json(c.into()))
}

#[derive(Deserialize)]
pub struct NewCertRequest {
    pub common_name: String,
    #[serde(default)]
    pub sans: Vec<String>,
    #[serde(default = "default_challenge")]
    pub challenge_type: String,
    pub dns_provider_id: Option<i64>,
    #[serde(default = "default_true")]
    pub auto_renew: bool,
    #[serde(default = "default_renew_days")]
    pub renew_days_before_expiry: i32,
}

fn default_challenge() -> String { "dns-01".into() }
fn default_true() -> bool { true }
fn default_renew_days() -> i32 { 30 }

pub async fn create_cert(
    State(state): State<AppState>,
    Json(req): Json<NewCertRequest>,
) -> Result<Json<CertSummary>, (StatusCode, String)> {
    acme::validate_dns_name(&req.common_name).map_err(bad)?;
    for s in &req.sans { acme::validate_dns_name(s).map_err(bad)?; }
    let challenge = ChallengeType::from_str(&req.challenge_type);
    if challenge == ChallengeType::Dns01 && req.dns_provider_id.is_none() {
        return Err(bad("dns_provider_id required for DNS-01 certs"));
    }

    let sans_json = serde_json::to_string(&req.sans).map_err(server)?;
    let res = sqlx::query(r#"
        INSERT INTO acme_cert
            (common_name, sans, challenge_type, dns_provider_id,
             auto_renew, renew_days_before_expiry, status)
        VALUES (?, ?, ?, ?, ?, ?, 'pending')
    "#)
    .bind(&req.common_name)
    .bind(&sans_json)
    .bind(challenge.as_str())
    .bind(req.dns_provider_id)
    .bind(req.auto_renew as i64)
    .bind(req.renew_days_before_expiry as i64)
    .execute(&state.pool).await.map_err(server)?;
    let id = res.last_insert_rowid();

    let cert = acme::load_cert(&state.pool, id).await
        .ok_or_else(|| server("post-insert read failed"))?;
    Ok(Json(cert.into()))
}

pub async fn delete_cert(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
    sqlx::query("DELETE FROM acme_cert WHERE id = ?").bind(id)
        .execute(&state.pool).await.map_err(server)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
pub struct IssueResponse {
    pub ok: bool,
    pub message: String,
    pub expires_at: Option<String>,
}

pub async fn renew_now(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Json<IssueResponse> {
    let outcome = acme_engine::issue(&state.pool, id).await;
    Json(IssueResponse {
        ok: outcome.ok,
        message: outcome.message,
        expires_at: outcome.expires_at.map(|t| t.to_rfc3339()),
    })
}

pub async fn publish_now(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Json<IssueResponse> {
    acme_export::publish_all(&state.pool, id).await;
    Json(IssueResponse { ok: true, message: "publish ran; check per-target status".into(), expires_at: None })
}

pub async fn download_cert_pem(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let c = acme::load_cert(&state.pool, id).await
        .ok_or_else(|| (StatusCode::NOT_FOUND, "not found".into()))?;
    let body = format!("{}\n{}", c.cert_pem.unwrap_or_default(), c.chain_pem.unwrap_or_default());
    let disp = format!("attachment; filename=\"{}.pem\"", c.common_name);
    let mut resp = body.into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, "application/x-pem-file".parse().unwrap());
    h.insert(header::CONTENT_DISPOSITION, disp.parse().unwrap());
    Ok(resp)
}

pub async fn download_key_pem(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let c = acme::load_cert(&state.pool, id).await
        .ok_or_else(|| (StatusCode::NOT_FOUND, "not found".into()))?;
    let body = c.key_pem.unwrap_or_default();
    let disp = format!("attachment; filename=\"{}.key\"", c.common_name);
    let mut resp = body.into_response();
    let h = resp.headers_mut();
    h.insert(header::CONTENT_TYPE, "application/x-pem-file".parse().unwrap());
    h.insert(header::CONTENT_DISPOSITION, disp.parse().unwrap());
    Ok(resp)
}

// =============================================================================
// DNS Providers
// =============================================================================

#[derive(Serialize)]
pub struct DnsProviderResponse {
    pub id: i64,
    pub name: String,
    pub kind: String,
    pub zone: String,
    pub has_token: bool,
    pub has_secret: bool,
    pub extra: serde_json::Value,
}

impl From<AcmeDnsProvider> for DnsProviderResponse {
    fn from(p: AcmeDnsProvider) -> Self {
        DnsProviderResponse {
            id: p.id,
            name: p.name,
            kind: p.kind.as_str().into(),
            zone: p.zone,
            has_token: p.api_token.is_some(),
            has_secret: p.aws_secret_key.is_some(),
            extra: p.extra,
        }
    }
}

pub async fn list_providers(State(state): State<AppState>) -> Json<Vec<DnsProviderResponse>> {
    Json(acme::load_all_providers(&state.pool).await.into_iter().map(Into::into).collect())
}

#[derive(Deserialize)]
pub struct PutProviderRequest {
    pub name: String,
    pub kind: String,
    pub zone: String,
    pub api_token: Option<String>,
    pub aws_secret_key: Option<String>,
    #[serde(default)]
    pub extra: serde_json::Value,
}

pub async fn create_provider(
    State(state): State<AppState>,
    Json(req): Json<PutProviderRequest>,
) -> Result<Json<DnsProviderResponse>, (StatusCode, String)> {
    DnsProviderKind::from_str(&req.kind).ok_or_else(|| bad("invalid kind"))?;
    if req.name.trim().is_empty() { return Err(bad("name required")); }
    let extra_str = serde_json::to_string(&req.extra).map_err(server)?;
    let res = sqlx::query(r#"
        INSERT INTO acme_dns_provider (name, kind, api_token, aws_secret_key, zone, extra)
        VALUES (?, ?, ?, ?, ?, ?)
    "#)
    .bind(&req.name).bind(&req.kind)
    .bind(&req.api_token).bind(&req.aws_secret_key)
    .bind(&req.zone).bind(&extra_str)
    .execute(&state.pool).await.map_err(|e| (StatusCode::CONFLICT, e.to_string()))?;
    let id = res.last_insert_rowid();
    Ok(Json(acme::load_provider(&state.pool, id).await.unwrap().into()))
}

pub async fn update_provider(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<PutProviderRequest>,
) -> Result<Json<DnsProviderResponse>, (StatusCode, String)> {
    let existing = acme::load_provider(&state.pool, id).await
        .ok_or_else(|| (StatusCode::NOT_FOUND, "not found".into()))?;
    DnsProviderKind::from_str(&req.kind).ok_or_else(|| bad("invalid kind"))?;
    // None / empty-string secret semantics same as s3_backup / smtp_notify.
    let api_token = match req.api_token.as_deref() {
        None => existing.api_token,
        Some("") => None,
        Some(v) => Some(v.to_string()),
    };
    let aws_secret = match req.aws_secret_key.as_deref() {
        None => existing.aws_secret_key,
        Some("") => None,
        Some(v) => Some(v.to_string()),
    };
    let extra_str = serde_json::to_string(&req.extra).map_err(server)?;
    sqlx::query(r#"
        UPDATE acme_dns_provider
           SET name = ?, kind = ?, api_token = ?, aws_secret_key = ?, zone = ?, extra = ?
         WHERE id = ?
    "#)
    .bind(&req.name).bind(&req.kind)
    .bind(&api_token).bind(&aws_secret)
    .bind(&req.zone).bind(&extra_str)
    .bind(id)
    .execute(&state.pool).await.map_err(server)?;
    Ok(Json(acme::load_provider(&state.pool, id).await.unwrap().into()))
}

pub async fn delete_provider(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
    sqlx::query("DELETE FROM acme_dns_provider WHERE id = ?").bind(id)
        .execute(&state.pool).await.map_err(server)?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
pub struct ProviderTestResponse { pub ok: bool, pub message: String }

pub async fn test_provider(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Json<ProviderTestResponse> {
    let Some(p) = acme::load_provider(&state.pool, id).await else {
        return Json(ProviderTestResponse { ok: false, message: "not found".into() });
    };
    let solver = match acme_dns::build_solver(&p) {
        Ok(s) => s,
        Err(e) => return Json(ProviderTestResponse { ok: false, message: e }),
    };
    // Add+remove a synthetic TXT to prove credentials + perms.
    let test_fqdn = format!("_acme-aifw-test.{}", p.zone.trim_end_matches('.'));
    let test_value = format!("aifw-test-{}", chrono::Utc::now().timestamp());
    if let Err(e) = solver.add_txt(&test_fqdn, &test_value).await {
        return Json(ProviderTestResponse { ok: false, message: format!("add_txt: {e}") });
    }
    if let Err(e) = solver.remove_txt(&test_fqdn, &test_value).await {
        return Json(ProviderTestResponse { ok: false, message: format!("add ok, remove failed: {e}") });
    }
    Json(ProviderTestResponse { ok: true, message: "TXT add+remove OK".into() })
}

// =============================================================================
// Export targets
// =============================================================================

#[derive(Serialize)]
pub struct ExportTargetResponse {
    pub id: i64,
    pub cert_id: i64,
    pub kind: String,
    pub config: serde_json::Value,
    pub last_run_at: Option<String>,
    pub last_run_ok: bool,
    pub last_run_error: Option<String>,
}

impl From<AcmeExportTarget> for ExportTargetResponse {
    fn from(t: AcmeExportTarget) -> Self {
        ExportTargetResponse {
            id: t.id, cert_id: t.cert_id,
            kind: t.kind.as_str().into(),
            config: t.config,
            last_run_at: t.last_run_at.map(|x| x.to_rfc3339()),
            last_run_ok: t.last_run_ok,
            last_run_error: t.last_run_error,
        }
    }
}

pub async fn list_targets(
    State(state): State<AppState>,
    Path(cert_id): Path<i64>,
) -> Json<Vec<ExportTargetResponse>> {
    Json(acme::load_targets_for_cert(&state.pool, cert_id).await.into_iter().map(Into::into).collect())
}

#[derive(Deserialize)]
pub struct PutTargetRequest {
    pub kind: String,
    #[serde(default)]
    pub config: serde_json::Value,
}

pub async fn create_target(
    State(state): State<AppState>,
    Path(cert_id): Path<i64>,
    Json(req): Json<PutTargetRequest>,
) -> Result<Json<ExportTargetResponse>, (StatusCode, String)> {
    ExportTargetKind::from_str(&req.kind).ok_or_else(|| bad("invalid kind"))?;
    let cfg_str = serde_json::to_string(&req.config).map_err(server)?;
    let res = sqlx::query(r#"
        INSERT INTO acme_export_target (cert_id, kind, config) VALUES (?, ?, ?)
    "#)
    .bind(cert_id).bind(&req.kind).bind(&cfg_str)
    .execute(&state.pool).await.map_err(server)?;
    let id = res.last_insert_rowid();
    let t = acme::load_targets_for_cert(&state.pool, cert_id).await
        .into_iter().find(|t| t.id == id)
        .ok_or_else(|| server("post-insert read failed"))?;
    Ok(Json(t.into()))
}

pub async fn delete_target(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
    sqlx::query("DELETE FROM acme_export_target WHERE id = ?").bind(id)
        .execute(&state.pool).await.map_err(server)?;
    Ok(StatusCode::NO_CONTENT)
}
