use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::sse::{Event, KeepAlive, Sse},
};
use std::convert::Infallible;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use aifw_common::{
    Action, Address, CountryCode, Direction, GeoIpAction, GeoIpRule, GeoIpRuleStatus, Interface,
    IpsecMode, IpsecProtocol, IpsecSa, NatRedirect, NatRule, NatStatus, NatType, PortRange,
    Protocol, Rule, RuleMatch, RuleStatus, StateTracking, WgPeer, WgTunnel,
};
use crate::AppState;
use crate::auth;

// --- Request / Response types ---

#[derive(Debug, Deserialize)]
pub struct CreateRuleRequest {
    pub action: String,
    pub direction: String,
    pub protocol: String,
    pub src_addr: Option<String>,
    pub src_port_start: Option<u16>,
    pub src_port_end: Option<u16>,
    pub dst_addr: Option<String>,
    pub dst_port_start: Option<u16>,
    pub dst_port_end: Option<u16>,
    pub interface: Option<String>,
    pub priority: Option<i32>,
    pub log: Option<bool>,
    pub quick: Option<bool>,
    pub label: Option<String>,
    pub state_tracking: Option<String>,
    pub status: Option<String>,
    pub schedule_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct CreateNatRuleRequest {
    pub nat_type: String,
    pub interface: String,
    pub protocol: String,
    pub src_addr: Option<String>,
    pub src_port_start: Option<u16>,
    pub src_port_end: Option<u16>,
    pub dst_addr: Option<String>,
    pub dst_port_start: Option<u16>,
    pub dst_port_end: Option<u16>,
    pub redirect_addr: String,
    pub redirect_port_start: Option<u16>,
    pub redirect_port_end: Option<u16>,
    pub label: Option<String>,
    pub status: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct DnsConfigRequest {
    pub servers: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DnsConfigResponse {
    pub servers: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct StaticRoute {
    pub id: String,
    pub destination: String,
    pub gateway: String,
    pub interface: Option<String>,
    pub metric: i32,
    pub enabled: bool,
    pub description: Option<String>,
    pub created_at: String,
    #[serde(default)]
    pub fib: u32,
}

#[derive(Debug, Deserialize)]
pub struct CreateRouteRequest {
    pub destination: String,
    pub gateway: String,
    pub interface: Option<String>,
    pub metric: Option<i32>,
    pub enabled: Option<bool>,
    pub description: Option<String>,
    #[serde(default)]
    pub fib: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub status: String,
    pub mac: Option<String>,
    pub role: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SystemRoute {
    pub destination: String,
    pub gateway: String,
    pub flags: String,
    pub interface: String,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub data: T,
}

#[derive(Debug, Serialize)]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub pf_running: bool,
    pub pf_states: u64,
    pub pf_rules: u64,
    pub aifw_rules: usize,
    pub aifw_active_rules: usize,
    pub nat_rules: usize,
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Debug, Serialize)]
pub struct MetricsResponse {
    pub pf_running: bool,
    pub pf_states_count: u64,
    pub pf_rules_count: u64,
    pub pf_packets_in: u64,
    pub pf_packets_out: u64,
    pub pf_bytes_in: u64,
    pub pf_bytes_out: u64,
    pub aifw_rules_total: usize,
    pub aifw_rules_active: usize,
    pub aifw_nat_rules_total: usize,
}

fn port_range(start: Option<u16>, end: Option<u16>) -> Option<PortRange> {
    match (start, end) {
        (Some(s), Some(e)) => Some(PortRange { start: s, end: e }),
        (Some(s), None) => Some(PortRange { start: s, end: s }),
        _ => None,
    }
}

fn bad_request() -> StatusCode {
    StatusCode::BAD_REQUEST
}

fn internal() -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}

// --- Auth endpoints ---

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<auth::LoginRequest>,
) -> Result<Json<auth::LoginResponse>, StatusCode> {
    // Rate limit by IP (X-Forwarded-For behind ALB, fall back to username)
    let client_ip = headers.get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .unwrap_or(&req.username)
        .trim()
        .to_string();

    if state.login_limiter.is_blocked(&client_ip).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let user = auth::get_user_by_username(&state.pool, &req.username).await?;

    // Always run Argon2 to prevent timing-based user enumeration
    let password_valid = if let Some(ref u) = user {
        auth::verify_password(&req.password, &u.password_hash)
    } else {
        let _ = auth::verify_password(&req.password, auth::password::dummy_hash());
        false
    };

    let user = user.ok_or(StatusCode::UNAUTHORIZED)?;

    if !user.enabled {
        auth::log_user_audit(&state.pool, &user.id.to_string(), Some(&user.id.to_string()), "login_denied_disabled", Some(&req.username)).await;
        return Err(StatusCode::UNAUTHORIZED);
    }

    if !password_valid {
        auth::log_user_audit(&state.pool, &user.id.to_string(), Some(&user.id.to_string()), "login_failed", Some(&req.username)).await;
        state.login_limiter.record_failure(&client_ip).await;
        return Err(StatusCode::UNAUTHORIZED);
    }

    state.login_limiter.clear(&client_ip).await;

    // Check if TOTP is required
    if user.totp_enabled {
        return Ok(Json(auth::LoginResponse {
            tokens: None,
            totp_required: true,
        }));
    }

    // Check if TOTP enforcement is on but user hasn't set it up
    if state.auth_settings.require_totp && !user.totp_enabled {
        return Ok(Json(auth::LoginResponse {
            tokens: None,
            totp_required: true,
        }));
    }

    // Resolve permissions for the JWT
    let (perm_bits, role_name) = auth::tokens::resolve_token_permissions(
        &state.pool, &user.role, user.role_id.as_deref()
    ).await.map_err(|_| internal())?;

    let tokens = auth::tokens::issue_token_pair(
        &state.pool,
        &user.id.to_string(),
        &user.username,
        perm_bits,
        &role_name,
        &state.auth_settings,
    )
    .await
    .map_err(|_| internal())?;

    auth::log_user_audit(&state.pool, &user.id.to_string(), Some(&user.id.to_string()), "login_success", Some(&user.username)).await;

    Ok(Json(auth::LoginResponse {
        tokens: Some(tokens),
        totp_required: false,
    }))
}

pub async fn totp_login(
    State(state): State<AppState>,
    Json(req): Json<auth::totp::TotpLoginRequest>,
) -> Result<Json<auth::TokenPair>, StatusCode> {
    let user = auth::get_user_by_username(&state.pool, &req.username)
        .await?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !user.enabled {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Verify password first — TOTP is second factor, not replacement
    if !auth::verify_password(&req.password, &user.password_hash) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Verify TOTP code or recovery code
    let totp_valid = if let Some(ref secret) = user.totp_secret {
        auth::totp::verify(secret, &req.totp_code)
    } else {
        false
    };

    let recovery_valid = if !totp_valid {
        auth::use_recovery_code(&state.pool, &user.id.to_string(), &req.totp_code).await
    } else {
        false
    };

    if !totp_valid && !recovery_valid {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Resolve permissions for the JWT
    let (perm_bits, role_name) = auth::tokens::resolve_token_permissions(
        &state.pool, &user.role, user.role_id.as_deref()
    ).await.map_err(|_| internal())?;

    let tokens = auth::tokens::issue_token_pair(
        &state.pool,
        &user.id.to_string(),
        &user.username,
        perm_bits,
        &role_name,
        &state.auth_settings,
    )
    .await
    .map_err(|_| internal())?;

    Ok(Json(tokens))
}

pub async fn refresh_token(
    State(state): State<AppState>,
    Json(req): Json<auth::tokens::RefreshRequest>,
) -> Result<Json<auth::TokenPair>, StatusCode> {
    let tokens = auth::tokens::rotate_refresh_token(
        &state.pool,
        &req.refresh_token,
        &state.auth_settings,
    )
    .await
    .map_err(|_| StatusCode::UNAUTHORIZED)?;

    Ok(Json(tokens))
}

pub async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<auth::tokens::LogoutRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    // Revoke the refresh token
    auth::tokens::revoke_refresh_token(&state.pool, &req.refresh_token)
        .await
        .map_err(|_| bad_request())?;
    // Also revoke the current access token if present
    if let Some(auth_header) = headers.get("authorization").and_then(|v| v.to_str().ok())
        && let Some(token) = auth_header.strip_prefix("Bearer ")
            && let Ok(data) = auth::verify_access_token(token, &state.auth_settings) {
                let exp = chrono::DateTime::from_timestamp(data.claims.exp, 0)
                    .map(|d| d.to_rfc3339())
                    .unwrap_or_default();
                let _ = auth::revoke_access_token(&state.pool, &data.claims.jti, &exp).await;
            }
    Ok(Json(MessageResponse { message: "Logged out".to_string() }))
}

pub async fn totp_setup(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<auth::totp::TotpSetupResponse>, StatusCode> {
    let user_id = extract_user_id(&headers, &state)?;
    let user = auth::get_user_by_id(&state.pool, &user_id)
        .await?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let secret = auth::totp::generate_secret();
    let uri = auth::totp::provisioning_uri(&secret, &user.username, "AiFw");
    let recovery_codes = auth::totp::generate_recovery_codes(8);

    // Save secret (not yet enabled — needs verification)
    auth::save_totp_secret(&state.pool, &user_id, &secret).await?;
    auth::save_recovery_codes(&state.pool, &user_id, &recovery_codes).await?;

    Ok(Json(auth::totp::TotpSetupResponse {
        secret,
        provisioning_uri: uri,
        recovery_codes,
    }))
}

pub async fn totp_verify(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<auth::totp::TotpVerifyRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let user_id = extract_user_id(&headers, &state)?;
    let user = auth::get_user_by_id(&state.pool, &user_id)
        .await?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let secret = user.totp_secret.ok_or(bad_request())?;
    if !auth::totp::verify(&secret, &req.code) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    auth::enable_totp(&state.pool, &user_id).await?;
    Ok(Json(MessageResponse { message: "TOTP enabled".to_string() }))
}

pub async fn totp_disable(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<auth::totp::TotpDisableRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let user_id = extract_user_id(&headers, &state)?;
    let user = auth::get_user_by_id(&state.pool, &user_id)
        .await?
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let secret = user.totp_secret.ok_or(bad_request())?;
    if !auth::totp::verify(&secret, &req.code) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    auth::disable_totp(&state.pool, &user_id).await?;
    Ok(Json(MessageResponse { message: "TOTP disabled".to_string() }))
}

pub async fn get_auth_settings(
    State(state): State<AppState>,
) -> Result<Json<auth::AuthSettings>, StatusCode> {
    Ok(Json(state.auth_settings.clone()))
}

pub async fn update_auth_settings(
    State(state): State<AppState>,
    Json(req): Json<auth::config::UpdateAuthSettingsRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    if let Some(v) = req.access_token_expiry_mins {
        auth::config::AuthSettings::save_setting(&state.pool, "access_token_expiry_mins", &v.to_string()).await.map_err(|_| internal())?;
    }
    if let Some(v) = req.refresh_token_expiry_days {
        auth::config::AuthSettings::save_setting(&state.pool, "refresh_token_expiry_days", &v.to_string()).await.map_err(|_| internal())?;
    }
    if let Some(v) = req.require_totp {
        auth::config::AuthSettings::save_setting(&state.pool, "require_totp", &v.to_string()).await.map_err(|_| internal())?;
    }
    if let Some(v) = req.require_totp_for_oauth {
        auth::config::AuthSettings::save_setting(&state.pool, "require_totp_for_oauth", &v.to_string()).await.map_err(|_| internal())?;
    }
    if let Some(v) = req.auto_create_oauth_users {
        auth::config::AuthSettings::save_setting(&state.pool, "auto_create_oauth_users", &v.to_string()).await.map_err(|_| internal())?;
    }
    if let Some(v) = req.max_login_attempts {
        auth::config::AuthSettings::save_setting(&state.pool, "max_login_attempts", &v.to_string()).await.map_err(|_| internal())?;
    }
    if let Some(v) = req.lockout_duration_secs {
        auth::config::AuthSettings::save_setting(&state.pool, "lockout_duration_secs", &v.to_string()).await.map_err(|_| internal())?;
    }
    if let Some(v) = req.allow_registration {
        auth::config::AuthSettings::save_setting(&state.pool, "allow_registration", &v.to_string()).await.map_err(|_| internal())?;
    }
    if let Some(v) = req.password_min_length {
        auth::config::AuthSettings::save_setting(&state.pool, "password_min_length", &v.to_string()).await.map_err(|_| internal())?;
    }
    Ok(Json(MessageResponse { message: "Settings updated".to_string() }))
}

pub async fn list_oauth_providers(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<auth::oauth::OAuthProvider>>>, StatusCode> {
    let providers = auth::oauth::list_providers(&state.pool).await.map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: providers }))
}

pub async fn create_oauth_provider(
    State(state): State<AppState>,
    Json(req): Json<auth::oauth::CreateProviderRequest>,
) -> Result<(StatusCode, Json<ApiResponse<auth::oauth::OAuthProvider>>), StatusCode> {
    let provider = match req.provider_type.as_str() {
        "google" => auth::oauth::OAuthProvider::google(&req.client_id, &req.client_secret),
        "github" => auth::oauth::OAuthProvider::github(&req.client_id, &req.client_secret),
        _ => auth::oauth::OAuthProvider {
            id: Uuid::new_v4(),
            name: req.name.clone(),
            provider_type: auth::oauth::OAuthProviderType::Oidc,
            client_id: req.client_id,
            client_secret: req.client_secret,
            auth_url: req.auth_url.unwrap_or_default(),
            token_url: req.token_url.unwrap_or_default(),
            userinfo_url: req.userinfo_url.unwrap_or_default(),
            scopes: req.scopes.unwrap_or_else(|| "openid email profile".to_string()),
            enabled: true,
            created_at: chrono::Utc::now().to_rfc3339(),
        },
    };

    auth::oauth::save_provider(&state.pool, &provider).await.map_err(|_| internal())?;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: provider })))
}

pub async fn delete_oauth_provider(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    auth::oauth::delete_provider(&state.pool, uuid).await.map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(MessageResponse { message: format!("Provider {id} deleted") }))
}

pub async fn oauth_authorize(
    State(state): State<AppState>,
    Path(provider_name): Path<String>,
) -> Result<Json<auth::oauth::AuthorizeResponse>, StatusCode> {
    let provider = auth::oauth::get_provider_by_name(&state.pool, &provider_name)
        .await
        .map_err(|_| internal())?
        .ok_or(StatusCode::NOT_FOUND)?;

    let oauth_state = Uuid::new_v4().to_string();
    let redirect_uri = format!("/api/v1/auth/oauth/{}/callback", provider_name);
    let url = provider.authorize_url(&redirect_uri, &oauth_state);

    Ok(Json(auth::oauth::AuthorizeResponse {
        authorize_url: url,
        state: oauth_state,
    }))
}

pub async fn oauth_callback(
    State(_state): State<AppState>,
    Path(_provider_name): Path<String>,
    axum::extract::Query(query): axum::extract::Query<auth::oauth::CallbackQuery>,
) -> Result<Json<MessageResponse>, StatusCode> {
    // Validate required parameters are present
    if query.code.is_empty() {
        return Err(bad_request());
    }
    if query.state.is_empty() {
        return Err(bad_request());
    }
    // OAuth token exchange is not yet implemented — return 501
    Err(StatusCode::NOT_IMPLEMENTED)
}

/// Public registration — only allowed when no users exist (first-user bootstrap).
/// First user is always created as admin regardless of request.
/// Uses a DB-level check to prevent TOCTOU race conditions.
pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<auth::CreateUserRequest>,
) -> Result<(StatusCode, Json<ApiResponse<auth::User>>), StatusCode> {
    // Atomic check: INSERT only succeeds if users table is empty.
    // If two requests race, only one INSERT will find COUNT(*)=0.
    let admin_req = auth::CreateUserRequest {
        username: req.username,
        password: req.password,
        role: Some("admin".to_string()),
    };
    auth::validate_password(&admin_req.password)?;
    let pw_hash = auth::hash_password(&admin_req.password)?;
    let user_id = uuid::Uuid::new_v4();
    let now = chrono::Utc::now().to_rfc3339();

    // Atomic: INSERT ... WHERE (SELECT COUNT(*) FROM users) = 0
    let result = sqlx::query(
        r#"INSERT INTO users (id, username, password_hash, totp_enabled, totp_secret, auth_provider, role, role_id, enabled, created_at)
           SELECT ?1, ?2, ?3, 0, NULL, 'local', 'admin', 'builtin-admin', 1, ?4
           WHERE (SELECT COUNT(*) FROM users) = 0"#,
    )
    .bind(user_id.to_string())
    .bind(&admin_req.username)
    .bind(&pw_hash)
    .bind(&now)
    .execute(&state.pool)
    .await
    .map_err(|_| StatusCode::CONFLICT)?;

    if result.rows_affected() == 0 {
        return Err(StatusCode::FORBIDDEN);
    }

    let user = auth::User {
        id: user_id,
        username: admin_req.username,
        password_hash: pw_hash,
        totp_enabled: false,
        totp_secret: None,
        auth_provider: "local".to_string(),
        role: "admin".to_string(),
        role_id: Some("builtin-admin".to_string()),
        enabled: true,
        created_at: now,
    };
    Ok((StatusCode::CREATED, Json(ApiResponse { data: user })))
}

/// Protected user creation — requires authentication (admin only via RBAC middleware)
pub async fn create_user(
    State(state): State<AppState>,
    Json(req): Json<auth::CreateUserRequest>,
) -> Result<(StatusCode, Json<ApiResponse<auth::User>>), StatusCode> {
    let user = auth::create_user(&state.pool, &req).await?;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: user })))
}

pub async fn create_api_key(
    State(state): State<AppState>,
    Json(req): Json<auth::CreateApiKeyRequest>,
) -> Result<(StatusCode, Json<auth::CreateApiKeyResponse>), StatusCode> {
    let row = sqlx::query_as::<_, (String,)>("SELECT id FROM users LIMIT 1")
        .fetch_optional(&state.pool)
        .await
        .map_err(|_| internal())?
        .ok_or(bad_request())?;

    let user_id = Uuid::parse_str(&row.0).map_err(|_| internal())?;
    let response = auth::create_api_key(&state.pool, user_id, &req.name).await?;
    Ok((StatusCode::CREATED, Json(response)))
}

fn extract_user_id(headers: &HeaderMap, state: &AppState) -> Result<String, StatusCode> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        let data = auth::verify_access_token(token, &state.auth_settings)
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        Ok(data.claims.sub)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

// --- User management ---

pub async fn list_users(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<auth::User>>>, StatusCode> {
    let users = auth::list_users(&state.pool).await?;
    Ok(Json(ApiResponse { data: users }))
}

pub async fn get_user(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<auth::User>>, StatusCode> {
    let user = auth::get_user_by_id(&state.pool, &id).await?.ok_or(StatusCode::NOT_FOUND)?;
    Ok(Json(ApiResponse { data: user }))
}

pub async fn update_user(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    Json(req): Json<auth::UpdateUserRequest>,
) -> Result<Json<ApiResponse<auth::User>>, StatusCode> {
    let actor_id = extract_user_id(&headers, &state)?;
    let user = auth::update_user(&state.pool, &id, &req).await?;
    let details = format!("updated user {}", user.username);
    auth::log_user_audit(&state.pool, &actor_id, Some(&id), "user_updated", Some(&details)).await;
    Ok(Json(ApiResponse { data: user }))
}

pub async fn delete_user_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let actor_id = extract_user_id(&headers, &state)?;
    // Prevent self-deletion
    if actor_id == id {
        return Err(StatusCode::BAD_REQUEST);
    }
    let user = auth::get_user_by_id(&state.pool, &id).await?.ok_or(StatusCode::NOT_FOUND)?;
    auth::delete_user(&state.pool, &id).await?;
    auth::log_user_audit(&state.pool, &actor_id, Some(&id), "user_deleted", Some(&format!("deleted user {}", user.username))).await;
    Ok(Json(MessageResponse { message: format!("User {} deleted", user.username) }))
}

pub async fn list_user_audit(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<auth::UserAuditEntry>>>, StatusCode> {
    let entries = auth::list_user_audit_log(&state.pool, 200).await?;
    Ok(Json(ApiResponse { data: entries }))
}

// --- Config backup/restore ---

pub async fn export_config(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let config = crate::backup::build_current_config(&state).await?;

    let routes = sqlx::query_as::<_, (String, String, String, Option<String>, i32, bool, Option<String>, String)>(
        "SELECT id, destination, gateway, interface, metric, enabled, description, created_at FROM static_routes ORDER BY metric ASC",
    ).fetch_all(&state.pool).await.unwrap_or_default();

    let static_routes: Vec<serde_json::Value> = routes.iter().map(|(id, d, g, i, m, e, desc, ca)| {
        serde_json::json!({"id": id, "destination": d, "gateway": g, "interface": i, "metric": m, "enabled": e, "description": desc, "created_at": ca})
    }).collect();

    Ok(Json(serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "exported_at": chrono::Utc::now().to_rfc3339(),
        "config": config,
        "static_routes": static_routes,
    })))
}

pub async fn import_config(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let config_val = payload.get("config").ok_or(StatusCode::BAD_REQUEST)?;
    let config: aifw_core::config::FirewallConfig = serde_json::from_value(config_val.clone())
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    let iface_map: crate::backup::InterfaceMap = payload.get("interface_map")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let rules_n = config.rules.len();
    let nat_n = config.nat.len();
    let geoip_n = config.geoip.len();
    let wg_n = config.vpn.wireguard.len();
    let ipsec_n = config.vpn.ipsec.len();
    let dns_n = config.system.dns_servers.len();

    crate::backup::apply_firewall_config(&state, &config, &iface_map).await?;

    let _ = sqlx::query("DELETE FROM static_routes").execute(&state.pool).await;
    let mut routes_n = 0;
    if let Some(routes) = payload.get("static_routes").and_then(|v| v.as_array()) {
        for route in routes {
            let dest = route.get("destination").and_then(|v| v.as_str()).unwrap_or("");
            let gw = route.get("gateway").and_then(|v| v.as_str()).unwrap_or("");
            if dest.is_empty() || gw.is_empty() { continue; }
            let iface = route.get("interface").and_then(|v| v.as_str());
            let metric = route.get("metric").and_then(|v| v.as_i64()).unwrap_or(0) as i32;
            let enabled = route.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true);
            let desc = route.get("description").and_then(|v| v.as_str());
            let id = route.get("id").and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
            let created_at = route.get("created_at").and_then(|v| v.as_str())
                .map(String::from)
                .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
            let _ = sqlx::query(
                "INSERT INTO static_routes (id, destination, gateway, interface, metric, enabled, description, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)")
                .bind(&id).bind(dest).bind(gw).bind(iface).bind(metric).bind(enabled).bind(desc).bind(&created_at)
                .execute(&state.pool).await;
            routes_n += 1;
        }
    }

    let msg = format!(
        "Imported: {rules_n} rules, {nat_n} NAT, {geoip_n} geo-IP, {wg_n} WireGuard, {ipsec_n} IPsec, {dns_n} DNS, {routes_n} static routes"
    );
    Ok(Json(MessageResponse { message: msg }))
}

// --- Schedules ---

#[derive(Debug, Serialize, Deserialize)]
pub struct Schedule {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub time_ranges: String,   // e.g. "08:00-17:00" or "08:00-12:00,13:00-17:00"
    pub days_of_week: String,  // e.g. "mon,tue,wed,thu,fri"
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub(crate) enum StringOrVec {
    Single(String),
    Multiple(Vec<String>),
}

impl StringOrVec {
    fn into_string(self) -> String {
        match self {
            StringOrVec::Single(s) => s,
            StringOrVec::Multiple(v) => v.join(","),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateScheduleRequest {
    pub name: String,
    pub description: Option<String>,
    pub time_ranges: StringOrVec,
    pub days_of_week: Option<StringOrVec>,
    pub enabled: Option<bool>,
}

pub async fn list_schedules(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<Schedule>>>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, String, Option<String>, String, String, bool, String)>(
        "SELECT id, name, description, time_ranges, days_of_week, enabled, created_at FROM schedules ORDER BY name ASC",
    ).fetch_all(&state.pool).await.map_err(|_| internal())?;
    let schedules: Vec<Schedule> = rows.into_iter().map(|(id,name,desc,tr,dow,en,ca)| Schedule {
        id, name, description: desc, time_ranges: tr, days_of_week: dow, enabled: en, created_at: ca,
    }).collect();
    Ok(Json(ApiResponse { data: schedules }))
}

fn validate_time_ranges(s: &str) -> bool {
    // Accepts "HH:MM-HH:MM" or comma-separated ranges
    for range in s.split(',') {
        let parts: Vec<&str> = range.trim().split('-').collect();
        if parts.len() != 2 { return false; }
        for part in &parts {
            let hm: Vec<&str> = part.split(':').collect();
            if hm.len() != 2 { return false; }
            let h: u8 = match hm[0].parse() { Ok(v) => v, Err(_) => return false };
            let m: u8 = match hm[1].parse() { Ok(v) => v, Err(_) => return false };
            if h > 23 || m > 59 { return false; }
        }
    }
    true
}

fn validate_days_of_week(s: &str) -> bool {
    const VALID: &[&str] = &["mon","tue","wed","thu","fri","sat","sun"];
    s.split(',').all(|d| VALID.contains(&d.trim()))
}

pub async fn create_schedule(
    State(state): State<AppState>,
    Json(req): Json<CreateScheduleRequest>,
) -> Result<(StatusCode, Json<ApiResponse<Schedule>>), StatusCode> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let time_ranges = req.time_ranges.into_string();
    if !validate_time_ranges(&time_ranges) { return Err(bad_request()); }
    let dow = req.days_of_week.map(|d| d.into_string()).unwrap_or_else(|| "mon,tue,wed,thu,fri,sat,sun".to_string());
    if !validate_days_of_week(&dow) { return Err(bad_request()); }
    let enabled = req.enabled.unwrap_or(true);
    sqlx::query("INSERT INTO schedules (id, name, description, time_ranges, days_of_week, enabled, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)")
        .bind(&id).bind(&req.name).bind(req.description.as_deref()).bind(&time_ranges).bind(&dow).bind(enabled).bind(&now)
        .execute(&state.pool).await.map_err(|_| bad_request())?;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: Schedule { id, name: req.name, description: req.description, time_ranges, days_of_week: dow, enabled, created_at: now } })))
}

pub async fn update_schedule(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateScheduleRequest>,
) -> Result<Json<ApiResponse<Schedule>>, StatusCode> {
    let time_ranges = req.time_ranges.into_string();
    if !validate_time_ranges(&time_ranges) { return Err(bad_request()); }
    let dow = req.days_of_week.map(|d| d.into_string()).unwrap_or_else(|| "mon,tue,wed,thu,fri,sat,sun".to_string());
    if !validate_days_of_week(&dow) { return Err(bad_request()); }
    let enabled = req.enabled.unwrap_or(true);
    let result = sqlx::query("UPDATE schedules SET name=?2, description=?3, time_ranges=?4, days_of_week=?5, enabled=?6 WHERE id=?1")
        .bind(&id).bind(&req.name).bind(req.description.as_deref()).bind(&time_ranges).bind(&dow).bind(enabled)
        .execute(&state.pool).await.map_err(|_| internal())?;
    if result.rows_affected() == 0 { return Err(StatusCode::NOT_FOUND); }
    let now = chrono::Utc::now().to_rfc3339();
    Ok(Json(ApiResponse { data: Schedule { id, name: req.name, description: req.description, time_ranges, days_of_week: dow, enabled, created_at: now } }))
}

pub async fn delete_schedule(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query("DELETE FROM schedules WHERE id=?1").bind(&id).execute(&state.pool).await.map_err(|_| internal())?;
    if result.rows_affected() == 0 { return Err(StatusCode::NOT_FOUND); }
    // Unlink from rules
    let _ = sqlx::query("UPDATE rules SET schedule_id = NULL WHERE schedule_id = ?1").bind(&id).execute(&state.pool).await;
    Ok(Json(MessageResponse { message: format!("Schedule {id} deleted") }))
}

// --- System PF rules (from pfctl, read-only) ---

pub async fn list_system_rules() -> Result<Json<ApiResponse<Vec<String>>>, StatusCode> {
    let mut all_rules = Vec::new();

    // Main ruleset
    if let Ok(output) = tokio::process::Command::new("/usr/local/bin/sudo")
        .args(["pfctl", "-sr"]).output().await {
        let stdout = String::from_utf8_lossy(&output.stdout);
        all_rules.extend(stdout.lines().filter(|l| !l.is_empty()).map(String::from));
    }

    // AiFw anchor rules
    for anchor in ["aifw", "aifw-nat", "aifw-vpn", "aifw-geoip"] {
        if let Ok(output) = tokio::process::Command::new("/usr/local/bin/sudo")
            .args(["pfctl", "-a", anchor, "-sr"]).output().await {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let anchor_rules: Vec<String> = stdout.lines().filter(|l| !l.is_empty()).map(String::from).collect();
            if !anchor_rules.is_empty() {
                all_rules.push(format!("# --- anchor \"{}\" ---", anchor));
                all_rules.extend(anchor_rules);
            }
        }
    }

    Ok(Json(ApiResponse { data: all_rules }))
}

// --- Rules endpoints ---

pub async fn list_rules(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<Rule>>>, StatusCode> {
    let rules = state.rule_engine.list_rules().await.map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: rules }))
}

pub async fn get_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<Rule>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let rule = state.rule_engine.get_rule(uuid).await.map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(ApiResponse { data: rule }))
}

pub async fn create_rule(
    State(state): State<AppState>,
    Json(req): Json<CreateRuleRequest>,
) -> Result<(StatusCode, Json<ApiResponse<Rule>>), StatusCode> {
    let action = match req.action.as_str() {
        "pass" => Action::Pass,
        "block" => Action::Block,
        "block_drop" | "block-drop" => Action::BlockDrop,
        "block_return" | "block-return" => Action::BlockReturn,
        _ => return Err(bad_request()),
    };

    let direction = match req.direction.as_str() {
        "in" => Direction::In,
        "out" => Direction::Out,
        "any" => Direction::Any,
        _ => return Err(bad_request()),
    };

    let protocol = Protocol::parse(&req.protocol).map_err(|_| bad_request())?;

    let src_addr = req.src_addr.as_deref()
        .map(Address::parse)
        .transpose()
        .map_err(|_| bad_request())?
        .unwrap_or(Address::Any);

    let dst_addr = req.dst_addr.as_deref()
        .map(Address::parse)
        .transpose()
        .map_err(|_| bad_request())?
        .unwrap_or(Address::Any);

    let rule_match = RuleMatch {
        src_addr,
        src_port: port_range(req.src_port_start, req.src_port_end),
        dst_addr,
        dst_port: port_range(req.dst_port_start, req.dst_port_end),
    };

    let mut rule = Rule::new(action, direction, protocol, rule_match);
    if let Some(p) = req.priority {
        rule.priority = p;
    }
    if let Some(l) = req.log {
        rule.log = l;
    }
    if let Some(q) = req.quick {
        rule.quick = q;
    }
    rule.label = req.label;
    rule.interface = req.interface.map(Interface);

    if let Some(ref st) = req.state_tracking {
        rule.state_options.tracking = match st.as_str() {
            "none" => StateTracking::None,
            "keep_state" => StateTracking::KeepState,
            "modulate_state" => StateTracking::ModulateState,
            "synproxy_state" => StateTracking::SynproxyState,
            _ => return Err(bad_request()),
        };
    }

    rule.schedule_id = req.schedule_id;

    // Validate label and interface to prevent pf rule injection
    if let Some(ref iface) = rule.interface {
        aifw_core::validation::validate_interface_name(&iface.0).map_err(|_| bad_request())?;
    }
    if let Some(ref label) = rule.label {
        aifw_core::validation::validate_label(label).map_err(|_| bad_request())?;
    }

    let rule = state.rule_engine.add_rule(rule).await.map_err(|_| bad_request())?;
    state.set_pending(|p| p.firewall = true).await;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: rule })))
}

pub async fn update_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateRuleRequest>,
) -> Result<Json<ApiResponse<Rule>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let mut rule = state.rule_engine.get_rule(uuid).await.map_err(|_| StatusCode::NOT_FOUND)?;

    rule.action = match req.action.as_str() {
        "pass" => Action::Pass,
        "block" => Action::Block,
        "block_drop" | "block-drop" => Action::BlockDrop,
        "block_return" | "block-return" => Action::BlockReturn,
        _ => return Err(bad_request()),
    };
    rule.direction = match req.direction.as_str() {
        "in" => Direction::In,
        "out" => Direction::Out,
        "any" => Direction::Any,
        _ => return Err(bad_request()),
    };
    rule.protocol = Protocol::parse(&req.protocol).map_err(|_| bad_request())?;
    rule.rule_match.src_addr = req.src_addr.as_deref()
        .map(Address::parse).transpose().map_err(|_| bad_request())?
        .unwrap_or(Address::Any);
    rule.rule_match.src_port = port_range(req.src_port_start, req.src_port_end);
    rule.rule_match.dst_addr = req.dst_addr.as_deref()
        .map(Address::parse).transpose().map_err(|_| bad_request())?
        .unwrap_or(Address::Any);
    rule.rule_match.dst_port = port_range(req.dst_port_start, req.dst_port_end);
    if let Some(p) = req.priority { rule.priority = p; }
    if let Some(l) = req.log { rule.log = l; }
    if let Some(q) = req.quick { rule.quick = q; }
    rule.label = req.label;
    rule.interface = req.interface.map(Interface);
    if let Some(ref st) = req.state_tracking {
        rule.state_options.tracking = match st.as_str() {
            "none" => StateTracking::None,
            "keep_state" => StateTracking::KeepState,
            "modulate_state" => StateTracking::ModulateState,
            "synproxy_state" => StateTracking::SynproxyState,
            _ => return Err(bad_request()),
        };
    }
    if let Some(ref s) = req.status {
        rule.status = match s.as_str() {
            "active" => RuleStatus::Active,
            "disabled" => RuleStatus::Disabled,
            _ => return Err(bad_request()),
        };
    }
    rule.schedule_id = req.schedule_id;
    rule.updated_at = chrono::Utc::now();

    // Validate label and interface to prevent pf rule injection
    if let Some(ref iface) = rule.interface {
        aifw_core::validation::validate_interface_name(&iface.0).map_err(|_| bad_request())?;
    }
    if let Some(ref label) = rule.label {
        aifw_core::validation::validate_label(label).map_err(|_| bad_request())?;
    }

    state.rule_engine.update_rule(rule.clone()).await.map_err(|_| internal())?;
    state.set_pending(|p| p.firewall = true).await;
    Ok(Json(ApiResponse { data: rule }))
}

pub async fn delete_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    state.rule_engine.delete_rule(uuid).await.map_err(|_| StatusCode::NOT_FOUND)?;
    state.set_pending(|p| p.firewall = true).await;
    Ok(Json(MessageResponse { message: format!("Rule {id} deleted") }))
}

pub async fn toggle_block_logging(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let enabled = payload.get("enabled").and_then(|v| v.as_bool()).unwrap_or(false);
    let now = chrono::Utc::now().to_rfc3339();

    // Update all block rules' log flag
    sqlx::query("UPDATE rules SET log = ?1, updated_at = ?2 WHERE action IN ('block', 'blockdrop', 'block_return', 'blockreturn')")
        .bind(enabled).bind(&now)
        .execute(&state.pool).await.map_err(|_| internal())?;

    // Reload pf rules
    let rules = state.rule_engine.list_rules().await.map_err(|_| internal())?;
    let pf_rules: Vec<String> = rules.iter().map(|r| r.to_pf_rule("aifw")).collect();
    let _ = state.pf.load_rules("aifw", &pf_rules).await;

    let msg = if enabled { "Block logging enabled" } else { "Block logging disabled" };
    Ok(Json(MessageResponse { message: msg.to_string() }))
}

// --- NAT endpoints ---

pub async fn list_nat_rules(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<NatRule>>>, StatusCode> {
    let rules = state.nat_engine.list_rules().await.map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: rules }))
}

pub async fn create_nat_rule(
    State(state): State<AppState>,
    Json(req): Json<CreateNatRuleRequest>,
) -> Result<(StatusCode, Json<ApiResponse<NatRule>>), StatusCode> {
    let nat_type = NatType::parse(&req.nat_type).map_err(|_| bad_request())?;
    let protocol = Protocol::parse(&req.protocol).map_err(|_| bad_request())?;

    let src_addr = req.src_addr.as_deref()
        .map(Address::parse)
        .transpose()
        .map_err(|_| bad_request())?
        .unwrap_or(Address::Any);

    let dst_addr = req.dst_addr.as_deref()
        .map(Address::parse)
        .transpose()
        .map_err(|_| bad_request())?
        .unwrap_or(Address::Any);

    let redirect_addr = Address::parse(&req.redirect_addr).map_err(|_| bad_request())?;

    // Validate interface and label to prevent pf rule injection
    aifw_core::validation::validate_interface_name(&req.interface).map_err(|_| bad_request())?;
    if let Some(ref label) = req.label {
        aifw_core::validation::validate_label(label).map_err(|_| bad_request())?;
    }

    let mut rule = NatRule::new(
        nat_type,
        Interface(req.interface),
        protocol,
        src_addr,
        dst_addr,
        NatRedirect {
            address: redirect_addr,
            port: port_range(req.redirect_port_start, req.redirect_port_end),
        },
    );
    rule.src_port = port_range(req.src_port_start, req.src_port_end);
    rule.dst_port = port_range(req.dst_port_start, req.dst_port_end);
    rule.label = req.label;

    let rule = state.nat_engine.add_rule(rule).await.map_err(|_| bad_request())?;
    state.set_pending(|p| p.nat = true).await;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: rule })))
}

pub async fn update_nat_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateNatRuleRequest>,
) -> Result<Json<ApiResponse<NatRule>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let mut rule = state.nat_engine.get_rule(uuid).await.map_err(|_| StatusCode::NOT_FOUND)?;

    rule.nat_type = NatType::parse(&req.nat_type).map_err(|_| bad_request())?;
    // Validate interface and label to prevent pf rule injection
    aifw_core::validation::validate_interface_name(&req.interface).map_err(|_| bad_request())?;
    if let Some(ref label) = req.label {
        aifw_core::validation::validate_label(label).map_err(|_| bad_request())?;
    }

    rule.interface = Interface(req.interface);
    rule.protocol = Protocol::parse(&req.protocol).map_err(|_| bad_request())?;
    rule.src_addr = req.src_addr.as_deref()
        .map(Address::parse).transpose().map_err(|_| bad_request())?
        .unwrap_or(Address::Any);
    rule.src_port = port_range(req.src_port_start, req.src_port_end);
    rule.dst_addr = req.dst_addr.as_deref()
        .map(Address::parse).transpose().map_err(|_| bad_request())?
        .unwrap_or(Address::Any);
    rule.dst_port = port_range(req.dst_port_start, req.dst_port_end);
    rule.redirect = NatRedirect {
        address: Address::parse(&req.redirect_addr).map_err(|_| bad_request())?,
        port: port_range(req.redirect_port_start, req.redirect_port_end),
    };
    rule.label = req.label;
    if let Some(ref s) = req.status {
        rule.status = match s.as_str() {
            "active" => NatStatus::Active,
            "disabled" => NatStatus::Disabled,
            _ => return Err(bad_request()),
        };
    }
    rule.updated_at = chrono::Utc::now();

    state.nat_engine.update_rule(&rule).await.map_err(|_| internal())?;
    state.set_pending(|p| p.nat = true).await;
    Ok(Json(ApiResponse { data: rule }))
}

pub async fn delete_nat_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    state.nat_engine.delete_rule(uuid).await.map_err(|_| StatusCode::NOT_FOUND)?;
    state.set_pending(|p| p.nat = true).await;
    Ok(Json(MessageResponse { message: format!("NAT rule {id} deleted") }))
}

// --- Status ---

pub async fn status(
    State(state): State<AppState>,
) -> Result<Json<StatusResponse>, StatusCode> {
    let stats = state.pf.get_stats().await.map_err(|_| internal())?;
    let rules = state.rule_engine.list_rules().await.map_err(|_| internal())?;
    let active = rules.iter().filter(|r| r.status == RuleStatus::Active).count();
    let nat_rules = state.nat_engine.list_rules().await.map_err(|_| internal())?;

    Ok(Json(StatusResponse {
        pf_running: stats.running,
        pf_states: stats.states_count,
        pf_rules: stats.rules_count,
        aifw_rules: rules.len(),
        aifw_active_rules: active,
        nat_rules: nat_rules.len(),
        packets_in: stats.packets_in,
        packets_out: stats.packets_out,
        bytes_in: stats.bytes_in,
        bytes_out: stats.bytes_out,
    }))
}

// --- pf state-table tuning (Settings → System → max states) ---

#[derive(serde::Serialize)]
pub struct PfTuningResponse {
    pub configured_max_states: u64,
    /// What pf is actually using right now. Drifts from `configured` if the
    /// last apply failed (e.g. pf wasn't running). UI uses both.
    pub live_max_states: Option<u64>,
    pub current_states: u64,
    pub min_states: u64,
    pub max_states: u64,
}

pub async fn get_pf_tuning(
    State(state): State<AppState>,
) -> Json<PfTuningResponse> {
    let stats = state.pf.get_stats().await.unwrap_or_default();
    Json(PfTuningResponse {
        configured_max_states: aifw_core::pf_tuning::configured_max_states(&state.pool).await,
        live_max_states: aifw_core::pf_tuning::live_max_states().await,
        current_states: stats.states_count,
        min_states: aifw_core::pf_tuning::MIN_STATES,
        max_states: aifw_core::pf_tuning::MAX_STATES,
    })
}

#[derive(serde::Deserialize)]
pub struct PutPfTuningRequest {
    pub max_states: u64,
}

pub async fn put_pf_tuning(
    State(state): State<AppState>,
    Json(req): Json<PutPfTuningRequest>,
) -> Result<Json<PfTuningResponse>, (StatusCode, String)> {
    aifw_core::pf_tuning::set_max_states(&state.pool, req.max_states)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(get_pf_tuning(State(state)).await)
}

/// `/api/v1/about` — surfaces version + memory breakdown for the About
/// page so it doesn't need to subscribe to the dashboard WebSocket just
/// to show a memory readout.
#[derive(serde::Serialize)]
pub struct AboutResponse {
    pub version: String,
    pub git_commit: Option<String>,
    pub built_at: Option<String>,
    pub memory: crate::ws::MemoryBreakdown,
}

pub async fn about_info(
    State(state): State<AppState>,
) -> Json<AboutResponse> {
    Json(AboutResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        // Optional build-time stamps. Both injected via env if set; otherwise
        // None — the About page treats them as best-effort.
        git_commit: option_env!("AIFW_GIT_COMMIT").map(|s| s.to_string()),
        built_at:   option_env!("AIFW_BUILT_AT").map(|s| s.to_string()),
        memory: crate::ws::collect_memory_breakdown(&state).await,
    })
}

// --- Connections ---

pub async fn list_connections(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<aifw_pf::PfState>>>, StatusCode> {
    state.conntrack.refresh().await.map_err(|_| internal())?;
    let connections = state.conntrack.get_connections().await;
    Ok(Json(ApiResponse { data: connections }))
}

// --- Pending / Reload ---

pub async fn get_pending(
    State(state): State<AppState>,
) -> Result<Json<crate::PendingChanges>, StatusCode> {
    let pending = state.pending.read().await.clone();
    Ok(Json(pending))
}

/// Issue a short-lived, single-use ticket for the WebSocket / SSE handshake.
/// The caller authenticates via the normal bearer header; the returned
/// ticket is then appended as `?ticket=<id>` to the stream URL. Browsers
/// can't set Authorization on WebSocket or EventSource, so the ticket is
/// the canonical way to prove identity on those endpoints.
pub async fn issue_ws_ticket(
    State(state): State<AppState>,
    auth_user: axum::Extension<crate::auth::AuthUser>,
) -> Json<serde_json::Value> {
    let ticket = state.ws_tickets.issue(&auth_user.user_id).await;
    Json(serde_json::json!({ "ticket": ticket, "expires_in_seconds": 30 }))
}

/// SSE stream that pushes PendingChanges whenever they mutate.
/// Auth handled by auth_middleware — for browsers use `?ticket=<id>`.
pub async fn pending_stream(
    State(state): State<AppState>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let mut rx = state.pending_tx.subscribe();

    let stream = async_stream::stream! {
        // Send current state immediately on connect.
        let current = state.pending.read().await.clone();
        if let Ok(json) = serde_json::to_string(&current) {
            yield Ok(Event::default().data(json));
        }

        // Then push on every change.
        while rx.changed().await.is_ok() {
            let val = rx.borrow_and_update().clone();
            if let Ok(json) = serde_json::to_string(&val) {
                yield Ok(Event::default().data(json));
            }
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub async fn reload(
    State(state): State<AppState>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let mut errors = Vec::new();

    // Apply VLANs from DB to OS
    if let Err(e) = crate::iface::apply_vlans(&state.pool).await {
        tracing::error!("Failed to apply VLANs: {e}");
        errors.push(format!("vlans: {e}"));
    }

    // Sync alias pf tables before loading rules that reference them
    if let Err(e) = state.alias_engine.sync_all().await {
        tracing::error!("Failed to sync aliases: {e}");
        errors.push(format!("aliases: {e}"));
    }
    // Re-inject VPN rules before applying filter rules
    if let Ok(vpn_rules) = state.vpn_engine.collect_vpn_rules().await {
        state.rule_engine.set_extra_rules(vpn_rules).await;
    }
    if let Err(e) = state.rule_engine.apply_rules().await {
        tracing::error!("Failed to apply filter rules: {e}");
        errors.push(format!("filter: {e}"));
    }
    if let Err(e) = state.nat_engine.apply_rules().await {
        tracing::error!("Failed to apply NAT rules: {e}");
        errors.push(format!("nat: {e}"));
    }
    // Clear pending flags for firewall and NAT
    state.set_pending(|p| {
        p.firewall = false;
        p.nat = false;
    }).await;
    if errors.is_empty() {
        Ok(Json(MessageResponse { message: "Changes applied successfully".to_string() }))
    } else {
        Ok(Json(MessageResponse { message: format!("Partial reload: {}", errors.join("; ")) }))
    }
}

// --- Blocked Traffic (pflog) ---

#[derive(Debug, Serialize)]
pub struct BlockedEntry {
    pub timestamp: String,
    pub action: String,
    pub direction: String,
    pub interface: String,
    pub protocol: String,
    pub src_addr: String,
    pub src_port: u16,
    pub dst_addr: String,
    pub dst_port: u16,
    pub reason: String,
}

pub async fn list_blocked_traffic() -> Result<Json<ApiResponse<Vec<BlockedEntry>>>, StatusCode> {
    let mut entries = Vec::new();

    // Read from /var/log/pflog binary — this is where pf logs all block/pass with log flag
    // tcpdump -n -e -r /var/log/pflog shows: "rule X(match): block/pass in/out on iface: src > dst"
    if let Ok(output) = tokio::process::Command::new("/usr/local/bin/sudo")
        .args(["/usr/sbin/tcpdump", "-tttt", "-n", "-e", "-r", "/var/log/pflog"])
        .output().await
        && output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().rev() {
                let action = if line.contains(": block ") {
                    "block"
                } else if line.contains(": pass ") {
                    "pass"
                } else {
                    continue;
                };

                // -tttt format: "2026-04-01 13:09:28.475326 rule ..."
                let mut words = line.split_whitespace();
                let date_part = words.next().unwrap_or("");
                let time_part = words.next().unwrap_or("");
                let timestamp = format!("{date_part}T{time_part}");

                let mut entry = BlockedEntry {
                    timestamp,
                    action: action.to_string(),
                    direction: String::new(),
                    interface: String::new(),
                    protocol: String::new(),
                    src_addr: String::new(),
                    src_port: 0,
                    dst_addr: String::new(),
                    dst_port: 0,
                    reason: "policy".to_string(),
                };

                let action_pos = if action == "block" { line.find(": block ") } else { line.find(": pass ") };
                if let Some(pos) = action_pos {
                    let rest = &line[pos + 2..];
                    let parts: Vec<&str> = rest.split_whitespace().collect();
                    entry.direction = parts.get(1).unwrap_or(&"").to_string();
                    entry.interface = parts.get(3).map(|s| s.trim_end_matches(':')).unwrap_or("").to_string();
                }

                if let Some(gt_pos) = line.find(" > ") {
                    let before = &line[..gt_pos];
                    let src_token = before.split_whitespace().next_back().unwrap_or("");
                    if let Some(dot_pos) = src_token.rfind('.') {
                        let maybe_port = &src_token[dot_pos + 1..];
                        let maybe_ip = &src_token[..dot_pos];
                        if let Ok(port) = maybe_port.parse::<u16>() {
                            if maybe_ip.chars().filter(|c| *c == '.').count() >= 3 {
                                entry.src_addr = maybe_ip.to_string();
                                entry.src_port = port;
                            } else if src_token.chars().filter(|c| *c == '.').count() == 3 {
                                entry.src_addr = src_token.to_string();
                            }
                        } else if src_token.chars().filter(|c| *c == '.').count() == 3 {
                            entry.src_addr = src_token.to_string();
                        }
                    }

                    let after = &line[gt_pos + 3..];
                    let dst_token = after.split(':').next().unwrap_or("").trim();
                    if let Some(dot_pos) = dst_token.rfind('.') {
                        let maybe_port = &dst_token[dot_pos + 1..];
                        let maybe_ip = &dst_token[..dot_pos];
                        if let Ok(port) = maybe_port.parse::<u16>() {
                            if maybe_ip.chars().filter(|c| *c == '.').count() >= 3 {
                                entry.dst_addr = maybe_ip.to_string();
                                entry.dst_port = port;
                            } else if dst_token.chars().filter(|c| *c == '.').count() == 3 {
                                entry.dst_addr = dst_token.to_string();
                            }
                        } else if dst_token.chars().filter(|c| *c == '.').count() == 3 {
                            entry.dst_addr = dst_token.to_string();
                        }
                    }
                }

                let lower = line.to_lowercase();
                if line.contains("Flags [") || lower.contains(" tcp ") { entry.protocol = "tcp".to_string(); }
                else if lower.contains(" udp ") { entry.protocol = "udp".to_string(); }
                else if lower.contains("icmp") { entry.protocol = "icmp".to_string(); }
                else if lower.contains(" esp ") || lower.contains("esp(") { entry.protocol = "esp".to_string(); }
                else if lower.contains(" ah ") || lower.contains("ah(") { entry.protocol = "ah".to_string(); }
                else if lower.contains(" gre ") || lower.contains("gre(") { entry.protocol = "gre".to_string(); }
                else if lower.contains("igmp") { entry.protocol = "igmp".to_string(); }

                if !entry.src_addr.is_empty() {
                    entries.push(entry);
                }
            }
        }

    Ok(Json(ApiResponse { data: entries }))
}

// --- Metrics ---

pub async fn metrics(
    State(state): State<AppState>,
) -> Result<Json<MetricsResponse>, StatusCode> {
    let stats = state.pf.get_stats().await.map_err(|_| internal())?;
    let rules = state.rule_engine.list_rules().await.map_err(|_| internal())?;
    let active = rules.iter().filter(|r| r.status == RuleStatus::Active).count();
    let nat_rules = state.nat_engine.list_rules().await.map_err(|_| internal())?;

    Ok(Json(MetricsResponse {
        pf_running: stats.running,
        pf_states_count: stats.states_count,
        pf_rules_count: stats.rules_count,
        pf_packets_in: stats.packets_in,
        pf_packets_out: stats.packets_out,
        pf_bytes_in: stats.bytes_in,
        pf_bytes_out: stats.bytes_out,
        aifw_rules_total: rules.len(),
        aifw_rules_active: active,
        aifw_nat_rules_total: nat_rules.len(),
    }))
}

// --- Logs ---

pub async fn list_logs(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<aifw_core::audit::AuditEntry>>>, StatusCode> {
    let entries = state.rule_engine.audit().list(100).await.map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: entries }))
}

// --- DNS ---

pub async fn get_dns() -> Result<Json<DnsConfigResponse>, StatusCode> {
    let content = tokio::fs::read_to_string("/etc/resolv.conf")
        .await
        .unwrap_or_default();
    let servers: Vec<String> = content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            line.strip_prefix("nameserver").map(|addr| addr.trim().to_string())
        })
        .collect();
    Ok(Json(DnsConfigResponse { servers }))
}

// --- Rule reordering ---

#[derive(Debug, Deserialize)]
pub struct ReorderRequest {
    pub rule_ids: Vec<String>,
}

pub async fn reorder_rules(
    State(state): State<AppState>,
    Json(req): Json<ReorderRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    for (i, id_str) in req.rule_ids.iter().enumerate() {
        let uuid = Uuid::parse_str(id_str).map_err(|_| bad_request())?;
        let mut rule = state.rule_engine.get_rule(uuid).await.map_err(|_| StatusCode::NOT_FOUND)?;
        rule.priority = i as i32;
        rule.updated_at = chrono::Utc::now();
        state.rule_engine.update_rule(rule).await.map_err(|_| internal())?;
    }
    state.set_pending(|p| p.firewall = true).await;
    Ok(Json(MessageResponse { message: format!("{} rules reordered", req.rule_ids.len()) }))
}

pub async fn get_nat_pf_output(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<String>>>, StatusCode> {
    let nat_rules = state.pf.get_nat_rules("aifw").await.unwrap_or_default();
    let filter_rules = state.pf.get_rules("aifw").await.unwrap_or_default();
    let mut output = Vec::new();
    if !nat_rules.is_empty() {
        output.push("# NAT Rules (anchor: aifw)".to_string());
        output.extend(nat_rules);
    }
    if !filter_rules.is_empty() {
        output.push("".to_string());
        output.push("# Filter Rules (anchor: aifw)".to_string());
        output.extend(filter_rules);
    }
    Ok(Json(ApiResponse { data: output }))
}

pub async fn reorder_nat_rules(
    State(state): State<AppState>,
    Json(req): Json<ReorderRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    // Update order by setting created_at timestamps in sequence
    for (i, id_str) in req.rule_ids.iter().enumerate() {
        let uuid = Uuid::parse_str(id_str).map_err(|_| bad_request())?;
        let _ = sqlx::query("UPDATE nat_rules SET created_at = datetime('2000-01-01', '+' || ?2 || ' seconds') WHERE id = ?1")
            .bind(uuid.to_string())
            .bind(i as i64)
            .execute(&state.pool)
            .await;
    }
    state.set_pending(|p| p.nat = true).await;
    Ok(Json(MessageResponse { message: format!("{} NAT rules reordered", req.rule_ids.len()) }))
}

// --- GeoIP ---

#[derive(Debug, Deserialize)]
pub struct CreateGeoIpRuleRequest {
    pub country_code: String,
    pub action: String,
    pub status: Option<String>,
}

pub async fn list_geoip_rules(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<GeoIpRule>>>, StatusCode> {
    let rules = state.geoip_engine.list_rules().await.map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: rules }))
}

pub async fn create_geoip_rule(
    State(state): State<AppState>,
    Json(req): Json<CreateGeoIpRuleRequest>,
) -> Result<(StatusCode, Json<ApiResponse<GeoIpRule>>), StatusCode> {
    let country = CountryCode::new(&req.country_code).map_err(|_| bad_request())?;
    let action = GeoIpAction::parse(&req.action).map_err(|_| bad_request())?;
    let rule = GeoIpRule::new(country, action);
    let rule = state.geoip_engine.add_rule(rule).await.map_err(|_| bad_request())?;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: rule })))
}

pub async fn update_geoip_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateGeoIpRuleRequest>,
) -> Result<Json<ApiResponse<GeoIpRule>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let mut rule = state.geoip_engine.get_rule(uuid).await.map_err(|_| StatusCode::NOT_FOUND)?;
    rule.country = CountryCode::new(&req.country_code).map_err(|_| bad_request())?;
    rule.action = GeoIpAction::parse(&req.action).map_err(|_| bad_request())?;
    if let Some(ref s) = req.status {
        rule.status = match s.as_str() {
            "active" => GeoIpRuleStatus::Active,
            "disabled" => GeoIpRuleStatus::Disabled,
            _ => return Err(bad_request()),
        };
    }
    state.geoip_engine.update_rule(&rule).await.map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: rule }))
}

pub async fn delete_geoip_rule(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    state.geoip_engine.delete_rule(uuid).await.map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(MessageResponse { message: format!("Geo-IP rule {id} deleted") }))
}

pub async fn geoip_lookup(
    State(state): State<AppState>,
    Path(ip_str): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let ip: std::net::IpAddr = ip_str.parse().map_err(|_| bad_request())?;
    let result = state.geoip_engine.lookup(ip).await;
    Ok(Json(serde_json::to_value(result).unwrap_or_default()))
}

// --- VPN: WireGuard ---

#[derive(Debug, Deserialize)]
pub struct CreateWgTunnelRequest {
    pub name: String,
    pub listen_port: u16,
    pub address: String,
    pub private_key: Option<String>,
    pub dns: Option<String>,
    pub mtu: Option<u16>,
    pub listen_interface: Option<String>,
    /// Comma-separated CIDRs to advertise as split-tunnel AllowedIPs.
    /// When empty/omitted, falls back to the tunnel's network CIDR.
    pub split_routes: Option<String>,
}

pub async fn list_wg_tunnels(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<WgTunnel>>>, StatusCode> {
    let tunnels = state.vpn_engine.list_wg_tunnels().await.map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: tunnels }))
}

pub async fn create_wg_tunnel(
    State(state): State<AppState>,
    Json(req): Json<CreateWgTunnelRequest>,
) -> Result<(StatusCode, Json<ApiResponse<WgTunnel>>), StatusCode> {
    let address = Address::parse(&req.address).map_err(|_| bad_request())?;
    // FreeBSD requires short interface names: wg0, wg1, etc. (not wg51820)
    let existing = state.vpn_engine.list_wg_tunnels().await.unwrap_or_default();
    let used_indices: std::collections::HashSet<u32> = existing.iter()
        .filter_map(|t| t.interface.0.strip_prefix("wg").and_then(|n| n.parse().ok()))
        .collect();
    let next_idx = (0u32..).find(|i| !used_indices.contains(i)).unwrap_or(0);
    let iface_name = format!("wg{next_idx}");
    let mut tunnel = WgTunnel::new(req.name, Interface(iface_name), req.listen_port, address);
    if let Some(ref pk) = req.private_key {
        tunnel.private_key = pk.clone();
    }
    tunnel.dns = req.dns;
    tunnel.mtu = req.mtu;
    tunnel.listen_interface = req.listen_interface;
    tunnel.split_routes = req
        .split_routes
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let tunnel = state.vpn_engine.add_wg_tunnel(tunnel).await.map_err(|_| bad_request())?;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: tunnel })))
}

pub async fn update_wg_tunnel(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateWgTunnelRequest>,
) -> Result<Json<ApiResponse<WgTunnel>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let mut tunnel = state.vpn_engine.get_wg_tunnel(uuid).await.map_err(|_| StatusCode::NOT_FOUND)?;
    tunnel.name = req.name;
    tunnel.listen_port = req.listen_port;
    tunnel.address = Address::parse(&req.address).map_err(|_| bad_request())?;
    tunnel.dns = req.dns;
    tunnel.mtu = req.mtu;
    tunnel.listen_interface = req.listen_interface;
    tunnel.split_routes = req
        .split_routes
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    tunnel.updated_at = chrono::Utc::now();
    let tunnel = state.vpn_engine.update_wg_tunnel(tunnel).await.map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: tunnel }))
}

pub async fn delete_wg_tunnel(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    // Stop tunnel if running before deleting
    let _ = state.vpn_engine.stop_tunnel(uuid).await;
    state.vpn_engine.delete_wg_tunnel(uuid).await.map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(MessageResponse { message: format!("WG tunnel {id} deleted") }))
}

pub async fn start_wg_tunnel(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    state.vpn_engine.start_tunnel(uuid).await.map_err(|e| {
        tracing::error!("Failed to start tunnel: {e}");
        internal()
    })?;
    // Apply VPN pf rules and re-inject into the aifw anchor
    let _ = state.vpn_engine.apply_vpn_rules().await;
    if let Ok(vpn_rules) = state.vpn_engine.collect_vpn_rules().await {
        state.rule_engine.set_extra_rules(vpn_rules).await;
        let _ = state.rule_engine.apply_rules().await;
    }
    Ok(Json(MessageResponse { message: "Tunnel started".to_string() }))
}

pub async fn stop_wg_tunnel(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    state.vpn_engine.stop_tunnel(uuid).await.map_err(|_| internal())?;
    Ok(Json(MessageResponse { message: "Tunnel stopped".to_string() }))
}

pub async fn wg_tunnel_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let status = state.vpn_engine.tunnel_status(uuid).await.map_err(|_| internal())?;
    Ok(Json(status))
}

pub async fn next_wg_peer_ip(
    State(state): State<AppState>,
    Path(tunnel_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let tid = Uuid::parse_str(&tunnel_id).map_err(|_| bad_request())?;
    let ip = state.vpn_engine.next_peer_ip(tid).await.map_err(|_| internal())?;
    Ok(Json(serde_json::json!({ "next_ip": ip })))
}

// --- VPN: WireGuard Peers ---

#[derive(Debug, Deserialize)]
pub struct CreateWgPeerRequest {
    pub name: Option<String>,
    pub public_key: Option<String>,
    pub preshared_key: Option<String>,
    pub auto_generate_key: Option<bool>,
    pub endpoint: Option<String>,
    pub allowed_ips: String,
    pub keepalive: Option<u16>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateWgPeerRequest {
    pub name: Option<String>,
    pub endpoint: Option<String>,
    pub allowed_ips: Option<String>,
    pub keepalive: Option<u16>,
    pub preshared_key: Option<String>,
}

pub async fn list_wg_peers(
    State(state): State<AppState>,
    Path(tunnel_id): Path<String>,
) -> Result<Json<ApiResponse<Vec<WgPeer>>>, StatusCode> {
    let uuid = Uuid::parse_str(&tunnel_id).map_err(|_| bad_request())?;
    let peers = state.vpn_engine.list_wg_peers(uuid).await.map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: peers }))
}

pub async fn create_wg_peer(
    State(state): State<AppState>,
    Path(tunnel_id): Path<String>,
    Json(req): Json<CreateWgPeerRequest>,
) -> Result<(StatusCode, Json<ApiResponse<WgPeer>>), StatusCode> {
    let tid = Uuid::parse_str(&tunnel_id).map_err(|_| bad_request())?;
    // Auto-assign IP if allowed_ips is empty or "auto"
    let ips_str = if req.allowed_ips.trim().is_empty() || req.allowed_ips.trim() == "auto" {
        state.vpn_engine.next_peer_ip(tid).await.map_err(|_| bad_request())?
    } else {
        req.allowed_ips.clone()
    };
    let allowed_ips: Vec<Address> = ips_str
        .split(',')
        .map(|s| Address::parse(s.trim()))
        .collect::<aifw_common::Result<Vec<_>>>()
        .map_err(|_| bad_request())?;

    let auto_gen = req.auto_generate_key.unwrap_or(false);
    let mut peer = if auto_gen {
        WgPeer::new_with_generated_key(tid, req.name.unwrap_or_default())
    } else {
        let pk = req.public_key.unwrap_or_default();
        if pk.is_empty() {
            return Err(bad_request());
        }
        WgPeer::new(tid, req.name.unwrap_or_default(), pk)
    };
    peer.allowed_ips = allowed_ips;
    peer.endpoint = req.endpoint;
    peer.persistent_keepalive = req.keepalive;
    peer.preshared_key = req.preshared_key;
    let peer = state.vpn_engine.add_wg_peer(peer).await.map_err(|_| bad_request())?;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: peer })))
}

pub async fn update_wg_peer(
    State(state): State<AppState>,
    Path((_tid, pid)): Path<(String, String)>,
    Json(req): Json<UpdateWgPeerRequest>,
) -> Result<Json<ApiResponse<WgPeer>>, StatusCode> {
    let uuid = Uuid::parse_str(&pid).map_err(|_| bad_request())?;
    let mut peer = state.vpn_engine.get_wg_peer(uuid).await.map_err(|_| StatusCode::NOT_FOUND)?;
    if let Some(name) = req.name { peer.name = name; }
    if let Some(ep) = req.endpoint { peer.endpoint = if ep.is_empty() { None } else { Some(ep) }; }
    if let Some(ref ips) = req.allowed_ips {
        peer.allowed_ips = ips.split(',')
            .map(|s| Address::parse(s.trim()))
            .collect::<aifw_common::Result<Vec<_>>>()
            .map_err(|_| bad_request())?;
    }
    if let Some(ka) = req.keepalive { peer.persistent_keepalive = if ka == 0 { None } else { Some(ka) }; }
    if let Some(psk) = req.preshared_key { peer.preshared_key = if psk.is_empty() { None } else { Some(psk) }; }
    state.vpn_engine.update_wg_peer(&peer).await.map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: peer }))
}

/// Get the WAN IP address for use as WireGuard endpoint in client configs.
async fn get_wan_ip(state: &AppState) -> Option<String> {
    // Find the WAN interface name from interface_roles
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT interface_name FROM interface_roles WHERE role = 'WAN' LIMIT 1"
    ).fetch_optional(&state.pool).await.ok()?;
    let wan_iface = row?.0;
    // Get the IP from ifconfig output
    let output = tokio::process::Command::new("ifconfig")
        .arg(&wan_iface)
        .output()
        .await
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    // Parse "inet X.X.X.X" from ifconfig output
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("inet ")
            && let Some(ip) = rest.split_whitespace().next() {
                return Some(ip.to_string());
            }
    }
    None
}

pub async fn get_peer_config(
    State(state): State<AppState>,
    Path((tid, pid)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let tunnel_id = Uuid::parse_str(&tid).map_err(|_| bad_request())?;
    let peer_id = Uuid::parse_str(&pid).map_err(|_| bad_request())?;
    let tunnel = state.vpn_engine.get_wg_tunnel(tunnel_id).await.map_err(|_| StatusCode::NOT_FOUND)?;
    let peer = state.vpn_engine.get_wg_peer(peer_id).await.map_err(|_| StatusCode::NOT_FOUND)?;
    // Use the WAN IP as the server endpoint (not the tunnel's internal VPN address)
    let server_endpoint = get_wan_ip(&state).await.unwrap_or_else(|| {
        // Fallback: strip CIDR from tunnel address
        let addr = tunnel.address.to_string();
        addr.split('/').next().unwrap_or(&addr).to_string()
    });
    let full_tunnel = peer.to_client_config(&tunnel, &server_endpoint, false);
    let split_tunnel = peer.to_client_config(&tunnel, &server_endpoint, true);
    Ok(Json(serde_json::json!({
        "full_tunnel": full_tunnel,
        "split_tunnel": split_tunnel,
    })))
}

pub async fn delete_wg_peer(
    State(state): State<AppState>,
    Path((_tid, pid)): Path<(String, String)>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&pid).map_err(|_| bad_request())?;
    state.vpn_engine.delete_wg_peer(uuid).await.map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(MessageResponse { message: format!("WG peer {pid} deleted") }))
}

// --- VPN: IPsec ---

#[derive(Debug, Deserialize)]
pub struct CreateIpsecSaRequest {
    pub name: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub protocol: String,
    pub mode: String,
}

pub async fn list_ipsec_sas(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<IpsecSa>>>, StatusCode> {
    let sas = state.vpn_engine.list_ipsec_sas().await.map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: sas }))
}

pub async fn create_ipsec_sa(
    State(state): State<AppState>,
    Json(req): Json<CreateIpsecSaRequest>,
) -> Result<(StatusCode, Json<ApiResponse<IpsecSa>>), StatusCode> {
    let src = Address::parse(&req.local_addr).map_err(|_| bad_request())?;
    let dst = Address::parse(&req.remote_addr).map_err(|_| bad_request())?;
    let protocol = IpsecProtocol::parse(&req.protocol).map_err(|_| bad_request())?;
    let mode = match req.mode.as_str() {
        "transport" => IpsecMode::Transport,
        _ => IpsecMode::Tunnel,
    };
    let sa = IpsecSa::new(req.name, src, dst, protocol, mode);
    let sa = state.vpn_engine.add_ipsec_sa(sa).await.map_err(|_| bad_request())?;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: sa })))
}

pub async fn delete_ipsec_sa(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    state.vpn_engine.delete_ipsec_sa(uuid).await.map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(MessageResponse { message: format!("IPsec SA {id} deleted") }))
}

// --- Static Routes ---

pub async fn list_static_routes(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<StaticRoute>>>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, String, String, Option<String>, i32, bool, Option<String>, String, i64)>(
        "SELECT id, destination, gateway, interface, metric, enabled, description, created_at, COALESCE(fib,0) FROM static_routes ORDER BY fib ASC, metric ASC",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| internal())?;
    let routes: Vec<StaticRoute> = rows.into_iter().map(|(id, dest, gw, iface, metric, enabled, desc, ca, fib)| StaticRoute {
        id, destination: dest, gateway: gw, interface: iface, metric, enabled, description: desc, created_at: ca, fib: fib as u32,
    }).collect();
    Ok(Json(ApiResponse { data: routes }))
}

fn validate_route_target(s: &str) -> Result<(), StatusCode> {
    // Accept IP or CIDR (e.g., "10.0.0.0/8", "192.168.1.1", "default")
    if s == "default" { return Ok(()); }
    if let Some((ip_str, prefix_str)) = s.split_once('/') {
        ip_str.parse::<std::net::IpAddr>().map_err(|_| bad_request())?;
        let prefix: u8 = prefix_str.parse().map_err(|_| bad_request())?;
        if prefix > 128 { return Err(bad_request()); }
    } else {
        s.parse::<std::net::IpAddr>().map_err(|_| bad_request())?;
    }
    Ok(())
}

pub async fn create_static_route(
    State(state): State<AppState>,
    Json(req): Json<CreateRouteRequest>,
) -> Result<(StatusCode, Json<ApiResponse<StaticRoute>>), StatusCode> {
    validate_route_target(&req.destination)?;
    validate_route_target(&req.gateway)?;
    if let Some(ref iface) = req.interface {
        aifw_core::validation::validate_interface_name(iface).map_err(|_| bad_request())?;
    }
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();
    let metric = req.metric.unwrap_or(0);
    let enabled = req.enabled.unwrap_or(true);
    let fib = req.fib.unwrap_or(0);

    sqlx::query(
        "INSERT INTO static_routes (id, destination, gateway, interface, metric, enabled, description, created_at, fib) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
    )
    .bind(&id).bind(&req.destination).bind(&req.gateway).bind(req.interface.as_deref())
    .bind(metric).bind(enabled).bind(req.description.as_deref()).bind(&now).bind(fib as i64)
    .execute(&state.pool)
    .await
    .map_err(|_| bad_request())?;

    // Apply to system if enabled
    if enabled {
        apply_route_to_system(&req.destination, &req.gateway, req.interface.as_deref(), fib).await;
    }

    let route = StaticRoute { id, destination: req.destination, gateway: req.gateway, interface: req.interface, metric, enabled, description: req.description, created_at: now, fib };
    Ok((StatusCode::CREATED, Json(ApiResponse { data: route })))
}

pub async fn update_static_route(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateRouteRequest>,
) -> Result<Json<ApiResponse<StaticRoute>>, StatusCode> {
    validate_route_target(&req.destination)?;
    validate_route_target(&req.gateway)?;
    if let Some(ref iface) = req.interface {
        aifw_core::validation::validate_interface_name(iface).map_err(|_| bad_request())?;
    }
    // Get old route to remove from system
    let old = sqlx::query_as::<_, (String, String, Option<String>, bool, i64)>(
        "SELECT destination, gateway, interface, enabled, COALESCE(fib,0) FROM static_routes WHERE id = ?1",
    )
    .bind(&id).fetch_optional(&state.pool).await.map_err(|_| internal())?
    .ok_or(StatusCode::NOT_FOUND)?;

    if old.3 { // was enabled, remove old route (from the FIB it was in)
        remove_route_from_system(&old.0, &old.1, old.4 as u32).await;
    }

    let metric = req.metric.unwrap_or(0);
    let enabled = req.enabled.unwrap_or(true);
    let fib = req.fib.unwrap_or(0);

    sqlx::query(
        "UPDATE static_routes SET destination = ?2, gateway = ?3, interface = ?4, metric = ?5, enabled = ?6, description = ?7, fib = ?8 WHERE id = ?1",
    )
    .bind(&id).bind(&req.destination).bind(&req.gateway).bind(req.interface.as_deref())
    .bind(metric).bind(enabled).bind(req.description.as_deref()).bind(fib as i64)
    .execute(&state.pool)
    .await
    .map_err(|_| internal())?;

    if enabled {
        apply_route_to_system(&req.destination, &req.gateway, req.interface.as_deref(), fib).await;
    }

    let now = chrono::Utc::now().to_rfc3339();
    let route = StaticRoute { id, destination: req.destination, gateway: req.gateway, interface: req.interface, metric, enabled, description: req.description, created_at: now, fib };
    Ok(Json(ApiResponse { data: route }))
}

pub async fn delete_static_route(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let row = sqlx::query_as::<_, (String, String, bool, i64)>(
        "SELECT destination, gateway, enabled, COALESCE(fib,0) FROM static_routes WHERE id = ?1",
    )
    .bind(&id).fetch_optional(&state.pool).await.map_err(|_| internal())?
    .ok_or(StatusCode::NOT_FOUND)?;

    if row.2 {
        remove_route_from_system(&row.0, &row.1, row.3 as u32).await;
    }

    sqlx::query("DELETE FROM static_routes WHERE id = ?1")
        .bind(&id).execute(&state.pool).await.map_err(|_| internal())?;

    Ok(Json(MessageResponse { message: format!("Route to {} deleted", row.0) }))
}

async fn apply_route_to_system(destination: &str, gateway: &str, interface: Option<&str>, fib: u32) {
    let fib_s = fib.to_string();
    let mut args: Vec<&str> = Vec::new();
    args.push("/sbin/route");
    if fib > 0 {
        args.push("-fib");
        args.push(&fib_s);
    }
    args.push("add");
    args.push(destination);
    args.push(gateway);
    if let Some(iface) = interface {
        args.push("-interface");
        args.push(iface);
    }
    let output = tokio::process::Command::new("/usr/local/bin/sudo")
        .args(&args)
        .output()
        .await;
    match output {
        Ok(o) if o.status.success() => {
            tracing::info!(destination, gateway, fib, "route added");
        }
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            tracing::warn!(destination, gateway, fib, error = %err, "route add failed");
        }
        Err(e) => {
            tracing::warn!(destination, gateway, fib, error = %e, "route command failed");
        }
    }
}

async fn remove_route_from_system(destination: &str, gateway: &str, fib: u32) {
    let fib_s = fib.to_string();
    let mut args: Vec<&str> = Vec::new();
    args.push("/sbin/route");
    if fib > 0 {
        args.push("-fib");
        args.push(&fib_s);
    }
    args.push("delete");
    args.push(destination);
    args.push(gateway);
    let output = tokio::process::Command::new("/usr/local/bin/sudo")
        .args(&args)
        .output()
        .await;
    match output {
        Ok(o) if o.status.success() => {
            tracing::info!(destination, gateway, fib, "route removed");
        }
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr);
            tracing::debug!(destination, gateway, fib, error = %err, "route delete failed (may not exist)");
        }
        Err(e) => {
            tracing::warn!(destination, gateway, fib, error = %e, "route command failed");
        }
    }
}

/// Apply all enabled static routes from the database. Called on API startup.
pub async fn apply_all_routes(pool: &sqlx::SqlitePool) {
    let routes: Vec<(String, String, Option<String>, i64)> = match sqlx::query_as(
        "SELECT destination, gateway, interface, COALESCE(fib,0) FROM static_routes WHERE enabled = 1 ORDER BY fib ASC, metric ASC"
    )
    .fetch_all(pool)
    .await
    {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(error = %e, "failed to load static routes for startup");
            return;
        }
    };

    if routes.is_empty() {
        return;
    }

    tracing::info!(count = routes.len(), "applying static routes on startup");
    for (dest, gw, iface, fib) in &routes {
        apply_route_to_system(dest, gw, iface.as_deref(), *fib as u32).await;
    }
}

// --- System routing table ---

pub async fn get_system_routes(
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<ApiResponse<Vec<SystemRoute>>>, StatusCode> {
    // Optional ?fib=N filter — defaults to main FIB. `netstat -rn -F N` shows
    // only the given FIB; without -F you get FIB 0.
    let fib: u32 = q.get("fib").and_then(|v| v.parse().ok()).unwrap_or(0);
    let fib_s = fib.to_string();
    let mut args: Vec<&str> = vec!["-rn", "-f", "inet"];
    if fib > 0 {
        args.push("-F");
        args.push(&fib_s);
    }
    let output = tokio::process::Command::new("netstat")
        .args(&args)
        .output()
        .await
        .map_err(|_| internal())?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let routes: Vec<SystemRoute> = stdout.lines()
        .skip_while(|l| !l.contains("Destination"))
        .skip(1)
        .filter(|l| !l.is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                Some(SystemRoute {
                    destination: parts[0].to_string(),
                    gateway: parts[1].to_string(),
                    flags: parts[2].to_string(),
                    interface: parts.last().unwrap_or(&"").to_string(),
                })
            } else { None }
        })
        .collect();
    Ok(Json(ApiResponse { data: routes }))
}

// --- Network interfaces ---

pub async fn list_interfaces(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<InterfaceInfo>>>, StatusCode> {
    let output = tokio::process::Command::new("ifconfig")
        .output()
        .await
        .map_err(|_| internal())?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut interfaces = Vec::new();
    let mut current: Option<InterfaceInfo> = None;

    for line in stdout.lines() {
        if !line.starts_with('\t') && !line.starts_with(' ') && line.contains(':') {
            if let Some(iface) = current.take() {
                interfaces.push(iface);
            }
            let name = line.split(':').next().unwrap_or("").to_string();
            let status = if line.contains("UP") { "up" } else { "down" };
            current = Some(InterfaceInfo { name, ipv4: None, ipv6: None, status: status.to_string(), mac: None, role: None });
        }
        if let Some(ref mut iface) = current {
            let trimmed = line.trim();
            if trimmed.starts_with("inet ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    iface.ipv4 = Some(parts[1].to_string());
                }
            }
            if trimmed.starts_with("inet6 ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    iface.ipv6 = Some(parts[1].to_string());
                }
            }
            if trimmed.starts_with("ether ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    iface.mac = Some(parts[1].to_string());
                }
            }
        }
    }
    if let Some(iface) = current {
        interfaces.push(iface);
    }

    // Filter out pseudo-interfaces
    interfaces.retain(|i| !i.name.starts_with("lo") && !i.name.starts_with("pflog") && !i.name.starts_with("enc") && !i.name.starts_with("pfsync"));

    // Add VLANs from DB that aren't already in the system interface list
    if let Ok(vlans) = sqlx::query_as::<_, (i64, String, bool)>(
        "SELECT vlan_id, parent, enabled FROM vlans WHERE enabled = 1"
    ).fetch_all(&state.pool).await {
        for (vid, _parent, _enabled) in vlans {
            let vlan_name = format!("vlan{}", vid);
            if !interfaces.iter().any(|i| i.name == vlan_name) {
                interfaces.push(InterfaceInfo {
                    name: vlan_name,
                    ipv4: None, ipv6: None,
                    status: "down".to_string(),
                    mac: None, role: None,
                });
            }
        }
    }

    // Enrich with roles from DB
    let roles = sqlx::query_as::<_, (String, String)>("SELECT interface_name, role FROM interface_roles")
        .fetch_all(&state.pool).await.unwrap_or_default();
    let role_map: std::collections::HashMap<String, String> = roles.into_iter().collect();
    for iface in &mut interfaces {
        iface.role = role_map.get(&iface.name).cloned();
    }

    Ok(Json(ApiResponse { data: interfaces }))
}

// --- Per-interface stats ---

#[derive(Debug, Serialize)]
pub struct InterfaceStatsResponse {
    pub name: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub errors_in: u64,
    pub errors_out: u64,
}

pub async fn get_interface_stats(
    Path(name): Path<String>,
) -> Result<Json<ApiResponse<InterfaceStatsResponse>>, StatusCode> {
    // Use netstat -I <iface> -b to get byte counters
    let output = tokio::process::Command::new("netstat")
        .args(["-I", &name, "-b", "-n"])
        .output()
        .await
        .map_err(|_| internal())?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut stats = InterfaceStatsResponse {
        name: name.clone(),
        bytes_in: 0, bytes_out: 0, packets_in: 0, packets_out: 0, errors_in: 0, errors_out: 0,
    };

    // Parse netstat -I output: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
    for line in stdout.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Format: Name Mtu Network Address Ipkts Ierrs Idrop Ibytes Opkts Oerrs Obytes Coll
        // Index:  0    1   2       3       4     5     6     7      8     9     10     11
        if parts.len() >= 11 && parts[0] == name {
            stats.packets_in = parts[4].parse().unwrap_or(0);
            stats.errors_in = parts[5].parse().unwrap_or(0);
            stats.bytes_in = parts[7].parse().unwrap_or(0);
            stats.packets_out = parts[8].parse().unwrap_or(0);
            stats.errors_out = parts[9].parse().unwrap_or(0);
            stats.bytes_out = parts[10].parse().unwrap_or(0);
            break;
        }
    }

    Ok(Json(ApiResponse { data: stats }))
}

// --- Valkey settings ---

pub async fn get_valkey_settings(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let enabled = sqlx::query_as::<_, (String,)>("SELECT value FROM auth_config WHERE key = 'valkey_enabled'")
        .fetch_optional(&state.pool).await.ok().flatten()
        .map(|r| r.0 == "true").unwrap_or(true);
    let url = sqlx::query_as::<_, (String,)>("SELECT value FROM auth_config WHERE key = 'valkey_url'")
        .fetch_optional(&state.pool).await.ok().flatten()
        .map(|r| r.0).unwrap_or_else(|| "redis://127.0.0.1:6379".to_string());
    let retention = sqlx::query_as::<_, (String,)>("SELECT value FROM auth_config WHERE key = 'valkey_retention_minutes'")
        .fetch_optional(&state.pool).await.ok().flatten()
        .and_then(|r| r.0.parse::<i64>().ok()).unwrap_or(30);
    let status = if state.redis.is_some() { "connected" } else if !enabled { "disabled" } else { "disconnected" };

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
        let _ = sqlx::query("INSERT OR REPLACE INTO auth_config (key, value) VALUES ('valkey_enabled', ?1)")
            .bind(if enabled { "true" } else { "false" })
            .execute(&state.pool).await;
    }
    if let Some(ref url) = req.url {
        let _ = sqlx::query("INSERT OR REPLACE INTO auth_config (key, value) VALUES ('valkey_url', ?1)")
            .bind(url).execute(&state.pool).await;
    }
    if let Some(retention) = req.retention_minutes {
        let _ = sqlx::query("INSERT OR REPLACE INTO auth_config (key, value) VALUES ('valkey_retention_minutes', ?1)")
            .bind(retention.to_string()).execute(&state.pool).await;
    }

    let status = if state.redis.is_some() { "connected" } else { "disconnected" };
    Ok(Json(serde_json::json!({
        "message": "Valkey settings saved. Restart API to apply connection changes.",
        "status": status,
    })))
}

// --- Dashboard History Settings ---

/// Average bytes per slim history entry (status + system + interfaces + services JSON).
const HISTORY_ENTRY_BYTES: usize = 2048;

pub async fn get_dashboard_history_settings(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let current = state.metrics_history_max.load(std::sync::atomic::Ordering::Relaxed);
    let buf_len = state.metrics_history.read().await.len();
    let estimated_ram_mb = (current as f64 * HISTORY_ENTRY_BYTES as f64) / (1024.0 * 1024.0);
    let mode = sqlx::query_as::<_, (String,)>(
        "SELECT value FROM auth_config WHERE key = 'dashboard_history_mode'"
    )
    .fetch_optional(&state.pool).await.ok().flatten()
    .map(|r| r.0).unwrap_or_else(|| "duration".to_string());
    let ram_limit_mb = sqlx::query_as::<_, (String,)>(
        "SELECT value FROM auth_config WHERE key = 'dashboard_history_ram_mb'"
    )
    .fetch_optional(&state.pool).await.ok().flatten()
    .and_then(|r| r.0.parse::<f64>().ok()).unwrap_or(0.0);

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
    let mode = req.get("mode").and_then(|v| v.as_str()).unwrap_or("duration");

    let seconds = match mode {
        "ram" => {
            // User specifies MB budget — we calculate how many entries fit
            let ram_mb = req.get("ram_limit_mb")
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

    // Clamp: min 5 minutes (300), max 30 days (2592000)
    let clamped = seconds.clamp(300, 2_592_000);

    let _ = sqlx::query("INSERT OR REPLACE INTO auth_config (key, value) VALUES ('dashboard_history_seconds', ?1)")
        .bind(clamped.to_string())
        .execute(&state.pool).await;
    let _ = sqlx::query("INSERT OR REPLACE INTO auth_config (key, value) VALUES ('dashboard_history_mode', ?1)")
        .bind(mode)
        .execute(&state.pool).await;

    state.metrics_history_max.store(clamped, std::sync::atomic::Ordering::Relaxed);

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
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT key, value FROM auth_config WHERE key LIKE ?1"
    ).bind(format!("{prefix}%")).fetch_all(&state.pool).await.map_err(|_| internal())?;
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
                .bind(&db_key).bind(&val).execute(&state.pool).await;
        }
    }
    Ok(Json(MessageResponse { message: format!("{section} settings saved") }))
}

// --- IDS Alert Buffer Settings ---

pub async fn get_ids_alert_settings(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let stats = state.alert_buffer.stats().await;
    let (max_mb, max_age) = state.alert_buffer.limits();
    Ok(Json(serde_json::json!({
        "max_mb": max_mb,
        "max_age_secs": max_age,
        "stats": stats.to_json(),
    })))
}

pub async fn update_ids_alert_settings(
    State(state): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    if let Some(mb) = req.get("max_mb").and_then(|v| v.as_u64()) {
        let mb = (mb as usize).clamp(8, 512);
        state.alert_buffer.set_max_mb(mb);
        let _ = sqlx::query("INSERT OR REPLACE INTO auth_config (key, value) VALUES ('ids_alert_max_mb', ?1)")
            .bind(mb.to_string()).execute(&state.pool).await;
    }
    if let Some(secs) = req.get("max_age_secs").and_then(|v| v.as_u64()) {
        let secs = (secs as usize).clamp(3600, 604800); // 1h to 7 days
        state.alert_buffer.set_max_age_secs(secs);
        let _ = sqlx::query("INSERT OR REPLACE INTO auth_config (key, value) VALUES ('ids_alert_max_age_secs', ?1)")
            .bind(secs.to_string()).execute(&state.pool).await;
    }
    state.alert_buffer.trim().await;
    let stats = state.alert_buffer.stats().await;
    Ok(Json(serde_json::json!({
        "message": "IDS alert settings updated",
        "stats": stats.to_json(),
    })))
}

// --- AI Provider Settings ---

pub async fn get_ai_settings(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    async fn get_val(pool: &sqlx::SqlitePool, key: &str) -> Option<String> {
        sqlx::query_as::<_, (String,)>("SELECT value FROM auth_config WHERE key = ?1")
            .bind(key).fetch_optional(pool).await.ok().flatten().map(|r| r.0)
    }

    let pool = &state.pool;
    let providers = ["openai", "claude", "lm_studio", "ollama"];
    let mut configs = Vec::new();

    for p in &providers {
        let enabled = get_val(pool, &format!("ai_{p}_enabled")).await.map(|v| v == "true").unwrap_or(false);
        let api_key = get_val(pool, &format!("ai_{p}_api_key")).await.unwrap_or_default();
        let endpoint = get_val(pool, &format!("ai_{p}_endpoint")).await.unwrap_or_default();
        let model = get_val(pool, &format!("ai_{p}_model")).await.unwrap_or_default();

        configs.push(serde_json::json!({
            "provider": p,
            "enabled": enabled,
            "api_key_set": !api_key.is_empty(),
            "endpoint": endpoint,
            "model": model,
        }));
    }

    let global_enabled = get_val(pool, "ai_enabled").await.map(|v| v == "true").unwrap_or(false);
    let active_provider = get_val(pool, "ai_active_provider").await.unwrap_or_default();

    Ok(Json(serde_json::json!({
        "enabled": global_enabled,
        "active_provider": active_provider,
        "providers": configs,
    })))
}

#[derive(Debug, Deserialize)]
pub struct UpdateAiSettingsRequest {
    pub enabled: Option<bool>,
    pub active_provider: Option<String>,
    pub provider: Option<String>,
    pub api_key: Option<String>,
    pub endpoint: Option<String>,
    pub model: Option<String>,
    pub provider_enabled: Option<bool>,
}

pub async fn update_ai_settings(
    State(state): State<AppState>,
    Json(req): Json<UpdateAiSettingsRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    async fn save_val(pool: &sqlx::SqlitePool, key: &str, val: &str) {
        let _ = sqlx::query("INSERT OR REPLACE INTO auth_config (key, value) VALUES (?1, ?2)")
            .bind(key).bind(val).execute(pool).await;
    }

    let pool = &state.pool;

    if let Some(enabled) = req.enabled {
        save_val(pool, "ai_enabled", if enabled { "true" } else { "false" }).await;
    }
    if let Some(ref active) = req.active_provider {
        save_val(pool, "ai_active_provider", active).await;
    }

    if let Some(ref provider) = req.provider {
        let valid = ["openai", "claude", "lm_studio", "ollama"];
        if !valid.contains(&provider.as_str()) {
            return Err(bad_request());
        }
        if let Some(ref key) = req.api_key {
            save_val(pool, &format!("ai_{provider}_api_key"), key).await;
        }
        if let Some(ref endpoint) = req.endpoint {
            save_val(pool, &format!("ai_{provider}_endpoint"), endpoint).await;
        }
        if let Some(ref model) = req.model {
            save_val(pool, &format!("ai_{provider}_model"), model).await;
        }
        if let Some(enabled) = req.provider_enabled {
            save_val(pool, &format!("ai_{provider}_enabled"), if enabled { "true" } else { "false" }).await;
        }
    }

    Ok(Json(serde_json::json!({ "message": "AI settings saved" })))
}

// --- AI HTTP helpers (curl with fetch fallback for FreeBSD) ---

async fn http_get_status(url: &str, auth: &str, provider: &str) -> Result<(String, bool), String> {
    // Try curl first, fall back to fetch (FreeBSD built-in)
    let result = if let Ok(output) = build_curl_status(url, auth, provider).await {
        output
    } else if let Ok(output) = build_fetch_status(url).await {
        output
    } else {
        return Err("No HTTP client available".to_string());
    };
    Ok(result)
}

async fn build_curl_status(url: &str, auth: &str, provider: &str) -> Result<(String, bool), String> {
    let mut args: Vec<String> = vec!["-sk", "--connect-timeout", "5", "-o", "/dev/null", "-w", "%{http_code}"]
        .into_iter().map(String::from).collect();
    if !auth.is_empty() {
        if provider == "claude" {
            args.extend(["-H".to_string(), format!("x-api-key: {auth}"), "-H".to_string(), "anthropic-version: 2023-06-01".to_string()]);
        } else {
            args.extend(["-H".to_string(), format!("Authorization: {auth}")]);
        }
    }
    args.push(url.to_string());
    let output = tokio::process::Command::new("curl")
        .args(&args).output().await.map_err(|e| e.to_string())?;
    if !output.status.success() && output.stdout.is_empty() {
        return Err("curl failed".to_string());
    }
    let code = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let ok = code.starts_with('2');
    Ok((code, ok))
}

async fn build_fetch_status(url: &str) -> Result<(String, bool), String> {
    // FreeBSD fetch: -o /dev/null returns 0 on success
    let output = tokio::process::Command::new("/usr/bin/fetch")
        .args(["-T", "5", "-o", "/dev/null", url])
        .output().await.map_err(|e| e.to_string())?;
    let ok = output.status.success();
    Ok((if ok { "200".to_string() } else { "000".to_string() }, ok))
}

async fn http_get_body(url: &str, auth: &str, provider: &str) -> Result<String, String> {
    // Try curl first
    if let Ok(body) = build_curl_body(url, auth, provider).await {
        return Ok(body);
    }
    // Fallback to fetch
    let output = tokio::process::Command::new("/usr/bin/fetch")
        .args(["-T", "5", "-qo", "-", url])
        .output().await.map_err(|e| e.to_string())?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

async fn build_curl_body(url: &str, auth: &str, provider: &str) -> Result<String, String> {
    let mut args: Vec<String> = vec!["-sk", "--connect-timeout", "5"]
        .into_iter().map(String::from).collect();
    if !auth.is_empty() {
        if provider == "claude" {
            args.extend(["-H".to_string(), format!("x-api-key: {auth}"), "-H".to_string(), "anthropic-version: 2023-06-01".to_string()]);
        } else {
            args.extend(["-H".to_string(), format!("Authorization: {auth}")]);
        }
    }
    args.push(url.to_string());
    let output = tokio::process::Command::new("curl")
        .args(&args).output().await.map_err(|e| e.to_string())?;
    if !output.status.success() && output.stdout.is_empty() {
        return Err("curl not available".to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// --- AI Provider Model List & Connection Test ---

pub async fn test_ai_provider(
    State(state): State<AppState>,
    Json(req): Json<serde_json::Value>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let provider = req.get("provider").and_then(|v| v.as_str()).ok_or(bad_request())?;
    let pool = &state.pool;

    // Load provider config
    async fn get_val(pool: &sqlx::SqlitePool, key: &str) -> String {
        sqlx::query_as::<_, (String,)>("SELECT value FROM auth_config WHERE key = ?1")
            .bind(key).fetch_optional(pool).await.ok().flatten().map(|r| r.0).unwrap_or_default()
    }

    let api_key = get_val(pool, &format!("ai_{provider}_api_key")).await;
    let endpoint = get_val(pool, &format!("ai_{provider}_endpoint")).await;
    let model = get_val(pool, &format!("ai_{provider}_model")).await;

    // Allow request overrides for testing before saving
    let endpoint = req.get("endpoint").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or(endpoint);
    let api_key = req.get("api_key").and_then(|v| v.as_str()).map(|s| s.to_string()).unwrap_or(api_key);

    if endpoint.is_empty() {
        return Ok(Json(serde_json::json!({ "success": false, "error": "No endpoint configured" })));
    }

    // Build the models URL based on provider type
    let (models_url, auth_header) = match provider {
        "openai" | "lm_studio" => {
            let url = format!("{}/models", endpoint.trim_end_matches('/'));
            let auth = if api_key.is_empty() { String::new() } else { format!("Bearer {api_key}") };
            (url, auth)
        }
        "claude" => {
            // Anthropic doesn't have a /models endpoint — just test with a minimal message
            let url = format!("{}/v1/messages", endpoint.trim_end_matches('/'));
            let auth = api_key.clone();
            (url, auth)
        }
        "ollama" => {
            let url = format!("{}/api/tags", endpoint.trim_end_matches('/'));
            (url, String::new())
        }
        _ => return Err(bad_request()),
    };

    // Test connectivity — try curl, fall back to fetch (FreeBSD built-in)
    let (status_code, success) = match http_get_status(&models_url, &auth_header, provider).await {
        Ok((code, ok)) => (code, ok),
        Err(_) => return Err(internal()),
    };

    Ok(Json(serde_json::json!({
        "success": success,
        "status_code": status_code,
        "endpoint": endpoint,
        "model": model,
    })))
}

pub async fn list_ai_models(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let provider = q.get("provider").ok_or(bad_request())?;
    let pool = &state.pool;

    async fn get_val(pool: &sqlx::SqlitePool, key: &str) -> String {
        sqlx::query_as::<_, (String,)>("SELECT value FROM auth_config WHERE key = ?1")
            .bind(key).fetch_optional(pool).await.ok().flatten().map(|r| r.0).unwrap_or_default()
    }

    let api_key = get_val(pool, &format!("ai_{provider}_api_key")).await;
    let endpoint = get_val(pool, &format!("ai_{provider}_endpoint")).await;

    if endpoint.is_empty() {
        return Ok(Json(serde_json::json!({ "models": [], "error": "No endpoint configured" })));
    }

    let (url, auth_args): (String, Vec<String>) = match provider.as_str() {
        "openai" | "lm_studio" => {
            let url = format!("{}/models", endpoint.trim_end_matches('/'));
            let mut a = vec![];
            if !api_key.is_empty() {
                a.push("-H".to_string());
                a.push(format!("Authorization: Bearer {api_key}"));
            }
            (url, a)
        }
        "ollama" => {
            let url = format!("{}/api/tags", endpoint.trim_end_matches('/'));
            (url, vec![])
        }
        "claude" => {
            // Anthropic doesn't expose a models list API — return known models
            return Ok(Json(serde_json::json!({
                "models": [
                    "claude-sonnet-4-20250514",
                    "claude-opus-4-20250514",
                    "claude-haiku-4-20250414",
                    "claude-3-5-sonnet-20241022",
                    "claude-3-5-haiku-20241022"
                ]
            })));
        }
        _ => return Err(bad_request()),
    };

    let auth = if auth_args.len() >= 2 { auth_args[1].clone() } else { String::new() };
    let body = http_get_body(&url, &auth, provider.as_str()).await.unwrap_or_default();

    // Parse response — OpenAI returns { data: [{id: "model-name"}, ...] }, Ollama returns { models: [{name: "model"}, ...] }
    let models: Vec<String> = if let Ok(json) = serde_json::from_str::<serde_json::Value>(&body) {
        if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
            data.iter().filter_map(|m| m.get("id").and_then(|v| v.as_str()).map(|s| s.to_string())).collect()
        } else if let Some(models) = json.get("models").and_then(|d| d.as_array()) {
            models.iter().filter_map(|m| m.get("name").and_then(|v| v.as_str()).map(|s| s.to_string())).collect()
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    Ok(Json(serde_json::json!({ "models": models })))
}

// --- TLS Policy Settings ---

pub async fn get_tls_settings(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let pool = &state.pool;
    let min_ver = sqlx::query_as::<_, (String,)>("SELECT value FROM auth_config WHERE key = 'tls_min_version'")
        .fetch_optional(pool).await.ok().flatten().map(|r| r.0).unwrap_or_else(|| "tls12".to_string());
    let block_expired = sqlx::query_as::<_, (String,)>("SELECT value FROM auth_config WHERE key = 'tls_block_expired'")
        .fetch_optional(pool).await.ok().flatten().map(|r| r.0 == "true").unwrap_or(true);
    let block_weak = sqlx::query_as::<_, (String,)>("SELECT value FROM auth_config WHERE key = 'tls_block_weak_keys'")
        .fetch_optional(pool).await.ok().flatten().map(|r| r.0 == "true").unwrap_or(true);
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
        let _ = sqlx::query("INSERT OR REPLACE INTO auth_config (key, value) VALUES ('tls_min_version', ?1)")
            .bind(v).execute(&state.pool).await;
    }
    if let Some(v) = req.get("block_expired").and_then(|v| v.as_bool()) {
        let _ = sqlx::query("INSERT OR REPLACE INTO auth_config (key, value) VALUES ('tls_block_expired', ?1)")
            .bind(if v { "true" } else { "false" }).execute(&state.pool).await;
    }
    if let Some(v) = req.get("block_weak_keys").and_then(|v| v.as_bool()) {
        let _ = sqlx::query("INSERT OR REPLACE INTO auth_config (key, value) VALUES ('tls_block_weak_keys', ?1)")
            .bind(if v { "true" } else { "false" }).execute(&state.pool).await;
    }
    Ok(Json(MessageResponse { message: "TLS policy saved".to_string() }))
}

pub async fn update_dns(
    State(state): State<AppState>,
    Json(req): Json<DnsConfigRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    // Validate all entries are valid IPs
    for server in &req.servers {
        if server.parse::<std::net::IpAddr>().is_err() {
            return Err(bad_request());
        }
    }

    // Persist to DB so settings survive DHCP renewal / network changes
    let dns_json = serde_json::to_string(&req.servers).unwrap_or_default();
    let _ = sqlx::query("INSERT OR REPLACE INTO auth_config (key, value) VALUES ('dns_servers', ?1)")
        .bind(&dns_json).execute(&state.pool).await;

    let content: String = req
        .servers
        .iter()
        .map(|s| format!("nameserver {s}"))
        .collect::<Vec<_>>()
        .join("\n");

    // Write via sudo tee — aifw user can't write root-owned /etc/resolv.conf
    let mut child = tokio::process::Command::new("/usr/local/bin/sudo")
        .args(["tee", "/etc/resolv.conf"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .map_err(|_| internal())?;

    if let Some(ref mut stdin) = child.stdin {
        use tokio::io::AsyncWriteExt;
        stdin.write_all(content.as_bytes()).await.map_err(|_| internal())?;
    }
    child.wait().await.map_err(|_| internal())?;

    Ok(Json(MessageResponse {
        message: "DNS configuration updated".to_string(),
    }))
}

// ============================================================
// Role management + /auth/me
// ============================================================

pub async fn get_current_user(
    State(state): State<AppState>,
    request: axum::extract::Request,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let auth_user = request.extensions().get::<auth::AuthUser>()
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let user = auth::get_user_by_id(&state.pool, &auth_user.user_id).await?
        .ok_or(StatusCode::NOT_FOUND)?;

    let perms = auth_user.permissions.to_strings();

    Ok(Json(serde_json::json!({
        "id": user.id,
        "username": user.username,
        "role": auth_user.role,
        "role_id": user.role_id,
        "permissions": perms,
        "totp_enabled": user.totp_enabled,
        "auth_provider": user.auth_provider,
    })))
}

pub async fn list_permissions() -> Json<serde_json::Value> {
    use aifw_common::permission::ALL_PERMISSIONS;
    let perms: Vec<serde_json::Value> = ALL_PERMISSIONS.iter().map(|p| {
        let s = p.as_str();
        let parts: Vec<&str> = s.split(':').collect();
        serde_json::json!({
            "key": s,
            "category": parts.first().unwrap_or(&""),
            "action": parts.get(1).unwrap_or(&""),
        })
    }).collect();
    Json(serde_json::json!({ "permissions": perms }))
}

pub async fn list_roles(
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, String, i64, bool, Option<String>, String)>(
        "SELECT id, name, permissions, builtin, description, created_at FROM roles ORDER BY builtin DESC, name ASC",
    )
    .fetch_all(&state.pool)
    .await
    .map_err(|_| internal())?;

    let roles: Vec<serde_json::Value> = rows.into_iter().map(|(id, name, perms, builtin, desc, created)| {
        let perm_set = aifw_common::PermissionSet::from_bits(perms as u64);
        serde_json::json!({
            "id": id,
            "name": name,
            "permissions": perm_set.to_strings(),
            "permission_bits": perms,
            "builtin": builtin,
            "description": desc,
            "created_at": created,
        })
    }).collect();

    Ok(Json(serde_json::json!({ "roles": roles })))
}

#[derive(Debug, Deserialize)]
pub struct CreateRoleRequest {
    pub name: String,
    pub permissions: Vec<String>,
    pub description: Option<String>,
}

pub async fn create_role(
    State(state): State<AppState>,
    Json(req): Json<CreateRoleRequest>,
) -> Result<(StatusCode, Json<serde_json::Value>), StatusCode> {
    if req.name.trim().is_empty() {
        return Err(bad_request());
    }
    let str_refs: Vec<&str> = req.permissions.iter().map(|s| s.as_str()).collect();
    let perm_set = aifw_common::PermissionSet::from_strings(&str_refs);
    let id = uuid::Uuid::new_v4().to_string();

    sqlx::query(
        "INSERT INTO roles (id, name, permissions, builtin, description) VALUES (?1, ?2, ?3, 0, ?4)"
    )
    .bind(&id)
    .bind(req.name.trim())
    .bind(perm_set.to_bits() as i64)
    .bind(req.description.as_deref())
    .execute(&state.pool)
    .await
    .map_err(|_| StatusCode::CONFLICT)?;

    Ok((StatusCode::CREATED, Json(serde_json::json!({
        "id": id,
        "name": req.name.trim(),
        "permissions": perm_set.to_strings(),
        "builtin": false,
    }))))
}

#[derive(Debug, Deserialize)]
pub struct UpdateRoleRequest {
    pub name: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub description: Option<String>,
}

pub async fn update_role(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<UpdateRoleRequest>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Prevent editing built-in roles' permissions
    let row = sqlx::query_as::<_, (bool,)>("SELECT builtin FROM roles WHERE id = ?1")
        .bind(&id).fetch_optional(&state.pool).await
        .map_err(|_| internal())?
        .ok_or(StatusCode::NOT_FOUND)?;

    if row.0 {
        // Built-in: only allow description update
        if req.permissions.is_some() || req.name.is_some() {
            return Err(StatusCode::FORBIDDEN);
        }
        if let Some(ref desc) = req.description {
            sqlx::query("UPDATE roles SET description = ?2 WHERE id = ?1")
                .bind(&id).bind(desc)
                .execute(&state.pool).await
                .map_err(|_| internal())?;
        }
    } else {
        if let Some(ref name) = req.name {
            sqlx::query("UPDATE roles SET name = ?2 WHERE id = ?1")
                .bind(&id).bind(name.trim())
                .execute(&state.pool).await
                .map_err(|_| internal())?;
        }
        if let Some(ref perms) = req.permissions {
            let str_refs: Vec<&str> = perms.iter().map(|s| s.as_str()).collect();
            let perm_set = aifw_common::PermissionSet::from_strings(&str_refs);
            sqlx::query("UPDATE roles SET permissions = ?2 WHERE id = ?1")
                .bind(&id).bind(perm_set.to_bits() as i64)
                .execute(&state.pool).await
                .map_err(|_| internal())?;
        }
        if let Some(ref desc) = req.description {
            sqlx::query("UPDATE roles SET description = ?2 WHERE id = ?1")
                .bind(&id).bind(desc)
                .execute(&state.pool).await
                .map_err(|_| internal())?;
        }
    }

    Ok(Json(serde_json::json!({ "message": "Role updated" })))
}

pub async fn delete_role(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    // Prevent deleting built-in roles
    let row = sqlx::query_as::<_, (bool,)>("SELECT builtin FROM roles WHERE id = ?1")
        .bind(&id).fetch_optional(&state.pool).await
        .map_err(|_| internal())?
        .ok_or(StatusCode::NOT_FOUND)?;

    if row.0 {
        return Err(StatusCode::FORBIDDEN);
    }

    // Check no users reference this role
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users WHERE role_id = ?1")
        .bind(&id).fetch_one(&state.pool).await
        .map_err(|_| internal())?;
    if count.0 > 0 {
        return Err(StatusCode::CONFLICT);
    }

    sqlx::query("DELETE FROM roles WHERE id = ?1")
        .bind(&id).execute(&state.pool).await
        .map_err(|_| internal())?;

    Ok(Json(MessageResponse { message: "Role deleted".to_string() }))
}
