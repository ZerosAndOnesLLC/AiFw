//! `/api/v1/auth` handlers — login, TOTP enrolment and second-factor
//! login, token refresh/logout, auth settings, OAuth provider config,
//! first-user registration, and API-key minting.
//!
//! `crate::auth` (the auth engine) is imported explicitly below; it
//! shadows the `auth` module re-exported by the `use super::*` wildcard.

use super::*;
use crate::auth;

pub async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<auth::LoginRequest>,
) -> Result<Json<auth::LoginResponse>, StatusCode> {
    // Rate-limit on two axes: the X-Forwarded-For-ish client IP (best
    // effort — spoofable without a trusted-proxies allow-list, tracked
    // as a follow-up) AND the username. The username axis guarantees a
    // password-spray against one account still gets limited even if
    // the attacker rotates XFF per request.
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| format!("user:{}", req.username));
    let rl_user = req.username.to_ascii_lowercase();

    if state.login_limiter.is_blocked(&client_ip, &rl_user).await {
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
        auth::log_user_audit(
            &state.pool,
            &user.id.to_string(),
            Some(&user.id.to_string()),
            "login_denied_disabled",
            Some(&req.username),
        )
        .await;
        return Err(StatusCode::UNAUTHORIZED);
    }

    if !password_valid {
        auth::log_user_audit(
            &state.pool,
            &user.id.to_string(),
            Some(&user.id.to_string()),
            "login_failed",
            Some(&req.username),
        )
        .await;
        state
            .login_limiter
            .record_failure(&client_ip, &rl_user)
            .await;
        return Err(StatusCode::UNAUTHORIZED);
    }

    state.login_limiter.clear(&client_ip, &rl_user).await;

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
    let (perm_bits, role_name) =
        auth::tokens::resolve_token_permissions(&state.pool, &user.role, user.role_id.as_deref())
            .await
            .map_err(|_| internal())?;

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

    auth::log_user_audit(
        &state.pool,
        &user.id.to_string(),
        Some(&user.id.to_string()),
        "login_success",
        Some(&user.username),
    )
    .await;

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
    let (perm_bits, role_name) =
        auth::tokens::resolve_token_permissions(&state.pool, &user.role, user.role_id.as_deref())
            .await
            .map_err(|_| internal())?;

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
    headers: HeaderMap,
    Json(req): Json<auth::tokens::RefreshRequest>,
) -> Result<Json<auth::TokenPair>, StatusCode> {
    // SEC-H8: rate-limit refresh like login. Key on the client IP (best
    // effort, spoofable without a trusted-proxy allow-list) and on the
    // token prefix so a spray of forged tokens from one source is capped.
    // Falling back to the prefix as the IP key when there's no XFF avoids a
    // single shared global bucket that would block unrelated clients.
    let token_prefix = auth::tokens::refresh_prefix(&req.refresh_token).to_string();
    let client_ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| format!("rfx:{token_prefix}"));

    if state
        .login_limiter
        .is_blocked(&client_ip, &token_prefix)
        .await
    {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    let tokens = match auth::tokens::rotate_refresh_token(
        &state.pool,
        &req.refresh_token,
        &state.auth_settings,
    )
    .await
    {
        Ok(t) => t,
        Err(_) => {
            state
                .login_limiter
                .record_failure(&client_ip, &token_prefix)
                .await;
            return Err(StatusCode::UNAUTHORIZED);
        }
    };

    state.login_limiter.clear(&client_ip, &token_prefix).await;
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
        && let Ok(data) = auth::verify_access_token(token, &state.auth_settings)
    {
        let exp = chrono::DateTime::from_timestamp(data.claims.exp, 0)
            .map(|d| d.to_rfc3339())
            .unwrap_or_default();
        let _ = auth::revoke_access_token(&state.pool, &data.claims.jti, &exp).await;
        // PERF-C12: invalidate the JTI cache so the just-revoked token
        // can't ride the positive-cache TTL.
        state.auth_jti_cache.remove(&data.claims.jti);
    }
    Ok(Json(MessageResponse {
        message: "Logged out".to_string(),
    }))
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
    Ok(Json(MessageResponse {
        message: "TOTP enabled".to_string(),
    }))
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
    Ok(Json(MessageResponse {
        message: "TOTP disabled".to_string(),
    }))
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
        auth::config::AuthSettings::save_setting(
            &state.pool,
            "access_token_expiry_mins",
            &v.to_string(),
        )
        .await
        .map_err(|_| internal())?;
    }
    if let Some(v) = req.refresh_token_expiry_days {
        auth::config::AuthSettings::save_setting(
            &state.pool,
            "refresh_token_expiry_days",
            &v.to_string(),
        )
        .await
        .map_err(|_| internal())?;
    }
    if let Some(v) = req.require_totp {
        auth::config::AuthSettings::save_setting(&state.pool, "require_totp", &v.to_string())
            .await
            .map_err(|_| internal())?;
    }
    if let Some(v) = req.require_totp_for_oauth {
        auth::config::AuthSettings::save_setting(
            &state.pool,
            "require_totp_for_oauth",
            &v.to_string(),
        )
        .await
        .map_err(|_| internal())?;
    }
    if let Some(v) = req.auto_create_oauth_users {
        auth::config::AuthSettings::save_setting(
            &state.pool,
            "auto_create_oauth_users",
            &v.to_string(),
        )
        .await
        .map_err(|_| internal())?;
    }
    if let Some(v) = req.max_login_attempts {
        auth::config::AuthSettings::save_setting(&state.pool, "max_login_attempts", &v.to_string())
            .await
            .map_err(|_| internal())?;
    }
    if let Some(v) = req.lockout_duration_secs {
        auth::config::AuthSettings::save_setting(
            &state.pool,
            "lockout_duration_secs",
            &v.to_string(),
        )
        .await
        .map_err(|_| internal())?;
    }
    if let Some(v) = req.allow_registration {
        auth::config::AuthSettings::save_setting(&state.pool, "allow_registration", &v.to_string())
            .await
            .map_err(|_| internal())?;
    }
    if let Some(v) = req.password_min_length {
        auth::config::AuthSettings::save_setting(
            &state.pool,
            "password_min_length",
            &v.to_string(),
        )
        .await
        .map_err(|_| internal())?;
    }
    Ok(Json(MessageResponse {
        message: "Settings updated".to_string(),
    }))
}

pub async fn list_oauth_providers(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<auth::oauth::OAuthProvider>>>, StatusCode> {
    let providers = auth::oauth::list_providers(&state.pool)
        .await
        .map_err(|_| internal())?;
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
            scopes: req
                .scopes
                .unwrap_or_else(|| "openid email profile".to_string()),
            enabled: true,
            created_at: chrono::Utc::now().to_rfc3339(),
        },
    };

    auth::oauth::save_provider(&state.pool, &provider)
        .await
        .map_err(|_| internal())?;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: provider })))
}

pub async fn delete_oauth_provider(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    auth::oauth::delete_provider(&state.pool, uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(MessageResponse {
        message: format!("Provider {id} deleted"),
    }))
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
    // SEC-H9: bind this state nonce so the callback can prove it originated
    // from an authorize request this server issued.
    auth::oauth::save_state(&state.pool, &oauth_state, &provider_name)
        .await
        .map_err(|_| internal())?;
    let redirect_uri = format!("/api/v1/auth/oauth/{}/callback", provider_name);
    let url = provider.authorize_url(&redirect_uri, &oauth_state);

    Ok(Json(auth::oauth::AuthorizeResponse {
        authorize_url: url,
        state: oauth_state,
    }))
}

pub async fn oauth_callback(
    State(state): State<AppState>,
    Path(provider_name): Path<String>,
    axum::extract::Query(query): axum::extract::Query<auth::oauth::CallbackQuery>,
) -> Result<Json<MessageResponse>, StatusCode> {
    // Validate required parameters are present
    if query.code.is_empty() {
        return Err(bad_request());
    }
    if query.state.is_empty() {
        return Err(bad_request());
    }
    // SEC-H9: the state nonce must match one we issued at /authorize for this
    // provider and be unexpired. consume_state deletes it (single-use), so a
    // replayed or forged callback is rejected before any token exchange.
    if !auth::oauth::consume_state(&state.pool, &query.state, &provider_name).await {
        return Err(StatusCode::UNAUTHORIZED);
    }
    // State is valid, but the token exchange itself is not yet implemented
    // (tracked in #170) — return 501 until that lands.
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
    auth::validate_password(&admin_req.password, state.auth_settings.password_min_length)?;
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

/// Pull the authenticated user's id out of a `Bearer` token. Shared with
/// `routes::users`, which needs the actor id for audit entries.
pub(super) fn extract_user_id(headers: &HeaderMap, state: &AppState) -> Result<String, StatusCode> {
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
