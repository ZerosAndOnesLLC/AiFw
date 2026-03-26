use chrono::{Duration, Utc};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use uuid::Uuid;

use super::config::AuthSettings;
use super::password::hash_password;

// ============================================================
// JWT Access Tokens
// ============================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String, // unique token ID
}

#[derive(Debug, Serialize)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: String,
    pub refresh_expires_at: String,
    pub token_type: String,
}

pub fn create_access_token(
    user_id: &str,
    username: &str,
    settings: &AuthSettings,
) -> Result<(String, String), String> {
    let now = Utc::now();
    let exp = now + Duration::minutes(settings.access_token_expiry_mins);
    let jti = Uuid::new_v4().to_string();

    let claims = Claims {
        sub: user_id.to_string(),
        username: username.to_string(),
        exp: exp.timestamp(),
        iat: now.timestamp(),
        jti: jti.clone(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(settings.jwt_secret.as_bytes()),
    )
    .map_err(|e| format!("token encode error: {e}"))?;

    Ok((token, exp.to_rfc3339()))
}

pub fn verify_access_token(
    token: &str,
    settings: &AuthSettings,
) -> Result<TokenData<Claims>, String> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(settings.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|e| format!("token verify error: {e}"))
}

// ============================================================
// Refresh Tokens (DB-backed with rotation + family tracking)
// ============================================================

pub async fn create_refresh_token(
    pool: &SqlitePool,
    user_id: &str,
    settings: &AuthSettings,
) -> Result<(String, String), String> {
    let raw_token = format!("rfx_{}", Uuid::new_v4().to_string().replace('-', ""));
    let token_hash = hash_password(&raw_token).map_err(|_| "hash error".to_string())?;
    let family_id = Uuid::new_v4().to_string();
    let expires = Utc::now() + Duration::days(settings.refresh_token_expiry_days);
    let id = Uuid::new_v4().to_string();

    sqlx::query(
        r#"INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at, revoked, created_at)
           VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)"#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&token_hash)
    .bind(&family_id)
    .bind(expires.to_rfc3339())
    .bind(Utc::now().to_rfc3339())
    .execute(pool)
    .await
    .map_err(|e| format!("db error: {e}"))?;

    Ok((raw_token, expires.to_rfc3339()))
}

/// Issue a full token pair (access + refresh)
pub async fn issue_token_pair(
    pool: &SqlitePool,
    user_id: &str,
    username: &str,
    settings: &AuthSettings,
) -> Result<TokenPair, String> {
    let (access_token, access_expires) = create_access_token(user_id, username, settings)?;
    let (refresh_token, refresh_expires) = create_refresh_token(pool, user_id, settings).await?;

    Ok(TokenPair {
        access_token,
        refresh_token,
        access_expires_at: access_expires,
        refresh_expires_at: refresh_expires,
        token_type: "Bearer".to_string(),
    })
}

/// Rotate a refresh token: validate the old one, revoke it, issue a new one.
/// If the old token was already revoked (reuse detected), revoke the entire family.
pub async fn rotate_refresh_token(
    pool: &SqlitePool,
    old_token: &str,
    settings: &AuthSettings,
) -> Result<TokenPair, String> {
    // Find the matching refresh token by checking hashes
    let rows = sqlx::query_as::<_, (String, String, String, String, bool, String)>(
        r#"SELECT id, user_id, token_hash, family_id, revoked, expires_at
           FROM refresh_tokens ORDER BY created_at DESC"#,
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("db error: {e}"))?;

    let mut matched = None;
    for (id, user_id, token_hash, family_id, revoked, expires_at) in &rows {
        if super::password::verify_password(old_token, token_hash) {
            matched = Some((
                id.clone(),
                user_id.clone(),
                family_id.clone(),
                *revoked,
                expires_at.clone(),
            ));
            break;
        }
    }

    let (token_id, user_id, family_id, was_revoked, expires_at) =
        matched.ok_or_else(|| "invalid refresh token".to_string())?;

    // Reuse detection: if token was already revoked, this is a stolen token replay
    if was_revoked {
        // Revoke ALL tokens in this family
        sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?1")
            .bind(&family_id)
            .execute(pool)
            .await
            .map_err(|e| format!("db error: {e}"))?;

        tracing::warn!(family_id = %family_id, "refresh token reuse detected — family revoked");
        return Err("token reuse detected — all sessions revoked".to_string());
    }

    // Check expiry
    let exp = chrono::DateTime::parse_from_rfc3339(&expires_at)
        .map_err(|_| "invalid expiry".to_string())?;
    if Utc::now() > exp {
        return Err("refresh token expired".to_string());
    }

    // Revoke the old token
    sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE id = ?1")
        .bind(&token_id)
        .execute(pool)
        .await
        .map_err(|e| format!("db error: {e}"))?;

    // Issue new refresh token in the same family
    let new_raw = format!("rfx_{}", Uuid::new_v4().to_string().replace('-', ""));
    let new_hash = hash_password(&new_raw).map_err(|_| "hash error".to_string())?;
    let new_expires = Utc::now() + Duration::days(settings.refresh_token_expiry_days);
    let new_id = Uuid::new_v4().to_string();

    sqlx::query(
        r#"INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at, revoked, created_at)
           VALUES (?1, ?2, ?3, ?4, ?5, 0, ?6)"#,
    )
    .bind(&new_id)
    .bind(&user_id)
    .bind(&new_hash)
    .bind(&family_id) // same family
    .bind(new_expires.to_rfc3339())
    .bind(Utc::now().to_rfc3339())
    .execute(pool)
    .await
    .map_err(|e| format!("db error: {e}"))?;

    // Get username for access token
    let username = sqlx::query_as::<_, (String,)>("SELECT username FROM users WHERE id = ?1")
        .bind(&user_id)
        .fetch_one(pool)
        .await
        .map_err(|e| format!("db error: {e}"))?
        .0;

    let (access_token, access_expires) = create_access_token(&user_id, &username, settings)?;

    Ok(TokenPair {
        access_token,
        refresh_token: new_raw,
        access_expires_at: access_expires,
        refresh_expires_at: new_expires.to_rfc3339(),
        token_type: "Bearer".to_string(),
    })
}

/// Revoke a specific refresh token (logout)
pub async fn revoke_refresh_token(pool: &SqlitePool, token: &str) -> Result<(), String> {
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT id, token_hash FROM refresh_tokens WHERE revoked = 0",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("db error: {e}"))?;

    for (id, token_hash) in &rows {
        if super::password::verify_password(token, token_hash) {
            sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE id = ?1")
                .bind(id)
                .execute(pool)
                .await
                .map_err(|e| format!("db error: {e}"))?;
            return Ok(());
        }
    }

    Err("refresh token not found".to_string())
}

/// Revoke all refresh tokens for a user (force logout everywhere)
pub async fn revoke_all_user_tokens(pool: &SqlitePool, user_id: &str) -> Result<u64, String> {
    let result = sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?1 AND revoked = 0")
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|e| format!("db error: {e}"))?;
    Ok(result.rows_affected())
}

// ============================================================
// Request/Response types
// ============================================================

#[derive(Debug, Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Debug, Deserialize)]
pub struct LogoutRequest {
    pub refresh_token: String,
}
