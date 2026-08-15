use chrono::{Duration, Utc};
use jsonwebtoken::{
    Algorithm, DecodingKey, EncodingKey, Header, TokenData, Validation, decode, encode,
};
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use uuid::Uuid;

use super::config::AuthSettings;
use super::password::hash_password;

// ============================================================
// JWT Access Tokens
// ============================================================

/// `iss` claim stamped on every access token and required on verify.
/// Together with [`JWT_AUDIENCE`] this scopes tokens to the AiFw API so a
/// token minted by any other HS256 user of the same secret material (or a
/// future second issuer sharing a key store) is rejected (SEC-M2 #299).
pub const JWT_ISSUER: &str = "aifw-api";
/// `aud` claim stamped on every access token and required on verify.
pub const JWT_AUDIENCE: &str = "aifw";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub exp: i64,
    pub iat: i64,
    pub jti: String, // unique token ID
    /// Issuer — always [`JWT_ISSUER`]. Optional on the struct only so the
    /// claims type can still describe pre-#299 tokens; validation rejects
    /// tokens where it is missing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Audience — always [`JWT_AUDIENCE`]. See `iss`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub perm: Option<u64>, // permission bitmask
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>, // role name for display
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
    permissions: u64,
    role_name: &str,
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
        iss: Some(JWT_ISSUER.to_string()),
        aud: Some(JWT_AUDIENCE.to_string()),
        perm: Some(permissions),
        role: Some(role_name.to_string()),
    };

    let token = encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(settings.jwt_secret.as_bytes()),
    )
    .map_err(|e| format!("token encode error: {e}"))?;

    Ok((token, exp.to_rfc3339()))
}

/// Validation rules for access tokens: HS256 only (no `alg` negotiation),
/// `exp` enforced, and `iss`/`aud` must match this API's constants.
fn access_token_validation() -> Validation {
    let mut v = Validation::new(Algorithm::HS256);
    v.set_issuer(&[JWT_ISSUER]);
    v.set_audience(&[JWT_AUDIENCE]);
    v.set_required_spec_claims(&["exp", "iss", "aud"]);
    v
}

pub fn verify_access_token(
    token: &str,
    settings: &AuthSettings,
) -> Result<TokenData<Claims>, String> {
    decode::<Claims>(
        token,
        &DecodingKey::from_secret(settings.jwt_secret.as_bytes()),
        &access_token_validation(),
    )
    .map_err(|e| format!("token verify error: {e}"))
}

// ============================================================
// Refresh Tokens (DB-backed with rotation + family tracking)
// ============================================================

/// Length of the non-secret prefix stored alongside the Argon2 hash.
/// The raw token is `rfx_<32 hex>` (36 chars); the first 12 (`rfx_` + 8 hex)
/// are enough to index a lookup to at most a handful of rows. This is NOT a
/// security boundary — the Argon2 hash still authenticates the token — it
/// only bounds the number of `verify_password` calls per request (SEC-H8).
const REFRESH_PREFIX_LEN: usize = 12;

pub(crate) fn refresh_prefix(raw: &str) -> &str {
    if raw.len() >= REFRESH_PREFIX_LEN {
        &raw[..REFRESH_PREFIX_LEN]
    } else {
        raw
    }
}

/// Delete revoked or expired refresh tokens. Called opportunistically on
/// rotate so the table (and any same-prefix bucket) stays small. Best-effort:
/// a failure here is non-fatal and must not block token issuance.
async fn prune_refresh_tokens(pool: &SqlitePool) {
    let now = Utc::now().to_rfc3339();
    if let Err(e) = sqlx::query("DELETE FROM refresh_tokens WHERE revoked = 1 OR expires_at < ?1")
        .bind(&now)
        .execute(pool)
        .await
    {
        tracing::warn!(error = %e, "failed to prune refresh_tokens");
    }
}

pub async fn create_refresh_token(
    pool: &SqlitePool,
    user_id: &str,
    settings: &AuthSettings,
) -> Result<(String, String), String> {
    let raw_token = format!("rfx_{}", Uuid::new_v4().to_string().replace('-', ""));
    let token_hash = hash_password(&raw_token).map_err(|_| "hash error".to_string())?;
    let prefix = refresh_prefix(&raw_token).to_string();
    let family_id = Uuid::new_v4().to_string();
    let expires = Utc::now() + Duration::days(settings.refresh_token_expiry_days);
    let id = Uuid::new_v4().to_string();

    sqlx::query(
        r#"INSERT INTO refresh_tokens (id, user_id, token_hash, token_prefix, family_id, expires_at, revoked, created_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7)"#,
    )
    .bind(&id)
    .bind(user_id)
    .bind(&token_hash)
    .bind(&prefix)
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
    permissions: u64,
    role_name: &str,
    settings: &AuthSettings,
) -> Result<TokenPair, String> {
    let (access_token, access_expires) =
        create_access_token(user_id, username, permissions, role_name, settings)?;
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
    // SEC-H8: look up by the non-secret prefix so we Argon2-verify at most a
    // handful of rows, not the whole table. A random/forged token whose prefix
    // matches nothing returns zero rows and costs no verify.
    let prefix = refresh_prefix(old_token);
    let rows = sqlx::query_as::<_, (String, String, String, String, bool, String)>(
        r#"SELECT id, user_id, token_hash, family_id, revoked, expires_at
           FROM refresh_tokens WHERE token_prefix = ?1 ORDER BY created_at DESC"#,
    )
    .bind(prefix)
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

    // Revoke the old token and insert its successor atomically (SEC-M15
    // #312). Without the transaction a crash between the two writes leaves
    // the family with either no live token (user logged out) or, worse, the
    // old one still valid alongside a new one — which would let a stolen
    // token be replayed without tripping reuse detection.
    let new_raw = format!("rfx_{}", Uuid::new_v4().to_string().replace('-', ""));
    let new_hash = hash_password(&new_raw).map_err(|_| "hash error".to_string())?;
    let new_prefix = refresh_prefix(&new_raw).to_string();
    let new_expires = Utc::now() + Duration::days(settings.refresh_token_expiry_days);
    let new_id = Uuid::new_v4().to_string();

    let mut tx = pool.begin().await.map_err(|e| format!("db error: {e}"))?;

    // Guard against a concurrent rotate of the same token: only proceed if
    // *this* statement flipped the row. If another request got there first
    // the row is already revoked and we must not mint a second successor.
    let revoked_now =
        sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE id = ?1 AND revoked = 0")
            .bind(&token_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("db error: {e}"))?
            .rows_affected();
    if revoked_now == 0 {
        // Lost the race — the other rotate owns the family now. Treat this
        // exactly like a reuse attempt: revoke the family so neither the
        // racing client nor a thief keeps a live token.
        sqlx::query("UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?1")
            .bind(&family_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("db error: {e}"))?;
        tx.commit().await.map_err(|e| format!("db error: {e}"))?;
        tracing::warn!(family_id = %family_id, "concurrent refresh token rotate — family revoked");
        return Err("token reuse detected — all sessions revoked".to_string());
    }

    // Issue new refresh token in the same family
    sqlx::query(
        r#"INSERT INTO refresh_tokens (id, user_id, token_hash, token_prefix, family_id, expires_at, revoked, created_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0, ?7)"#,
    )
    .bind(&new_id)
    .bind(&user_id)
    .bind(&new_hash)
    .bind(&new_prefix)
    .bind(&family_id) // same family
    .bind(new_expires.to_rfc3339())
    .bind(Utc::now().to_rfc3339())
    .execute(&mut *tx)
    .await
    .map_err(|e| format!("db error: {e}"))?;

    tx.commit().await.map_err(|e| format!("db error: {e}"))?;

    // Opportunistic cleanup of revoked/expired rows keeps the table bounded.
    prune_refresh_tokens(pool).await;

    // Get username, enabled, and role for permission resolution
    let (username, enabled, role, role_id) =
        sqlx::query_as::<_, (String, bool, String, Option<String>)>(
            "SELECT username, enabled, role, role_id FROM users WHERE id = ?1",
        )
        .bind(&user_id)
        .fetch_one(pool)
        .await
        .map_err(|e| format!("db error: {e}"))?;

    if !enabled {
        return Err("user account is disabled".to_string());
    }

    // Resolve permissions from role
    let (perm_bits, role_name) = resolve_token_permissions(pool, &role, role_id.as_deref()).await?;

    let (access_token, access_expires) =
        create_access_token(&user_id, &username, perm_bits, &role_name, settings)?;

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
    // SEC-H8: scope to the prefix so logout verifies at most a few hashes.
    let prefix = refresh_prefix(token);
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT id, token_hash FROM refresh_tokens WHERE token_prefix = ?1 AND revoked = 0",
    )
    .bind(prefix)
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

// ============================================================
// Permission resolution for token issuance
// ============================================================

/// Resolve permission bitmask and role name for embedding in JWT.
/// Tries role_id (new system) first, falls back to legacy role string.
pub async fn resolve_token_permissions(
    pool: &SqlitePool,
    legacy_role: &str,
    role_id: Option<&str>,
) -> Result<(u64, String), String> {
    use aifw_common::permission::{PermissionSet, builtin_role_permissions};

    // Try new role_id system first
    if let Some(rid) = role_id {
        let row =
            sqlx::query_as::<_, (i64, String)>("SELECT permissions, name FROM roles WHERE id = ?1")
                .bind(rid)
                .fetch_optional(pool)
                .await
                .map_err(|e| format!("db error: {e}"))?;

        if let Some((bits, name)) = row {
            return Ok((bits as u64, name));
        }
    }

    // Fallback to legacy role string
    let perms = PermissionSet::from_permissions(&builtin_role_permissions(legacy_role));
    Ok((perms.to_bits(), legacy_role.to_string()))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> AuthSettings {
        AuthSettings {
            jwt_secret: "unit-test-secret".to_string(),
            access_token_expiry_mins: 5,
            refresh_token_expiry_days: 1,
            require_totp: false,
            require_totp_for_oauth: false,
            auto_create_oauth_users: false,
            max_login_attempts: 5,
            lockout_duration_secs: 60,
            allow_registration: false,
            password_min_length: 8,
        }
    }

    #[test]
    fn access_token_carries_iss_and_aud_and_verifies() {
        let s = settings();
        let (tok, _) = create_access_token("u1", "alice", 0, "viewer", &s).unwrap();
        let data = verify_access_token(&tok, &s).expect("freshly minted token verifies");
        assert_eq!(data.claims.iss.as_deref(), Some(JWT_ISSUER));
        assert_eq!(data.claims.aud.as_deref(), Some(JWT_AUDIENCE));
        assert_eq!(data.header.alg, Algorithm::HS256);
    }

    /// SEC-M2 #299: a token signed with the right secret but lacking (or
    /// carrying the wrong) iss/aud must be rejected — otherwise anything
    /// else that ever shares the secret could mint API sessions.
    #[test]
    fn token_without_iss_aud_is_rejected() {
        let s = settings();
        let now = Utc::now();
        let mut claims = Claims {
            sub: "u1".into(),
            username: "alice".into(),
            exp: (now + Duration::minutes(5)).timestamp(),
            iat: now.timestamp(),
            jti: "x".into(),
            iss: None,
            aud: None,
            perm: None,
            role: None,
        };
        let key = EncodingKey::from_secret(s.jwt_secret.as_bytes());
        let legacy = encode(&Header::new(Algorithm::HS256), &claims, &key).unwrap();
        assert!(
            verify_access_token(&legacy, &s).is_err(),
            "no iss/aud must fail"
        );

        claims.iss = Some("someone-else".into());
        claims.aud = Some(JWT_AUDIENCE.into());
        let wrong_iss = encode(&Header::new(Algorithm::HS256), &claims, &key).unwrap();
        assert!(
            verify_access_token(&wrong_iss, &s).is_err(),
            "wrong iss must fail"
        );

        claims.iss = Some(JWT_ISSUER.into());
        claims.aud = Some("other-app".into());
        let wrong_aud = encode(&Header::new(Algorithm::HS256), &claims, &key).unwrap();
        assert!(
            verify_access_token(&wrong_aud, &s).is_err(),
            "wrong aud must fail"
        );
    }

    /// The validator pins HS256; a token that names another HMAC alg in its
    /// header must not be accepted even with the correct secret.
    #[test]
    fn token_with_other_alg_is_rejected() {
        let s = settings();
        let now = Utc::now();
        let claims = Claims {
            sub: "u1".into(),
            username: "alice".into(),
            exp: (now + Duration::minutes(5)).timestamp(),
            iat: now.timestamp(),
            jti: "x".into(),
            iss: Some(JWT_ISSUER.into()),
            aud: Some(JWT_AUDIENCE.into()),
            perm: None,
            role: None,
        };
        let key = EncodingKey::from_secret(s.jwt_secret.as_bytes());
        let hs512 = encode(&Header::new(Algorithm::HS512), &claims, &key).unwrap();
        assert!(verify_access_token(&hs512, &s).is_err());
    }
}
