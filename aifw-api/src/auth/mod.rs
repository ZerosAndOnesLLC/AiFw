pub mod config;
pub mod oauth;
pub mod password;
pub mod totp;
pub mod tokens;

pub use config::AuthSettings;
pub use password::{hash_password, verify_password};
pub use tokens::{TokenPair, verify_access_token};

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use uuid::Uuid;

// ============================================================
// User model (extended with TOTP + OAuth fields)
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub totp_enabled: bool,
    #[serde(skip_serializing)]
    pub totp_secret: Option<String>,
    pub auth_provider: String,
    pub created_at: String,
}

// ============================================================
// Request / Response types
// ============================================================

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub tokens: Option<TokenPair>,
    pub totp_required: bool,
}

#[derive(Debug, Deserialize)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
}

#[derive(Debug, Serialize)]
pub struct CreateApiKeyResponse {
    pub id: Uuid,
    pub name: String,
    pub key: String,
    pub prefix: String,
}

// ============================================================
// DB Migration (extended schema)
// ============================================================

pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            totp_enabled INTEGER NOT NULL DEFAULT 0,
            totp_secret TEXT,
            auth_provider TEXT NOT NULL DEFAULT 'local',
            created_at TEXT NOT NULL
        )"#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS api_keys (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            prefix TEXT NOT NULL,
            user_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )"#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS refresh_tokens (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            family_id TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )"#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS recovery_codes (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            code_hash TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )"#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS oauth_providers (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            provider_type TEXT NOT NULL,
            client_id TEXT NOT NULL,
            client_secret TEXT NOT NULL,
            auth_url TEXT NOT NULL,
            token_url TEXT NOT NULL,
            userinfo_url TEXT NOT NULL,
            scopes TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )"#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS oauth_identities (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            provider_id TEXT NOT NULL,
            provider_user_id TEXT NOT NULL,
            email TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (provider_id) REFERENCES oauth_providers(id)
        )"#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS auth_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )"#,
    )
    .execute(pool)
    .await?;

    Ok(())
}

// ============================================================
// User operations
// ============================================================

pub async fn create_user(pool: &SqlitePool, req: &CreateUserRequest) -> Result<User, StatusCode> {
    let pw_hash = hash_password(&req.password)?;
    let user = User {
        id: Uuid::new_v4(),
        username: req.username.clone(),
        password_hash: pw_hash,
        totp_enabled: false,
        totp_secret: None,
        auth_provider: "local".to_string(),
        created_at: Utc::now().to_rfc3339(),
    };

    sqlx::query(
        "INSERT INTO users (id, username, password_hash, totp_enabled, totp_secret, auth_provider, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
    )
    .bind(user.id.to_string())
    .bind(&user.username)
    .bind(&user.password_hash)
    .bind(user.totp_enabled)
    .bind(user.totp_secret.as_deref())
    .bind(&user.auth_provider)
    .bind(&user.created_at)
    .execute(pool)
    .await
    .map_err(|_| StatusCode::CONFLICT)?;

    Ok(user)
}

pub async fn get_user_by_username(pool: &SqlitePool, username: &str) -> Result<Option<User>, StatusCode> {
    let row = sqlx::query_as::<_, (String, String, String, bool, Option<String>, String, String)>(
        "SELECT id, username, password_hash, totp_enabled, totp_secret, auth_provider, created_at FROM users WHERE username = ?1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(row.map(|(id, username, pw, totp_on, totp_sec, provider, ca)| User {
        id: Uuid::parse_str(&id).unwrap_or_default(),
        username,
        password_hash: pw,
        totp_enabled: totp_on,
        totp_secret: totp_sec,
        auth_provider: provider,
        created_at: ca,
    }))
}

pub async fn get_user_by_id(pool: &SqlitePool, user_id: &str) -> Result<Option<User>, StatusCode> {
    let row = sqlx::query_as::<_, (String, String, String, bool, Option<String>, String, String)>(
        "SELECT id, username, password_hash, totp_enabled, totp_secret, auth_provider, created_at FROM users WHERE id = ?1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(row.map(|(id, username, pw, totp_on, totp_sec, provider, ca)| User {
        id: Uuid::parse_str(&id).unwrap_or_default(),
        username,
        password_hash: pw,
        totp_enabled: totp_on,
        totp_secret: totp_sec,
        auth_provider: provider,
        created_at: ca,
    }))
}

// ============================================================
// TOTP DB operations
// ============================================================

pub async fn save_totp_secret(pool: &SqlitePool, user_id: &str, secret: &str) -> Result<(), StatusCode> {
    sqlx::query("UPDATE users SET totp_secret = ?1 WHERE id = ?2")
        .bind(secret)
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(())
}

pub async fn enable_totp(pool: &SqlitePool, user_id: &str) -> Result<(), StatusCode> {
    sqlx::query("UPDATE users SET totp_enabled = 1 WHERE id = ?1")
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(())
}

pub async fn disable_totp(pool: &SqlitePool, user_id: &str) -> Result<(), StatusCode> {
    sqlx::query("UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?1")
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    // Also delete recovery codes
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?1")
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(())
}

pub async fn save_recovery_codes(pool: &SqlitePool, user_id: &str, codes: &[String]) -> Result<(), StatusCode> {
    // Delete old codes
    sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?1")
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    for code in codes {
        let code_hash = hash_password(code)?;
        sqlx::query("INSERT INTO recovery_codes (id, user_id, code_hash, used) VALUES (?1, ?2, ?3, 0)")
            .bind(Uuid::new_v4().to_string())
            .bind(user_id)
            .bind(&code_hash)
            .execute(pool)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    Ok(())
}

/// Try to use a recovery code. Returns true if valid and unused.
pub async fn use_recovery_code(pool: &SqlitePool, user_id: &str, code: &str) -> bool {
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT id, code_hash FROM recovery_codes WHERE user_id = ?1 AND used = 0",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default();

    for (id, code_hash) in rows {
        if verify_password(code, &code_hash) {
            let _ = sqlx::query("UPDATE recovery_codes SET used = 1 WHERE id = ?1")
                .bind(&id)
                .execute(pool)
                .await;
            return true;
        }
    }
    false
}

// ============================================================
// API key operations
// ============================================================

pub async fn create_api_key(pool: &SqlitePool, user_id: Uuid, name: &str) -> Result<CreateApiKeyResponse, StatusCode> {
    let raw_key = format!("aifw_{}", Uuid::new_v4().to_string().replace('-', ""));
    let prefix = raw_key[..12].to_string();
    let key_hash = hash_password(&raw_key)?;
    let id = Uuid::new_v4();

    sqlx::query("INSERT INTO api_keys (id, name, key_hash, prefix, user_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)")
        .bind(id.to_string())
        .bind(name)
        .bind(&key_hash)
        .bind(&prefix)
        .bind(user_id.to_string())
        .bind(Utc::now().to_rfc3339())
        .execute(pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(CreateApiKeyResponse { id, name: name.to_string(), key: raw_key, prefix })
}

pub async fn verify_api_key(pool: &SqlitePool, key: &str) -> Result<String, StatusCode> {
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT ak.key_hash, u.id FROM api_keys ak JOIN users u ON ak.user_id = u.id",
    )
    .fetch_all(pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    for (key_hash, user_id) in rows {
        if verify_password(key, &key_hash) {
            return Ok(user_id);
        }
    }
    Err(StatusCode::UNAUTHORIZED)
}

// ============================================================
// Auth middleware
// ============================================================

pub async fn auth_middleware(
    State(state): State<crate::AppState>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let user_id = if let Some(token) = auth_header.strip_prefix("Bearer ") {
        let token_data = verify_access_token(token, &state.auth_settings)
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        token_data.claims.sub
    } else if let Some(key) = auth_header.strip_prefix("ApiKey ") {
        verify_api_key(&state.pool, key).await?
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    request.extensions_mut().insert(AuthUser(user_id));
    Ok(next.run(request).await)
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AuthUser(pub String);
