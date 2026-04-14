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
    pub role: String,
    pub role_id: Option<String>,
    pub enabled: bool,
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
    pub role: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub username: Option<String>,
    pub password: Option<String>,
    pub role: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct UserAuditEntry {
    pub id: String,
    pub user_id: Option<String>,
    pub actor_id: String,
    pub action: String,
    pub details: Option<String>,
    pub ip_addr: Option<String>,
    pub created_at: String,
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

    // Add role and enabled columns if they don't exist
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'")
        .execute(pool).await;
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")
        .execute(pool).await;

    // Static routes
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS static_routes (
            id TEXT PRIMARY KEY,
            destination TEXT NOT NULL,
            gateway TEXT NOT NULL,
            interface TEXT,
            metric INTEGER DEFAULT 0,
            enabled INTEGER NOT NULL DEFAULT 1,
            description TEXT,
            created_at TEXT NOT NULL
        )"#,
    )
    .execute(pool)
    .await?;

    // Add fib column (0 = main FIB). Multi-WAN (#132) routes can target
    // additional FIBs created via routing instances.
    let _ = sqlx::query("ALTER TABLE static_routes ADD COLUMN fib INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await;

    // Schedules
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS schedules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            time_ranges TEXT NOT NULL,
            days_of_week TEXT NOT NULL DEFAULT 'mon,tue,wed,thu,fri,sat,sun',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )"#,
    )
    .execute(pool)
    .await?;

    // Add schedule_id column to rules if not exists
    let _ = sqlx::query("ALTER TABLE rules ADD COLUMN schedule_id TEXT")
        .execute(pool).await;

    // User audit log
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS user_audit_log (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            actor_id TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            ip_addr TEXT,
            created_at TEXT NOT NULL
        )"#,
    )
    .execute(pool)
    .await?;

    // Token blacklist for access token revocation
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS revoked_tokens (
            jti TEXT PRIMARY KEY,
            expires_at TEXT NOT NULL
        )"#,
    )
    .execute(pool)
    .await?;

    // --- RBAC: roles table ---
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS roles (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            permissions INTEGER NOT NULL DEFAULT 0,
            builtin INTEGER NOT NULL DEFAULT 0,
            description TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )"#,
    )
    .execute(pool)
    .await?;

    // Seed built-in roles (idempotent)
    {
        use aifw_common::permission::{PermissionSet, builtin_role_permissions};
        let admin_bits = PermissionSet::from_permissions(&builtin_role_permissions("admin")).to_bits() as i64;
        let operator_bits = PermissionSet::from_permissions(&builtin_role_permissions("operator")).to_bits() as i64;
        let viewer_bits = PermissionSet::from_permissions(&builtin_role_permissions("viewer")).to_bits() as i64;

        sqlx::query(
            "INSERT OR IGNORE INTO roles (id, name, permissions, builtin, description) VALUES (?1, ?2, ?3, 1, ?4)"
        )
        .bind("builtin-admin").bind("admin").bind(admin_bits).bind("Full system access")
        .execute(pool).await?;

        sqlx::query(
            "INSERT OR IGNORE INTO roles (id, name, permissions, builtin, description) VALUES (?1, ?2, ?3, 1, ?4)"
        )
        .bind("builtin-operator").bind("operator").bind(operator_bits).bind("Operational access without system administration")
        .execute(pool).await?;

        sqlx::query(
            "INSERT OR IGNORE INTO roles (id, name, permissions, builtin, description) VALUES (?1, ?2, ?3, 1, ?4)"
        )
        .bind("builtin-viewer").bind("viewer").bind(viewer_bits).bind("Read-only access")
        .execute(pool).await?;

        // Update built-in role permissions in case new permissions were added
        sqlx::query("UPDATE roles SET permissions = ?1 WHERE id = 'builtin-admin'")
            .bind(admin_bits).execute(pool).await?;
        sqlx::query("UPDATE roles SET permissions = ?1 WHERE id = 'builtin-operator'")
            .bind(operator_bits).execute(pool).await?;
        sqlx::query("UPDATE roles SET permissions = ?1 WHERE id = 'builtin-viewer'")
            .bind(viewer_bits).execute(pool).await?;
    }

    // Add role_id column to users (references roles table)
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN role_id TEXT")
        .execute(pool).await;

    // Backfill role_id from legacy role string
    sqlx::query("UPDATE users SET role_id = 'builtin-admin' WHERE role = 'admin' AND role_id IS NULL")
        .execute(pool).await?;
    sqlx::query("UPDATE users SET role_id = 'builtin-operator' WHERE role = 'operator' AND role_id IS NULL")
        .execute(pool).await?;
    sqlx::query("UPDATE users SET role_id = 'builtin-viewer' WHERE role = 'viewer' AND role_id IS NULL")
        .execute(pool).await?;

    Ok(())
}

/// Revoke an access token by its JTI (unique token ID).
pub async fn revoke_access_token(pool: &SqlitePool, jti: &str, expires_at: &str) -> Result<(), StatusCode> {
    sqlx::query("INSERT OR IGNORE INTO revoked_tokens (jti, expires_at) VALUES (?1, ?2)")
        .bind(jti)
        .bind(expires_at)
        .execute(pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(())
}

/// Check if an access token has been revoked.
pub async fn is_token_revoked(pool: &SqlitePool, jti: &str) -> bool {
    sqlx::query_as::<_, (String,)>("SELECT jti FROM revoked_tokens WHERE jti = ?1")
        .bind(jti)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .is_some()
}

/// Clean up expired entries from the blacklist (called periodically).
#[allow(dead_code)]
pub async fn cleanup_revoked_tokens(pool: &SqlitePool) {
    let now = chrono::Utc::now().to_rfc3339();
    let _ = sqlx::query("DELETE FROM revoked_tokens WHERE expires_at < ?1")
        .bind(&now)
        .execute(pool)
        .await;
}

// ============================================================
// User operations
// ============================================================

/// Validate password meets minimum security requirements.
pub fn validate_password(password: &str) -> Result<(), StatusCode> {
    if password.len() < 8 {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !password.chars().any(|c| c.is_uppercase()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !password.chars().any(|c| c.is_lowercase()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(())
}

pub async fn create_user(pool: &SqlitePool, req: &CreateUserRequest) -> Result<User, StatusCode> {
    validate_password(&req.password)?;
    let pw_hash = hash_password(&req.password)?;
    let role = req.role.as_deref().unwrap_or("viewer").to_string();
    let role_id = match role.as_str() {
        "admin" => Some("builtin-admin".to_string()),
        "operator" => Some("builtin-operator".to_string()),
        "viewer" => Some("builtin-viewer".to_string()),
        _ => None,
    };
    let user = User {
        id: Uuid::new_v4(),
        username: req.username.clone(),
        password_hash: pw_hash,
        totp_enabled: false,
        totp_secret: None,
        auth_provider: "local".to_string(),
        role,
        role_id: role_id.clone(),
        enabled: true,
        created_at: Utc::now().to_rfc3339(),
    };

    sqlx::query(
        "INSERT INTO users (id, username, password_hash, totp_enabled, totp_secret, auth_provider, role, role_id, enabled, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
    )
    .bind(user.id.to_string())
    .bind(&user.username)
    .bind(&user.password_hash)
    .bind(user.totp_enabled)
    .bind(user.totp_secret.as_deref())
    .bind(&user.auth_provider)
    .bind(&user.role)
    .bind(user.role_id.as_deref())
    .bind(user.enabled)
    .bind(&user.created_at)
    .execute(pool)
    .await
    .map_err(|_| StatusCode::CONFLICT)?;

    Ok(user)
}

pub async fn list_users(pool: &SqlitePool) -> Result<Vec<User>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, String, String, bool, Option<String>, String, String, Option<String>, bool, String)>(
        "SELECT id, username, password_hash, totp_enabled, totp_secret, auth_provider, role, role_id, enabled, created_at FROM users ORDER BY created_at ASC",
    )
    .fetch_all(pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(rows.into_iter().map(|(id, username, pw, totp_on, totp_sec, provider, role, role_id, enabled, ca)| User {
        id: Uuid::parse_str(&id).unwrap_or_default(),
        username, password_hash: pw, totp_enabled: totp_on, totp_secret: totp_sec,
        auth_provider: provider, role, role_id, enabled, created_at: ca,
    }).collect())
}

pub async fn update_user(pool: &SqlitePool, user_id: &str, req: &UpdateUserRequest) -> Result<User, StatusCode> {
    let mut user = get_user_by_id(pool, user_id).await?.ok_or(StatusCode::NOT_FOUND)?;

    if let Some(ref username) = req.username {
        user.username = username.clone();
    }
    if let Some(ref password) = req.password {
        validate_password(password)?;
        user.password_hash = hash_password(password)?;
    }
    if let Some(ref role) = req.role {
        user.role = role.clone();
        // Map built-in role names to role_id; custom role_id can be set directly
        user.role_id = match role.as_str() {
            "admin" => Some("builtin-admin".to_string()),
            "operator" => Some("builtin-operator".to_string()),
            "viewer" => Some("builtin-viewer".to_string()),
            _ => {
                // Check if it's a custom role_id
                let exists = sqlx::query_as::<_, (String,)>("SELECT id FROM roles WHERE id = ?1 OR name = ?1")
                    .bind(role)
                    .fetch_optional(pool)
                    .await
                    .ok()
                    .flatten();
                exists.map(|(id,)| id)
            }
        };
    }
    if let Some(enabled) = req.enabled {
        user.enabled = enabled;
    }

    sqlx::query(
        "UPDATE users SET username = ?2, password_hash = ?3, role = ?4, role_id = ?5, enabled = ?6 WHERE id = ?1",
    )
    .bind(user_id)
    .bind(&user.username)
    .bind(&user.password_hash)
    .bind(&user.role)
    .bind(user.role_id.as_deref())
    .bind(user.enabled)
    .execute(pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(user)
}

pub async fn delete_user(pool: &SqlitePool, user_id: &str) -> Result<(), StatusCode> {
    let result = sqlx::query("DELETE FROM users WHERE id = ?1")
        .bind(user_id)
        .execute(pool)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if result.rows_affected() == 0 {
        return Err(StatusCode::NOT_FOUND);
    }
    // Clean up related data
    let _ = sqlx::query("DELETE FROM refresh_tokens WHERE user_id = ?1").bind(user_id).execute(pool).await;
    let _ = sqlx::query("DELETE FROM recovery_codes WHERE user_id = ?1").bind(user_id).execute(pool).await;
    let _ = sqlx::query("DELETE FROM api_keys WHERE user_id = ?1").bind(user_id).execute(pool).await;
    Ok(())
}

pub async fn log_user_audit(pool: &SqlitePool, actor_id: &str, user_id: Option<&str>, action: &str, details: Option<&str>) {
    let _ = sqlx::query(
        "INSERT INTO user_audit_log (id, user_id, actor_id, action, details, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(user_id)
    .bind(actor_id)
    .bind(action)
    .bind(details)
    .bind(Utc::now().to_rfc3339())
    .execute(pool)
    .await;
}

pub async fn list_user_audit_log(pool: &SqlitePool, limit: i64) -> Result<Vec<UserAuditEntry>, StatusCode> {
    let rows = sqlx::query_as::<_, (String, Option<String>, String, String, Option<String>, Option<String>, String)>(
        "SELECT id, user_id, actor_id, action, details, ip_addr, created_at FROM user_audit_log ORDER BY created_at DESC LIMIT ?1",
    )
    .bind(limit)
    .fetch_all(pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(rows.into_iter().map(|(id, user_id, actor_id, action, details, ip_addr, created_at)| UserAuditEntry {
        id, user_id, actor_id, action, details, ip_addr, created_at,
    }).collect())
}

pub async fn get_user_by_username(pool: &SqlitePool, username: &str) -> Result<Option<User>, StatusCode> {
    let row = sqlx::query_as::<_, (String, String, String, bool, Option<String>, String, String, Option<String>, bool, String)>(
        "SELECT id, username, password_hash, totp_enabled, totp_secret, auth_provider, role, role_id, enabled, created_at FROM users WHERE username = ?1",
    )
    .bind(username)
    .fetch_optional(pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(row.map(|(id, username, pw, totp_on, totp_sec, provider, role, role_id, enabled, ca)| User {
        id: Uuid::parse_str(&id).unwrap_or_default(),
        username, password_hash: pw, totp_enabled: totp_on, totp_secret: totp_sec,
        auth_provider: provider, role, role_id, enabled, created_at: ca,
    }))
}

pub async fn get_user_by_id(pool: &SqlitePool, user_id: &str) -> Result<Option<User>, StatusCode> {
    let row = sqlx::query_as::<_, (String, String, String, bool, Option<String>, String, String, Option<String>, bool, String)>(
        "SELECT id, username, password_hash, totp_enabled, totp_secret, auth_provider, role, role_id, enabled, created_at FROM users WHERE id = ?1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(row.map(|(id, username, pw, totp_on, totp_sec, provider, role, role_id, enabled, ca)| User {
        id: Uuid::parse_str(&id).unwrap_or_default(),
        username, password_hash: pw, totp_enabled: totp_on, totp_secret: totp_sec,
        auth_provider: provider, role, role_id, enabled, created_at: ca,
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
    // Use prefix for fast lookup, then verify hash only on prefix-matched keys
    let prefix = if key.len() >= 12 { &key[..12] } else { key };
    let rows = sqlx::query_as::<_, (String, String)>(
        "SELECT ak.key_hash, u.id FROM api_keys ak JOIN users u ON ak.user_id = u.id WHERE ak.prefix = ?1",
    )
    .bind(prefix)
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
    use aifw_common::permission::PermissionSet;

    // Accept auth from: Authorization header, or ?token= query param (for WebSocket/SSE)
    let auth_header = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let query_token: Option<String> = request.uri().query()
        .and_then(|q| q.split('&').find(|p| p.starts_with("token=")))
        .and_then(|p| p.strip_prefix("token="))
        .map(|t| percent_decode(t));

    // Resolve (user_id, perm_from_token, role_from_token) from the credential
    let (user_id, jwt_perm, jwt_role) = if let Some(token) = auth_header.and_then(|h| h.strip_prefix("Bearer ")) {
        let token_data = verify_access_token(token, &state.auth_settings)
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        if is_token_revoked(&state.pool, &token_data.claims.jti).await {
            return Err(StatusCode::UNAUTHORIZED);
        }
        (token_data.claims.sub, token_data.claims.perm, token_data.claims.role)
    } else if let Some(key) = auth_header.and_then(|h| h.strip_prefix("ApiKey ")) {
        let uid = verify_api_key(&state.pool, key).await?;
        (uid, None, None) // API keys don't carry JWT claims — will do DB lookup
    } else if let Some(ref token) = query_token {
        let token_data = verify_access_token(token, &state.auth_settings)
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        if is_token_revoked(&state.pool, &token_data.claims.jti).await {
            return Err(StatusCode::UNAUTHORIZED);
        }
        (token_data.claims.sub, token_data.claims.perm, token_data.claims.role)
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    // Check if user is still enabled
    let user = get_user_by_id(&state.pool, &user_id).await?
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !user.enabled {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Resolve permissions: from JWT if present, otherwise DB lookup
    let (perm_set, role_name) = match jwt_perm {
        Some(bits) => (PermissionSet::from_bits(bits), jwt_role.unwrap_or_else(|| user.role.clone())),
        None => {
            // Legacy token or API key — resolve from DB
            let (bits, name) = tokens::resolve_token_permissions(
                &state.pool, &user.role, user.role_id.as_deref()
            ).await.map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            (PermissionSet::from_bits(bits), name)
        }
    };

    // Dispatch ApiRequest hook to plugins
    {
        let mgr = state.plugin_manager.read().await;
        if mgr.running_count() > 0 {
            let method = request.method().to_string();
            let path = request.uri().path().to_string();
            let event = aifw_plugins::HookEvent {
                hook: aifw_plugins::HookPoint::ApiRequest,
                data: aifw_plugins::hooks::HookEventData::Api {
                    method, path, remote_addr: None,
                },
            };
            let actions = mgr.dispatch(&event).await;
            for action in &actions {
                if matches!(action, aifw_plugins::HookAction::Block) {
                    return Err(StatusCode::FORBIDDEN);
                }
            }
        }
    }

    request.extensions_mut().insert(AuthUser {
        user_id,
        username: user.username.clone(),
        permissions: perm_set,
        role: role_name,
    });
    Ok(next.run(request).await)
}

/// Simple percent-decoding for URL query params (no external crate needed).
fn percent_decode(s: &str) -> String {
    let mut out = Vec::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(b) = u8::from_str_radix(std::str::from_utf8(&bytes[i+1..i+3]).unwrap_or(""), 16) {
                out.push(b);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).unwrap_or_default()
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AuthUser {
    pub user_id: String,
    pub username: String,
    pub permissions: aifw_common::PermissionSet,
    pub role: String,
}

/// Permission check middleware. Reads `AuthUser` from request extensions
/// (set by auth_middleware) and checks if the user has the required permission.
#[allow(dead_code)]
pub async fn require_perm(
    perm: aifw_common::Permission,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_user = request
        .extensions()
        .get::<AuthUser>()
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !auth_user.permissions.has(perm) {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(request).await)
}

/// Macro to create a permission-check middleware closure for use with `from_fn`.
#[macro_export]
macro_rules! perm_check {
    ($perm:expr) => {
        |request: axum::extract::Request, next: axum::middleware::Next| async move {
            let auth_user = request
                .extensions()
                .get::<$crate::auth::AuthUser>()
                .ok_or(axum::http::StatusCode::UNAUTHORIZED)?;
            if !auth_user.permissions.has($perm) {
                return Err(axum::http::StatusCode::FORBIDDEN);
            }
            Ok::<_, axum::http::StatusCode>(next.run(request).await)
        }
    };
}

/// Legacy alias — checks users:write permission (admin-level).
/// Kept for backward compatibility; new code should use perm_check! directly.
#[allow(dead_code)]
pub async fn require_admin(
    State(_state): State<crate::AppState>,
    request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let auth_user = request
        .extensions()
        .get::<AuthUser>()
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if !auth_user.permissions.has(aifw_common::Permission::UsersWrite) {
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(next.run(request).await)
}
