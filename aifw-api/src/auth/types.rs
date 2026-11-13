//! User model plus the request/response payloads shared across the auth
//! handlers. Re-exported from `auth/mod.rs`, so `auth::User`,
//! `auth::LoginRequest`, etc. keep resolving.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::tokens::TokenPair;

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
    /// Owner of the key. Defaults to the caller; minting for anyone else
    /// needs `users:write`.
    #[serde(default)]
    pub user_id: Option<String>,
    /// Narrow the key to this role. Its permissions must be a subset of both
    /// the owner's and the caller's; enforced again on every request.
    #[serde(default)]
    pub role_id: Option<String>,
    /// Lifetime in days (1..=3650). None = never expires.
    #[serde(default)]
    pub expires_in_days: Option<u32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateApiKeyResponse {
    pub id: Uuid,
    pub name: String,
    pub key: String,
    pub prefix: String,
    pub user_id: String,
    pub role_id: Option<String>,
    pub expires_at: Option<String>,
}

/// An API key as listed — never includes the secret or its hash.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyInfo {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub user_id: String,
    pub username: String,
    pub role_id: Option<String>,
    pub role_name: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub last_used_at: Option<String>,
    pub expired: bool,
}

#[derive(Debug, Default, Deserialize)]
pub struct ListApiKeysQuery {
    /// List every user's keys (needs `users:read`); default is the caller's own.
    #[serde(default)]
    pub all: bool,
}
