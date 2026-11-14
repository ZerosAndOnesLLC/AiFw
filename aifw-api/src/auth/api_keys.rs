//! API-key minting, listing, revocation and verification, including the
//! reserved cluster/daemon/CLI key names that operators may not self-assign
//! (SEC-H12).
//!
//! A key belongs to one user. It may be narrowed to a role (its effective
//! permissions are the intersection of the owner's and that role's), may
//! expire, and records when it was last used.

use axum::http::StatusCode;
use chrono::{DateTime, Duration, Utc};
use sqlx::sqlite::SqlitePool;
use uuid::Uuid;

use super::password::{hash_password, verify_password};
use super::types::{ApiKeyInfo, CreateApiKeyResponse};

/// API key names reserved for internal identities: the daemon loopback key,
/// the inbound cluster peer key and the on-box root CLI key. They are minted
/// by dedicated code paths only, never listed or revoked through the normal
/// Users → API Keys endpoints, so an operator can't self-grant peer / daemon
/// privilege by naming a regular key one of them (SEC-H12).
pub const RESERVED_API_KEY_NAMES: &[&str] = &[
    "aifw-daemon-loopback",
    "aifw-cluster-peer",
    CLI_LOCAL_KEY_NAME,
];

/// Name of the root-only key the `aifw` CLI provisions for itself on the
/// appliance (see `aifw local cli-key`).
pub const CLI_LOCAL_KEY_NAME: &str = "aifw-cli-local";

/// Longest lifetime a key may be minted with (10 years).
pub const MAX_KEY_LIFETIME_DAYS: u32 = 3650;

/// `last_used_at` is only rewritten when the stored value is older than
/// this, so a script hammering the API doesn't turn every read into a write.
const LAST_USED_WRITE_INTERVAL_SECS: i64 = 300;

/// Identity resolved from a valid API key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiKeyIdentity {
    pub key_id: String,
    pub user_id: String,
    pub key_name: String,
    /// Role the key is narrowed to, if any.
    pub role_id: Option<String>,
}

fn db_err(context: &'static str) -> impl Fn(sqlx::Error) -> StatusCode {
    move |e| {
        tracing::error!(error = %e, "auth: {context}");
        StatusCode::INTERNAL_SERVER_ERROR
    }
}

/// Validate a requested lifetime and turn it into an absolute expiry.
pub fn expiry_from_days(
    days: Option<u32>,
    now: DateTime<Utc>,
) -> Result<Option<String>, StatusCode> {
    match days {
        None => Ok(None),
        Some(0) => Err(StatusCode::BAD_REQUEST),
        Some(d) if d > MAX_KEY_LIFETIME_DAYS => Err(StatusCode::BAD_REQUEST),
        Some(d) => Ok(Some((now + Duration::days(i64::from(d))).to_rfc3339())),
    }
}

/// True when `expires_at` (RFC 3339) is set and not in the future. An
/// unparseable value counts as expired — fail closed.
pub fn is_expired(expires_at: Option<&str>, now: DateTime<Utc>) -> bool {
    match expires_at {
        None => false,
        Some(s) => DateTime::parse_from_rfc3339(s)
            .map(|t| t.with_timezone(&Utc) <= now)
            .unwrap_or(true),
    }
}

/// Mint a key for `user_id`. The caller is responsible for authorization
/// (who may mint for whom, and that `role_id` is a permitted subset).
pub async fn create_api_key(
    pool: &SqlitePool,
    user_id: Uuid,
    name: &str,
    role_id: Option<&str>,
    expires_at: Option<String>,
) -> Result<CreateApiKeyResponse, StatusCode> {
    let name = name.trim();
    if name.is_empty() || name.len() > 128 || RESERVED_API_KEY_NAMES.contains(&name) {
        return Err(StatusCode::BAD_REQUEST);
    }
    let raw_key = format!("aifw_{}", Uuid::new_v4().simple());
    let prefix = raw_key[..12].to_string();
    let key_hash = hash_password(&raw_key)?;
    let id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO api_keys (id, name, key_hash, prefix, user_id, created_at, role_id, expires_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
    )
    .bind(id.to_string())
    .bind(name)
    .bind(&key_hash)
    .bind(&prefix)
    .bind(user_id.to_string())
    .bind(Utc::now().to_rfc3339())
    .bind(role_id)
    .bind(expires_at.as_deref())
    .execute(pool)
    .await
    .map_err(db_err("failed to insert API key"))?;

    Ok(CreateApiKeyResponse {
        id,
        name: name.to_string(),
        key: raw_key,
        prefix,
        user_id: user_id.to_string(),
        role_id: role_id.map(str::to_string),
        expires_at,
    })
}

/// List keys, newest first. `owner = Some(id)` limits to that user's keys.
/// Reserved internal keys are never listed.
pub async fn list_api_keys(
    pool: &SqlitePool,
    owner: Option<&str>,
) -> Result<Vec<ApiKeyInfo>, StatusCode> {
    type Row = (
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        String,
        Option<String>,
        Option<String>,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT ak.id, ak.name, ak.prefix, ak.user_id, u.username, ak.role_id, r.name, \
                ak.created_at, ak.expires_at, ak.last_used_at \
         FROM api_keys ak \
         JOIN users u ON ak.user_id = u.id \
         LEFT JOIN roles r ON ak.role_id = r.id \
         WHERE (?1 IS NULL OR ak.user_id = ?1) \
           AND ak.name NOT IN (?2, ?3, ?4) \
         ORDER BY ak.created_at DESC",
    )
    .bind(owner)
    .bind(RESERVED_API_KEY_NAMES[0])
    .bind(RESERVED_API_KEY_NAMES[1])
    .bind(RESERVED_API_KEY_NAMES[2])
    .fetch_all(pool)
    .await
    .map_err(db_err("failed to list API keys"))?;

    let now = Utc::now();
    Ok(rows
        .into_iter()
        .map(
            |(
                id,
                name,
                prefix,
                user_id,
                username,
                role_id,
                role_name,
                created_at,
                expires_at,
                last_used_at,
            )| {
                let expired = is_expired(expires_at.as_deref(), now);
                ApiKeyInfo {
                    id,
                    name,
                    prefix,
                    user_id,
                    username,
                    role_id,
                    role_name,
                    created_at,
                    expires_at,
                    last_used_at,
                    expired,
                }
            },
        )
        .collect())
}

/// Owner and name of a key, for authorization before revoking it.
pub async fn api_key_owner(
    pool: &SqlitePool,
    id: &str,
) -> Result<Option<(String, String)>, StatusCode> {
    sqlx::query_as::<_, (String, String)>("SELECT user_id, name FROM api_keys WHERE id = ?1")
        .bind(id)
        .fetch_optional(pool)
        .await
        .map_err(db_err("failed to look up API key"))
}

/// Delete a key by id. Returns false when nothing was deleted. Reserved
/// internal keys are refused.
pub async fn revoke_api_key(pool: &SqlitePool, id: &str) -> Result<bool, StatusCode> {
    let res = sqlx::query("DELETE FROM api_keys WHERE id = ?1 AND name NOT IN (?2, ?3, ?4)")
        .bind(id)
        .bind(RESERVED_API_KEY_NAMES[0])
        .bind(RESERVED_API_KEY_NAMES[1])
        .bind(RESERVED_API_KEY_NAMES[2])
        .execute(pool)
        .await
        .map_err(db_err("failed to delete API key"))?;
    Ok(res.rows_affected() > 0)
}

/// Verify an API key. Expired keys are rejected. On success the key's
/// `last_used_at` is refreshed (throttled).
pub async fn verify_api_key(pool: &SqlitePool, key: &str) -> Result<ApiKeyIdentity, StatusCode> {
    // Use prefix for fast lookup, then verify hash only on prefix-matched keys
    let prefix = key.get(..12).unwrap_or(key);
    type Row = (
        String,
        String,
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
    );
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT ak.id, ak.key_hash, u.id, ak.name, ak.role_id, ak.expires_at, ak.last_used_at \
         FROM api_keys ak JOIN users u ON ak.user_id = u.id WHERE ak.prefix = ?1",
    )
    .bind(prefix)
    .fetch_all(pool)
    .await
    .map_err(db_err("failed to query API keys"))?;

    let now = Utc::now();
    for (key_id, key_hash, user_id, key_name, role_id, expires_at, last_used_at) in rows {
        if !verify_password(key, &key_hash) {
            continue;
        }
        if is_expired(expires_at.as_deref(), now) {
            return Err(StatusCode::UNAUTHORIZED);
        }
        if last_used_is_stale(last_used_at.as_deref(), now) {
            touch_last_used(pool, &key_id, now).await;
        }
        return Ok(ApiKeyIdentity {
            key_id,
            user_id,
            key_name,
            role_id,
        });
    }
    Err(StatusCode::UNAUTHORIZED)
}

fn last_used_is_stale(last_used_at: Option<&str>, now: DateTime<Utc>) -> bool {
    match last_used_at.and_then(|s| DateTime::parse_from_rfc3339(s).ok()) {
        None => true,
        Some(t) => (now - t.with_timezone(&Utc)).num_seconds() >= LAST_USED_WRITE_INTERVAL_SECS,
    }
}

async fn touch_last_used(pool: &SqlitePool, key_id: &str, now: DateTime<Utc>) {
    if let Err(e) = sqlx::query("UPDATE api_keys SET last_used_at = ?1 WHERE id = ?2")
        .bind(now.to_rfc3339())
        .bind(key_id)
        .execute(pool)
        .await
    {
        tracing::warn!(error = %e, "auth: failed to record API key last use");
    }
}

/// Permission bits and name of a role row, if it exists.
pub async fn role_permission_bits(
    pool: &SqlitePool,
    role_id: &str,
) -> Result<Option<(u64, String)>, StatusCode> {
    let row =
        sqlx::query_as::<_, (i64, String)>("SELECT permissions, name FROM roles WHERE id = ?1")
            .bind(role_id)
            .fetch_optional(pool)
            .await
            .map_err(db_err("failed to query role"))?;
    Ok(row.map(|(bits, name)| (bits as u64, name)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_rejects_zero_and_overlong() {
        let now = Utc::now();
        assert_eq!(expiry_from_days(Some(0), now), Err(StatusCode::BAD_REQUEST));
        assert_eq!(
            expiry_from_days(Some(MAX_KEY_LIFETIME_DAYS + 1), now),
            Err(StatusCode::BAD_REQUEST)
        );
        assert_eq!(expiry_from_days(None, now), Ok(None));
        let exp = expiry_from_days(Some(30), now).unwrap().unwrap();
        assert!(!is_expired(Some(&exp), now));
        assert!(is_expired(Some(&exp), now + Duration::days(31)));
    }

    #[test]
    fn unparseable_expiry_fails_closed() {
        assert!(is_expired(Some("not-a-date"), Utc::now()));
        assert!(!is_expired(None, Utc::now()));
    }

    #[test]
    fn last_used_write_is_throttled() {
        let now = Utc::now();
        assert!(last_used_is_stale(None, now));
        let recent = (now - Duration::seconds(10)).to_rfc3339();
        assert!(!last_used_is_stale(Some(&recent), now));
        let old = (now - Duration::seconds(LAST_USED_WRITE_INTERVAL_SECS + 1)).to_rfc3339();
        assert!(last_used_is_stale(Some(&old), now));
    }

    #[test]
    fn cli_local_name_is_reserved() {
        assert!(RESERVED_API_KEY_NAMES.contains(&CLI_LOCAL_KEY_NAME));
    }
}
