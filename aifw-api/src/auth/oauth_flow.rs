//! OAuth 2.0 / OIDC login flow (#170): authorization-code exchange with
//! PKCE, userinfo lookup, local-account resolution and the optional TOTP
//! second step.
//!
//! Provider *configuration* and the CSRF `state` store live in
//! [`super::oauth`]; this module is the runtime that turns a provider
//! callback into an AiFw session.
//!
//! # Flow
//! 1. `GET /auth/oauth/{provider}/authorize` — mint `state` + PKCE
//!    verifier, persist both, return the provider's authorization URL.
//! 2. Browser → provider consent → `GET /auth/oauth/{provider}/callback
//!    ?code=&state=`.
//! 3. [`exchange_code`] posts the code (+ verifier) to the token endpoint,
//!    [`fetch_identity`] reads the userinfo endpoint (GitHub: plus
//!    `/user/emails` when the profile hides the address).
//! 4. [`resolve_user`] maps the identity to a local account: an existing
//!    `oauth_identities` link wins; otherwise a *verified* email matching a
//!    local username links that account; otherwise `auto_create_oauth_users`
//!    provisions a `viewer` with an unusable password.
//! 5. If `require_totp_for_oauth` and the account has TOTP enrolled, a
//!    single-use pending ticket sends the browser to the TOTP prompt
//!    (`POST /auth/oauth/totp`); else the session is issued straight away.

use std::time::Duration;

use axum::http::HeaderMap;
use base64::Engine as _;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use sqlx::SqlitePool;
use uuid::Uuid;

use super::oauth::{OAuthProvider, OAuthProviderType};
use super::types::User;

/// How long a TOTP-pending ticket stays valid.
const PENDING_TTL_SECS: i64 = 300;
/// Timeout for each provider HTTP call.
const HTTP_TIMEOUT: Duration = Duration::from_secs(15);
/// `auth_config` key holding the externally reachable base URL used to
/// build the callback redirect URI (e.g. `https://fw.example.com:8080`).
pub const PUBLIC_URL_KEY: &str = "oauth_public_url";

/// Where an OAuth login attempt failed; rendered into the UI redirect as
/// `?oauth_error=<code>` and logged with detail server-side.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowError {
    /// Provider disabled or unknown.
    Provider,
    /// `state` missing, expired, replayed or for another provider.
    State,
    /// Token endpoint refused the code.
    Exchange,
    /// Userinfo endpoint failed or returned no usable subject.
    Userinfo,
    /// No linked account, no verified email to link by, or auto-create off.
    NoAccount,
    /// The account exists but is disabled.
    Disabled,
    /// Internal/database failure.
    Internal,
}

impl FlowError {
    /// Stable machine-readable code for the UI.
    pub fn code(self) -> &'static str {
        match self {
            FlowError::Provider => "provider",
            FlowError::State => "state",
            FlowError::Exchange => "exchange",
            FlowError::Userinfo => "userinfo",
            FlowError::NoAccount => "no_account",
            FlowError::Disabled => "disabled",
            FlowError::Internal => "internal",
        }
    }
}

// ============================================================
// PKCE
// ============================================================

/// A fresh PKCE verifier (43 base64url chars from 32 random bytes).
pub fn new_code_verifier() -> String {
    let mut bytes = [0u8; 32];
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    OsRng.fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// S256 challenge for a verifier.
pub fn code_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

// ============================================================
// Redirect URI
// ============================================================

/// Base URL the provider must send the browser back to. The operator can
/// pin it (`oauth_public_url` in `auth_config`, e.g. behind a reverse
/// proxy); otherwise it is derived from the request `Host` and the API's
/// own TLS mode.
pub async fn public_base_url(pool: &SqlitePool, headers: &HeaderMap, tls: bool) -> Option<String> {
    let configured: Option<String> =
        sqlx::query_scalar("SELECT value FROM auth_config WHERE key = ?1")
            .bind(PUBLIC_URL_KEY)
            .fetch_optional(pool)
            .await
            .ok()
            .flatten();
    if let Some(u) = configured.map(|s| s.trim().trim_end_matches('/').to_string())
        && !u.is_empty()
    {
        return Some(u);
    }
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|h| h.to_str().ok())?
        .trim();
    if host.is_empty() {
        return None;
    }
    let scheme = if tls { "https" } else { "http" };
    Some(format!("{scheme}://{host}"))
}

/// Callback path for a provider name (relative to the public base URL).
pub fn callback_path(provider_name: &str) -> String {
    format!(
        "/api/v1/auth/oauth/{}/callback",
        url::form_urlencoded::byte_serialize(provider_name.as_bytes()).collect::<String>()
    )
}

/// Full authorization URL with `state` and PKCE challenge, properly encoded.
pub fn authorize_url(
    provider: &OAuthProvider,
    redirect_uri: &str,
    state: &str,
    verifier: &str,
) -> String {
    let mut params = url::form_urlencoded::Serializer::new(String::new());
    params
        .append_pair("client_id", &provider.client_id)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", &provider.scopes)
        .append_pair("state", state)
        .append_pair("code_challenge", &code_challenge(verifier))
        .append_pair("code_challenge_method", "S256");
    if provider.provider_type == OAuthProviderType::Google {
        // Ask Google for a fresh consent only when needed; keeps the
        // repeated-login UX quiet.
        params.append_pair("access_type", "online");
    }
    let sep = if provider.auth_url.contains('?') {
        "&"
    } else {
        "?"
    };
    format!("{}{sep}{}", provider.auth_url, params.finish())
}

// ============================================================
// Token exchange + userinfo
// ============================================================

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    #[serde(default)]
    id_token: Option<String>,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
}

/// What the provider told us about the person who just consented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// Provider-scoped stable subject (`sub`, GitHub numeric `id`).
    pub subject: String,
    /// Email if the provider disclosed one.
    pub email: Option<String>,
    /// Whether the provider vouches for the email (`email_verified`, GitHub
    /// primary+verified). Unverified emails never link existing accounts.
    pub email_verified: bool,
    /// Display/login name for a provisioned username when there is no email.
    pub login: Option<String>,
}

fn http() -> Result<reqwest::Client, FlowError> {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent(concat!("AiFw/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| {
            tracing::error!(error = %e, "oauth: http client build failed");
            FlowError::Internal
        })
}

/// Redeem the authorization code for an access token.
pub async fn exchange_code(
    provider: &OAuthProvider,
    code: &str,
    redirect_uri: &str,
    verifier: &str,
) -> Result<String, FlowError> {
    let client = http()?;
    let body = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "authorization_code")
        .append_pair("code", code)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("client_id", &provider.client_id)
        .append_pair("client_secret", &provider.client_secret)
        .append_pair("code_verifier", verifier)
        .finish();
    let resp = client
        .post(&provider.token_url)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .await
        .map_err(|e| {
            tracing::warn!(provider = %provider.name, error = %e, "oauth: token endpoint unreachable");
            FlowError::Exchange
        })?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    let parsed: TokenResponse = serde_json::from_str(&body).map_err(|e| {
        tracing::warn!(provider = %provider.name, %status, error = %e, "oauth: token response not JSON");
        FlowError::Exchange
    })?;
    if let Some(err) = parsed.error {
        tracing::warn!(provider = %provider.name, %status, error = %err,
            description = parsed.error_description.as_deref().unwrap_or(""),
            "oauth: token endpoint refused the code");
        return Err(FlowError::Exchange);
    }
    if !status.is_success() {
        tracing::warn!(provider = %provider.name, %status, "oauth: token endpoint error");
        return Err(FlowError::Exchange);
    }
    let _ = parsed.id_token; // userinfo is the source of truth for every provider type
    parsed
        .access_token
        .filter(|t| !t.is_empty())
        .ok_or_else(|| {
            tracing::warn!(provider = %provider.name, "oauth: token response without access_token");
            FlowError::Exchange
        })
}

/// Read the userinfo endpoint and normalise it into an [`Identity`].
pub async fn fetch_identity(
    provider: &OAuthProvider,
    access_token: &str,
) -> Result<Identity, FlowError> {
    let client = http()?;
    let info: serde_json::Value = client
        .get(&provider.userinfo_url)
        .bearer_auth(access_token)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .map_err(|e| {
            tracing::warn!(provider = %provider.name, error = %e, "oauth: userinfo request failed");
            FlowError::Userinfo
        })?
        .json()
        .await
        .map_err(|e| {
            tracing::warn!(provider = %provider.name, error = %e, "oauth: userinfo not JSON");
            FlowError::Userinfo
        })?;

    let mut identity = identity_from_userinfo(provider.provider_type, &info).ok_or_else(|| {
        tracing::warn!(provider = %provider.name, "oauth: userinfo has no subject");
        FlowError::Userinfo
    })?;

    // GitHub hides the address unless it is public; the emails API returns
    // the verified primary for the `user:email` scope.
    if provider.provider_type == OAuthProviderType::Github && identity.email.is_none() {
        let emails_url = if provider.userinfo_url.ends_with("/user") {
            format!("{}/emails", provider.userinfo_url)
        } else {
            "https://api.github.com/user/emails".to_string()
        };
        if let Ok(resp) = client
            .get(&emails_url)
            .bearer_auth(access_token)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            && let Ok(list) = resp.json::<Vec<serde_json::Value>>().await
        {
            let pick = list
                .iter()
                .find(|e| {
                    e["primary"].as_bool() == Some(true) && e["verified"].as_bool() == Some(true)
                })
                .or_else(|| list.iter().find(|e| e["verified"].as_bool() == Some(true)));
            if let Some(e) = pick.and_then(|e| e["email"].as_str()) {
                identity.email = Some(e.to_string());
                identity.email_verified = true;
            }
        }
    }
    Ok(identity)
}

/// Pure normalisation of a userinfo document (testable without HTTP).
pub fn identity_from_userinfo(
    kind: OAuthProviderType,
    info: &serde_json::Value,
) -> Option<Identity> {
    let str_of = |k: &str| {
        info.get(k)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };
    match kind {
        OAuthProviderType::Github => {
            let subject = info.get("id").and_then(|v| {
                v.as_i64()
                    .map(|n| n.to_string())
                    .or_else(|| v.as_str().map(str::to_string))
            })?;
            Some(Identity {
                subject,
                // Public profile email; verification comes via /user/emails.
                email: str_of("email"),
                email_verified: false,
                login: str_of("login").or_else(|| str_of("name")),
            })
        }
        OAuthProviderType::Google | OAuthProviderType::Oidc => {
            let subject = str_of("sub")?;
            let verified = info
                .get("email_verified")
                .map(|v| v.as_bool() == Some(true) || v.as_str() == Some("true"))
                .unwrap_or(false);
            Some(Identity {
                subject,
                email: str_of("email"),
                email_verified: verified,
                login: str_of("preferred_username").or_else(|| str_of("name")),
            })
        }
    }
}

// ============================================================
// Account resolution
// ============================================================

/// Map an identity to a local user, linking or provisioning as policy allows.
pub async fn resolve_user(
    pool: &SqlitePool,
    provider: &OAuthProvider,
    identity: &Identity,
    auto_create: bool,
) -> Result<User, FlowError> {
    // 1. Existing link.
    let linked: Option<String> = sqlx::query_scalar(
        "SELECT user_id FROM oauth_identities WHERE provider_id = ?1 AND provider_user_id = ?2",
    )
    .bind(provider.id.to_string())
    .bind(&identity.subject)
    .fetch_optional(pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "oauth: identity lookup failed");
        FlowError::Internal
    })?;
    if let Some(uid) = linked {
        return match super::users::get_user_by_id(pool, &uid).await {
            Ok(Some(u)) => Ok(u),
            Ok(None) => {
                // Dangling link (user deleted) — drop it and fall through.
                let _ = sqlx::query("DELETE FROM oauth_identities WHERE user_id = ?1")
                    .bind(&uid)
                    .execute(pool)
                    .await;
                resolve_unlinked(pool, provider, identity, auto_create).await
            }
            Err(_) => Err(FlowError::Internal),
        };
    }
    resolve_unlinked(pool, provider, identity, auto_create).await
}

async fn resolve_unlinked(
    pool: &SqlitePool,
    provider: &OAuthProvider,
    identity: &Identity,
    auto_create: bool,
) -> Result<User, FlowError> {
    let email = identity
        .email
        .as_deref()
        .map(|e| e.trim().to_ascii_lowercase());

    // 2. Verified email that matches an existing local username → link.
    if identity.email_verified
        && let Some(email) = email.as_deref()
        && let Ok(Some(user)) = super::users::get_user_by_username(pool, email).await
    {
        link_identity(pool, &user, provider, identity).await?;
        return Ok(user);
    }

    // 3. Provision.
    if !auto_create {
        return Err(FlowError::NoAccount);
    }
    let base = match (&email, identity.email_verified, &identity.login) {
        (Some(e), true, _) => e.clone(),
        (_, _, Some(login)) => format!(
            "{}:{}",
            provider.name.to_ascii_lowercase(),
            login.to_ascii_lowercase()
        ),
        (Some(e), false, None) => e.clone(),
        _ => format!(
            "{}:{}",
            provider.name.to_ascii_lowercase(),
            identity.subject
        ),
    };
    let username = unique_username(pool, &base).await?;
    // Unusable password: OAuth accounts authenticate only through the
    // provider. Long random secret hashed with the normal Argon2 path.
    let random = format!("{}{}", Uuid::new_v4(), Uuid::new_v4());
    let pw_hash = super::password::hash_password(&random).map_err(|_| FlowError::Internal)?;
    let id = Uuid::new_v4();
    let now = chrono::Utc::now().to_rfc3339();
    sqlx::query(
        r#"INSERT INTO users (id, username, password_hash, totp_enabled, totp_secret, auth_provider, role, role_id, enabled, created_at)
           VALUES (?1, ?2, ?3, 0, NULL, ?4, 'viewer', 'builtin-viewer', 1, ?5)"#,
    )
    .bind(id.to_string())
    .bind(&username)
    .bind(&pw_hash)
    .bind(&provider.name)
    .bind(&now)
    .execute(pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "oauth: user provisioning failed");
        FlowError::Internal
    })?;
    let user = User {
        id,
        username,
        password_hash: pw_hash,
        totp_enabled: false,
        totp_secret: None,
        auth_provider: provider.name.clone(),
        role: "viewer".to_string(),
        role_id: Some("builtin-viewer".to_string()),
        enabled: true,
        created_at: now,
    };
    link_identity(pool, &user, provider, identity).await?;
    super::users::log_user_audit(
        pool,
        &user.id.to_string(),
        Some(&user.id.to_string()),
        "oauth_user_provisioned",
        Some(&format!("{} via {}", user.username, provider.name)),
    )
    .await;
    Ok(user)
}

async fn unique_username(pool: &SqlitePool, base: &str) -> Result<String, FlowError> {
    let base: String = base
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '@' | '.' | '_' | '-' | ':' | '+'))
        .take(120)
        .collect();
    let base = if base.is_empty() {
        "oauth-user".to_string()
    } else {
        base
    };
    for n in 0..100u32 {
        let candidate = if n == 0 {
            base.clone()
        } else {
            format!("{base}-{n}")
        };
        let taken: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE username = ?1")
            .bind(&candidate)
            .fetch_one(pool)
            .await
            .map_err(|_| FlowError::Internal)?;
        if taken == 0 {
            return Ok(candidate);
        }
    }
    Err(FlowError::Internal)
}

async fn link_identity(
    pool: &SqlitePool,
    user: &User,
    provider: &OAuthProvider,
    identity: &Identity,
) -> Result<(), FlowError> {
    sqlx::query(
        "INSERT INTO oauth_identities (id, user_id, provider_id, provider_user_id, email, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(user.id.to_string())
    .bind(provider.id.to_string())
    .bind(&identity.subject)
    .bind(identity.email.as_deref().unwrap_or(""))
    .bind(chrono::Utc::now().to_rfc3339())
    .execute(pool)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "oauth: identity link failed");
        FlowError::Internal
    })?;
    Ok(())
}

// ============================================================
// TOTP-pending tickets
// ============================================================

/// Create the pending-login table (idempotent).
pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS oauth_pending_logins (
            ticket TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            provider TEXT NOT NULL,
            created_at TEXT NOT NULL
        )"#,
    )
    .execute(pool)
    .await?;
    for stmt in [
        "ALTER TABLE oauth_states ADD COLUMN code_verifier TEXT",
        "ALTER TABLE oauth_states ADD COLUMN redirect_uri TEXT",
    ] {
        if let Err(e) = sqlx::query(stmt).execute(pool).await
            && !e.to_string().contains("duplicate column")
        {
            return Err(e);
        }
    }
    Ok(())
}

/// Issue a single-use ticket that lets the browser finish an OAuth login
/// with a TOTP code.
pub async fn issue_pending(
    pool: &SqlitePool,
    user_id: &str,
    provider: &str,
) -> Result<String, FlowError> {
    let ticket = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO oauth_pending_logins (ticket, user_id, provider, created_at) VALUES (?1, ?2, ?3, ?4)",
    )
    .bind(&ticket)
    .bind(user_id)
    .bind(provider)
    .bind(chrono::Utc::now().to_rfc3339())
    .execute(pool)
    .await
    .map_err(|_| FlowError::Internal)?;
    Ok(ticket)
}

/// Consume a pending ticket; returns the user id if it was valid and fresh.
pub async fn consume_pending(pool: &SqlitePool, ticket: &str) -> Option<String> {
    let cutoff = (chrono::Utc::now() - chrono::Duration::seconds(PENDING_TTL_SECS)).to_rfc3339();
    let _ = sqlx::query("DELETE FROM oauth_pending_logins WHERE created_at < ?1")
        .bind(&cutoff)
        .execute(pool)
        .await;
    sqlx::query_scalar::<_, String>(
        "DELETE FROM oauth_pending_logins WHERE ticket = ?1 RETURNING user_id",
    )
    .bind(ticket)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn pkce_challenge_is_s256_of_verifier() {
        // RFC 7636 appendix B vector
        let v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(
            code_challenge(v),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        let fresh = new_code_verifier();
        assert!(
            fresh.len() >= 43
                && fresh
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn authorize_url_is_encoded_and_carries_pkce() {
        let p = OAuthProvider::google("cid", "sec");
        let u = authorize_url(
            &p,
            "https://fw.example.com:8080/api/v1/auth/oauth/Google/callback",
            "st ate",
            "ver",
        );
        assert!(u.starts_with("https://accounts.google.com/o/oauth2/v2/auth?client_id=cid&"));
        assert!(u.contains("redirect_uri=https%3A%2F%2Ffw.example.com%3A8080%2Fapi%2Fv1%2Fauth%2Foauth%2FGoogle%2Fcallback"));
        assert!(u.contains("scope=openid+email+profile"));
        assert!(u.contains("state=st+ate"));
        assert!(u.contains(&format!("code_challenge={}", code_challenge("ver"))));
        assert!(u.contains("code_challenge_method=S256"));
    }

    #[test]
    fn userinfo_normalisation() {
        let g = identity_from_userinfo(
            OAuthProviderType::Google,
            &json!({"sub":"123","email":"A@Example.com","email_verified":true,"name":"A"}),
        )
        .unwrap();
        assert_eq!(g.subject, "123");
        assert!(g.email_verified);
        let o = identity_from_userinfo(OAuthProviderType::Oidc, &json!({"sub":"x","email":"a@b"}))
            .unwrap();
        assert!(
            !o.email_verified,
            "missing email_verified claim ⇒ unverified"
        );
        let gh = identity_from_userinfo(
            OAuthProviderType::Github,
            &json!({"id": 42, "login":"octo", "email": null}),
        )
        .unwrap();
        assert_eq!(gh.subject, "42");
        assert_eq!(gh.login.as_deref(), Some("octo"));
        assert!(gh.email.is_none());
        assert!(identity_from_userinfo(OAuthProviderType::Oidc, &json!({"email":"a@b"})).is_none());
    }
}
