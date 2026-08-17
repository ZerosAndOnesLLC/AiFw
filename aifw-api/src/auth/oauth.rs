use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use uuid::Uuid;

// ============================================================
// OAuth2 Provider Configuration
// ============================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum OAuthProviderType {
    Google,
    Github,
    Oidc,
}

impl std::fmt::Display for OAuthProviderType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OAuthProviderType::Google => write!(f, "google"),
            OAuthProviderType::Github => write!(f, "github"),
            OAuthProviderType::Oidc => write!(f, "oidc"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthProvider {
    pub id: Uuid,
    pub name: String,
    pub provider_type: OAuthProviderType,
    pub client_id: String,
    #[serde(skip_serializing)]
    pub client_secret: String,
    pub auth_url: String,
    pub token_url: String,
    pub userinfo_url: String,
    pub scopes: String,
    pub enabled: bool,
    pub created_at: String,
}

impl OAuthProvider {
    /// Create a Google provider with well-known endpoints
    pub fn google(client_id: &str, client_secret: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: "Google".to_string(),
            provider_type: OAuthProviderType::Google,
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_url: "https://oauth2.googleapis.com/token".to_string(),
            userinfo_url: "https://openidconnect.googleapis.com/v1/userinfo".to_string(),
            scopes: "openid email profile".to_string(),
            enabled: true,
            created_at: Utc::now().to_rfc3339(),
        }
    }

    /// Create a GitHub provider with well-known endpoints
    pub fn github(client_id: &str, client_secret: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: "GitHub".to_string(),
            provider_type: OAuthProviderType::Github,
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            auth_url: "https://github.com/login/oauth/authorize".to_string(),
            token_url: "https://github.com/login/oauth/access_token".to_string(),
            userinfo_url: "https://api.github.com/user".to_string(),
            scopes: "read:user user:email".to_string(),
            enabled: true,
            created_at: Utc::now().to_rfc3339(),
        }
    }
}

// ============================================================
// DB operations
// ============================================================

pub async fn save_provider(pool: &SqlitePool, provider: &OAuthProvider) -> Result<(), String> {
    sqlx::query(
        r#"INSERT INTO oauth_providers (id, name, provider_type, client_id, client_secret,
           auth_url, token_url, userinfo_url, scopes, enabled, created_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"#,
    )
    .bind(provider.id.to_string())
    .bind(&provider.name)
    .bind(provider.provider_type.to_string())
    .bind(&provider.client_id)
    // #298: sealed at rest
    .bind(
        aifw_core::secrets::seal(&provider.client_secret)
            .map_err(|e| format!("seal client_secret: {e}"))?,
    )
    .bind(&provider.auth_url)
    .bind(&provider.token_url)
    .bind(&provider.userinfo_url)
    .bind(&provider.scopes)
    .bind(provider.enabled)
    .bind(&provider.created_at)
    .execute(pool)
    .await
    .map_err(|e| format!("db error: {e}"))?;
    Ok(())
}

pub async fn list_providers(pool: &SqlitePool) -> Result<Vec<OAuthProvider>, String> {
    let rows = sqlx::query_as::<_, (String, String, String, String, String, String, String, String, String, bool, String)>(
        "SELECT id, name, provider_type, client_id, client_secret, auth_url, token_url, userinfo_url, scopes, enabled, created_at FROM oauth_providers ORDER BY name"
    )
    .fetch_all(pool)
    .await
    .map_err(|e| format!("db error: {e}"))?;

    Ok(rows
        .into_iter()
        .map(
            |(id, name, pt, ci, cs, au, tu, uu, sc, en, ca)| OAuthProvider {
                id: Uuid::parse_str(&id).unwrap_or_default(),
                name,
                provider_type: match pt.as_str() {
                    "google" => OAuthProviderType::Google,
                    "github" => OAuthProviderType::Github,
                    _ => OAuthProviderType::Oidc,
                },
                client_id: ci,
                client_secret: aifw_core::secrets::open_lossy(&cs),
                auth_url: au,
                token_url: tu,
                userinfo_url: uu,
                scopes: sc,
                enabled: en,
                created_at: ca,
            },
        )
        .collect())
}

pub async fn get_provider_by_name(
    pool: &SqlitePool,
    name: &str,
) -> Result<Option<OAuthProvider>, String> {
    let providers = list_providers(pool).await?;
    Ok(providers
        .into_iter()
        .find(|p| p.name.to_lowercase() == name.to_lowercase()))
}

pub async fn delete_provider(pool: &SqlitePool, id: Uuid) -> Result<(), String> {
    sqlx::query("DELETE FROM oauth_providers WHERE id = ?1")
        .bind(id.to_string())
        .execute(pool)
        .await
        .map_err(|e| format!("db error: {e}"))?;
    Ok(())
}

// ============================================================
// SEC-H9: OAuth CSRF state store
// ============================================================

/// How long an issued `state` nonce remains valid between authorize and
/// callback. OAuth round-trips complete in seconds; 10 minutes is generous
/// while keeping the store self-cleaning.
const OAUTH_STATE_TTL_SECS: i64 = 600;

/// What was stored alongside a `state` nonce at authorize time (#170).
#[derive(Debug, Clone)]
pub struct PendingAuthorize {
    /// PKCE code verifier to send with the token exchange.
    pub code_verifier: String,
    /// Exact redirect URI used in the authorize request (must repeat).
    pub redirect_uri: String,
}

/// Persist a freshly-issued `state` nonce bound to a provider, together
/// with the PKCE verifier and redirect URI the callback must reuse.
pub async fn save_state(
    pool: &SqlitePool,
    state: &str,
    provider: &str,
    pending: &PendingAuthorize,
) -> Result<(), String> {
    sqlx::query(
        "INSERT OR REPLACE INTO oauth_states (state, provider, created_at, code_verifier, redirect_uri) VALUES (?1, ?2, ?3, ?4, ?5)",
    )
    .bind(state)
    .bind(provider)
    .bind(Utc::now().to_rfc3339())
    .bind(&pending.code_verifier)
    .bind(&pending.redirect_uri)
    .execute(pool)
    .await
    .map_err(|e| format!("db error: {e}"))?;
    Ok(())
}

/// Consume a `state` nonce at the callback: it must exist, match the
/// provider, and be unexpired. The row is deleted so a nonce is single-use
/// (replay-proof). Returns what was stored at authorize time iff the state
/// was valid. Expired rows are swept opportunistically.
pub async fn consume_state(
    pool: &SqlitePool,
    state: &str,
    provider: &str,
) -> Option<PendingAuthorize> {
    // Best-effort GC of stale nonces.
    let cutoff = (Utc::now() - chrono::Duration::seconds(OAUTH_STATE_TTL_SECS)).to_rfc3339();
    let _ = sqlx::query("DELETE FROM oauth_states WHERE created_at < ?1")
        .bind(&cutoff)
        .execute(pool)
        .await;

    let row = sqlx::query_as::<_, (String, String, Option<String>, Option<String>)>(
        "DELETE FROM oauth_states WHERE state = ?1 RETURNING provider, created_at, code_verifier, redirect_uri",
    )
    .bind(state)
    .fetch_optional(pool)
    .await
    .unwrap_or(None);

    let (row_provider, created_at, verifier, redirect_uri) = row?;
    let fresh = chrono::DateTime::parse_from_rfc3339(&created_at)
        .map(|c| (Utc::now() - c.with_timezone(&Utc)).num_seconds() <= OAUTH_STATE_TTL_SECS)
        .unwrap_or(false);
    if !(fresh && row_provider.eq_ignore_ascii_case(provider)) {
        return None;
    }
    Some(PendingAuthorize {
        code_verifier: verifier.unwrap_or_default(),
        redirect_uri: redirect_uri.unwrap_or_default(),
    })
}

// ============================================================
// Request/Response types
// ============================================================

#[derive(Debug, Deserialize)]
pub struct CreateProviderRequest {
    pub name: String,
    pub provider_type: String,
    pub client_id: String,
    pub client_secret: String,
    pub auth_url: Option<String>,
    pub token_url: Option<String>,
    pub userinfo_url: Option<String>,
    pub scopes: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AuthorizeResponse {
    pub authorize_url: String,
    pub state: String,
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    #[serde(default)]
    pub code: String,
    #[serde(default)]
    pub state: String,
    /// Provider-side denial (`access_denied`, …).
    #[serde(default)]
    pub error: Option<String>,
}

/// Body of `POST /auth/oauth/totp` — finish a TOTP-gated OAuth login.
#[derive(Debug, Deserialize)]
pub struct OAuthTotpRequest {
    pub ticket: String,
    pub totp_code: String,
}

/// Public login options for the sign-in page (no secrets).
#[derive(Debug, Serialize)]
pub struct LoginOption {
    pub name: String,
    pub provider_type: OAuthProviderType,
}

/// `GET/PUT /auth/oauth/settings`.
#[derive(Debug, Serialize, Deserialize)]
pub struct OAuthSettings {
    /// Externally reachable base URL used to build the callback redirect
    /// URI; empty ⇒ derived from the request `Host`.
    #[serde(default)]
    pub public_url: String,
}
