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

    /// Build the authorization URL with state parameter
    pub fn authorize_url(&self, redirect_uri: &str, state: &str) -> String {
        format!(
            "{}?client_id={}&redirect_uri={}&response_type=code&scope={}&state={}",
            self.auth_url,
            url_encode(&self.client_id),
            url_encode(redirect_uri),
            url_encode(&self.scopes),
            url_encode(state),
        )
    }
}

/// Linked OAuth identity for a user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthIdentity {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider_id: Uuid,
    pub provider_user_id: String,
    pub email: String,
    pub created_at: String,
}

/// User info returned from OAuth provider
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthUserInfo {
    pub provider_user_id: String,
    pub email: String,
    pub name: Option<String>,
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
    .bind(&provider.client_secret)
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
        .map(|(id, name, pt, ci, cs, au, tu, uu, sc, en, ca)| OAuthProvider {
            id: Uuid::parse_str(&id).unwrap_or_default(),
            name,
            provider_type: match pt.as_str() {
                "google" => OAuthProviderType::Google,
                "github" => OAuthProviderType::Github,
                _ => OAuthProviderType::Oidc,
            },
            client_id: ci,
            client_secret: cs,
            auth_url: au,
            token_url: tu,
            userinfo_url: uu,
            scopes: sc,
            enabled: en,
            created_at: ca,
        })
        .collect())
}

pub async fn get_provider_by_name(pool: &SqlitePool, name: &str) -> Result<Option<OAuthProvider>, String> {
    let providers = list_providers(pool).await?;
    Ok(providers.into_iter().find(|p| p.name.to_lowercase() == name.to_lowercase()))
}

pub async fn delete_provider(pool: &SqlitePool, id: Uuid) -> Result<(), String> {
    sqlx::query("DELETE FROM oauth_providers WHERE id = ?1")
        .bind(id.to_string())
        .execute(pool)
        .await
        .map_err(|e| format!("db error: {e}"))?;
    Ok(())
}

pub async fn save_identity(pool: &SqlitePool, identity: &OAuthIdentity) -> Result<(), String> {
    sqlx::query(
        r#"INSERT INTO oauth_identities (id, user_id, provider_id, provider_user_id, email, created_at)
           VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
    )
    .bind(identity.id.to_string())
    .bind(identity.user_id.to_string())
    .bind(identity.provider_id.to_string())
    .bind(&identity.provider_user_id)
    .bind(&identity.email)
    .bind(&identity.created_at)
    .execute(pool)
    .await
    .map_err(|e| format!("db error: {e}"))?;
    Ok(())
}

pub async fn find_identity_by_provider_user(
    pool: &SqlitePool,
    provider_id: Uuid,
    provider_user_id: &str,
) -> Result<Option<OAuthIdentity>, String> {
    let row = sqlx::query_as::<_, (String, String, String, String, String, String)>(
        "SELECT id, user_id, provider_id, provider_user_id, email, created_at FROM oauth_identities WHERE provider_id = ?1 AND provider_user_id = ?2"
    )
    .bind(provider_id.to_string())
    .bind(provider_user_id)
    .fetch_optional(pool)
    .await
    .map_err(|e| format!("db error: {e}"))?;

    Ok(row.map(|(id, uid, pid, puid, email, ca)| OAuthIdentity {
        id: Uuid::parse_str(&id).unwrap_or_default(),
        user_id: Uuid::parse_str(&uid).unwrap_or_default(),
        provider_id: Uuid::parse_str(&pid).unwrap_or_default(),
        provider_user_id: puid,
        email,
        created_at: ca,
    }))
}

fn url_encode(s: &str) -> String {
    s.replace(' ', "+")
        .replace(':', "%3A")
        .replace('/', "%2F")
        .replace('@', "%40")
        .replace('&', "%26")
        .replace('=', "%3D")
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
    pub code: String,
    pub state: String,
}
