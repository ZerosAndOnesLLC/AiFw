use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;

/// Global auth settings (stored in DB, loaded at startup)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSettings {
    #[serde(skip_serializing)]
    pub jwt_secret: String,
    /// Access token expiry in minutes (default 15)
    pub access_token_expiry_mins: i64,
    /// Refresh token expiry in days (default 7)
    pub refresh_token_expiry_days: i64,
    /// Require TOTP for all local users
    pub require_totp: bool,
    /// Require TOTP for OAuth2 users too
    pub require_totp_for_oauth: bool,
    /// Auto-create local user on first OAuth2 login
    pub auto_create_oauth_users: bool,
}

impl Default for AuthSettings {
    fn default() -> Self {
        // Generate 256-bit secret from two UUIDs (2 × 128-bit = 256-bit entropy)
        let jwt_secret = format!(
            "{}{}",
            uuid::Uuid::new_v4().to_string().replace('-', ""),
            uuid::Uuid::new_v4().to_string().replace('-', ""),
        );
        Self {
            jwt_secret,
            access_token_expiry_mins: 480,
            refresh_token_expiry_days: 30,
            require_totp: false,
            require_totp_for_oauth: false,
            auto_create_oauth_users: true,
        }
    }
}

impl AuthSettings {
    /// Load settings from DB, falling back to defaults
    pub async fn load(pool: &SqlitePool) -> Self {
        let mut settings = Self::default();

        let rows = sqlx::query_as::<_, (String, String)>(
            "SELECT key, value FROM auth_config",
        )
        .fetch_all(pool)
        .await
        .unwrap_or_default();

        for (key, value) in rows {
            match key.as_str() {
                "jwt_secret" => settings.jwt_secret = value,
                "access_token_expiry_mins" => {
                    settings.access_token_expiry_mins = value.parse().unwrap_or(15);
                }
                "refresh_token_expiry_days" => {
                    settings.refresh_token_expiry_days = value.parse().unwrap_or(7);
                }
                "require_totp" => settings.require_totp = value == "true",
                "require_totp_for_oauth" => settings.require_totp_for_oauth = value == "true",
                "auto_create_oauth_users" => settings.auto_create_oauth_users = value == "true",
                _ => {}
            }
        }

        settings
    }

    /// Save a setting to DB
    pub async fn save_setting(pool: &SqlitePool, key: &str, value: &str) -> Result<(), String> {
        sqlx::query(
            "INSERT OR REPLACE INTO auth_config (key, value) VALUES (?1, ?2)",
        )
        .bind(key)
        .bind(value)
        .execute(pool)
        .await
        .map_err(|e| format!("db error: {e}"))?;
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct UpdateAuthSettingsRequest {
    pub access_token_expiry_mins: Option<i64>,
    pub refresh_token_expiry_days: Option<i64>,
    pub require_totp: Option<bool>,
    pub require_totp_for_oauth: Option<bool>,
    pub auto_create_oauth_users: Option<bool>,
}
