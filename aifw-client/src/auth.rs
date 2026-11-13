//! Credentials: API keys, bearer tokens, and refreshable login sessions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Refresh a session this long before its access token expires, so a
/// request doesn't race the expiry.
const REFRESH_SKEW_SECS: i64 = 30;

/// Token pair returned by `/auth/login`, `/auth/totp/login` and `/auth/refresh`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default)]
    pub access_expires_at: Option<String>,
    #[serde(default)]
    pub refresh_expires_at: Option<String>,
}

/// A logged-in session that can renew itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: Option<DateTime<Utc>>,
}

impl Session {
    pub fn from_tokens(t: &TokenPair) -> Self {
        Self {
            access_token: t.access_token.clone(),
            refresh_token: t.refresh_token.clone(),
            access_expires_at: t
                .access_expires_at
                .as_deref()
                .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                .map(|t| t.with_timezone(&Utc)),
        }
    }

    /// True when the access token is expired or about to be.
    pub fn needs_refresh(&self, now: DateTime<Utc>) -> bool {
        self.access_expires_at
            .is_some_and(|exp| (exp - now).num_seconds() <= REFRESH_SKEW_SECS)
    }
}

/// How requests authenticate.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum Auth {
    #[default]
    None,
    /// `Authorization: ApiKey <key>`
    ApiKey(String),
    /// `Authorization: Bearer <jwt>` (not refreshable)
    Bearer(String),
    /// Bearer JWT that refreshes itself through `/auth/refresh`.
    Session(Session),
}

impl Auth {
    /// The `Authorization` header value, if any.
    pub fn header(&self) -> Option<String> {
        match self {
            Auth::None => None,
            Auth::ApiKey(k) => Some(format!("ApiKey {k}")),
            Auth::Bearer(t) => Some(format!("Bearer {t}")),
            Auth::Session(s) => Some(format!("Bearer {}", s.access_token)),
        }
    }

    /// Short label for `whoami` / diagnostics — never the secret.
    pub fn kind(&self) -> &'static str {
        match self {
            Auth::None => "none",
            Auth::ApiKey(_) => "api-key",
            Auth::Bearer(_) => "bearer",
            Auth::Session(_) => "session",
        }
    }
}

/// Classify a raw token (from `AIFW_TOKEN`, `--api-key`, a key file): AiFw
/// API keys start with `aifw_`; anything else is treated as a bearer JWT.
/// Internal keys (daemon loopback) are 64 hex chars with no prefix, so a
/// bare 64-hex string is also an API key.
pub fn credential_from_token(token: &str) -> Auth {
    let t = token.trim();
    if t.is_empty() {
        return Auth::None;
    }
    let is_internal_key = t.len() == 64 && t.bytes().all(|b| b.is_ascii_hexdigit());
    if t.starts_with("aifw_") || is_internal_key {
        Auth::ApiKey(t.to_string())
    } else {
        Auth::Bearer(t.to_string())
    }
}

/// Where a refreshed session is persisted. Refresh tokens rotate on every
/// use and reusing an old one revokes the whole family, so the new pair
/// must be saved before it is used again.
pub trait SessionStore: Send + Sync {
    fn save(&self, tokens: &TokenPair) -> std::result::Result<(), String>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn token_classification() {
        assert_eq!(
            credential_from_token("aifw_0123456789abcdef"),
            Auth::ApiKey("aifw_0123456789abcdef".into())
        );
        let hex64 = "ab".repeat(32);
        assert_eq!(credential_from_token(&hex64), Auth::ApiKey(hex64.clone()));
        assert_eq!(
            credential_from_token("eyJhbGciOi.x.y"),
            Auth::Bearer("eyJhbGciOi.x.y".into())
        );
        assert_eq!(credential_from_token("  \n"), Auth::None);
        assert_eq!(
            credential_from_token("aifw_k\n"),
            Auth::ApiKey("aifw_k".into()),
            "trailing newline from a key file is trimmed"
        );
    }

    #[test]
    fn headers() {
        assert_eq!(
            Auth::ApiKey("k".into()).header().as_deref(),
            Some("ApiKey k")
        );
        assert_eq!(
            Auth::Bearer("t".into()).header().as_deref(),
            Some("Bearer t")
        );
        assert_eq!(Auth::None.header(), None);
        let s = Session {
            access_token: "a".into(),
            refresh_token: "r".into(),
            access_expires_at: None,
        };
        assert_eq!(Auth::Session(s).header().as_deref(), Some("Bearer a"));
    }

    #[test]
    fn refresh_timing() {
        let now = Utc::now();
        let pair = TokenPair {
            access_token: "a".into(),
            refresh_token: "r".into(),
            access_expires_at: Some((now + Duration::minutes(10)).to_rfc3339()),
            refresh_expires_at: None,
        };
        let s = Session::from_tokens(&pair);
        assert!(!s.needs_refresh(now));
        assert!(s.needs_refresh(now + Duration::minutes(10) - Duration::seconds(5)));
        let no_exp = Session {
            access_expires_at: None,
            ..s
        };
        assert!(
            !no_exp.needs_refresh(now),
            "unknown expiry: rely on 401 retry"
        );
    }
}
