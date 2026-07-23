//! Session cookies for the browser UI (SEC-M7 #304).
//!
//! The web UI authenticates with `HttpOnly` cookies instead of storing the
//! JWT in `localStorage`, so an XSS bug can no longer exfiltrate the token.
//! Non-browser clients (CLI, API keys, scripts) keep using `Authorization`
//! headers — cookies are an additional credential source, not a replacement.
//!
//! Two cookies are issued at login and rotated on refresh:
//! - [`ACCESS_COOKIE`]: the access JWT, sent on every request (`Path=/`).
//! - [`REFRESH_COOKIE`]: the refresh token, scoped to `Path=/api/v1/auth` so
//!   it only travels to the refresh/logout endpoints.
//!
//! Both are `HttpOnly; SameSite=Strict`, plus `Secure` when the API serves
//! TLS. Cross-site request forgery is blocked twice over: `SameSite=Strict`
//! keeps browsers from attaching the cookies cross-site at all, and the auth
//! middleware additionally requires the custom [`CSRF_HEADER`] on unsafe
//! methods when the credential came from a cookie (a cross-site page cannot
//! set custom headers without a CORS preflight, and credentialed cross-origin
//! requests are never approved — the CORS layer does not allow credentials).

use axum::http::{HeaderMap, HeaderValue};

use super::config::AuthSettings;
use super::tokens::TokenPair;

/// Access-token cookie: the JWT, attached to every same-site request.
pub const ACCESS_COOKIE: &str = "aifw_at";
/// Refresh-token cookie, scoped to the auth endpoints only.
pub const REFRESH_COOKIE: &str = "aifw_rt";
/// Path scope for [`REFRESH_COOKIE`].
const REFRESH_PATH: &str = "/api/v1/auth";
/// Header the UI sends on every request; required by the auth middleware for
/// unsafe methods when authenticating via cookie (CSRF defense in depth).
pub const CSRF_HEADER: &str = "x-aifw-csrf";

/// Read a cookie's value from the request headers. Handles multiple `Cookie`
/// headers and the standard `name=value; name2=value2` form.
pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    for header in headers.get_all(axum::http::header::COOKIE) {
        let Ok(s) = header.to_str() else { continue };
        for pair in s.split(';') {
            let mut it = pair.trim().splitn(2, '=');
            if it.next() == Some(name) {
                return Some(it.next().unwrap_or("").to_string());
            }
        }
    }
    None
}

fn build_cookie(name: &str, value: &str, path: &str, max_age_secs: i64, secure: bool) -> String {
    let secure = if secure { "; Secure" } else { "" };
    format!(
        "{name}={value}; Path={path}; Max-Age={max_age_secs}; HttpOnly; SameSite=Strict{secure}"
    )
}

/// `Set-Cookie` values installing a freshly issued token pair.
pub fn session_cookies(
    tokens: &TokenPair,
    settings: &AuthSettings,
    secure: bool,
) -> Vec<HeaderValue> {
    let access = build_cookie(
        ACCESS_COOKIE,
        &tokens.access_token,
        "/",
        settings.access_token_expiry_mins.max(0) * 60,
        secure,
    );
    let refresh = build_cookie(
        REFRESH_COOKIE,
        &tokens.refresh_token,
        REFRESH_PATH,
        settings.refresh_token_expiry_days.max(0) * 86_400,
        secure,
    );
    // The values are ASCII we produced ourselves (JWT / rfx_ hex + fixed
    // attributes), so HeaderValue conversion cannot fail.
    [access, refresh]
        .into_iter()
        .filter_map(|c| HeaderValue::from_str(&c).ok())
        .collect()
}

/// `Set-Cookie` values expiring both session cookies (logout).
pub fn clear_cookies(secure: bool) -> Vec<HeaderValue> {
    [
        build_cookie(ACCESS_COOKIE, "", "/", 0, secure),
        build_cookie(REFRESH_COOKIE, "", REFRESH_PATH, 0, secure),
    ]
    .into_iter()
    .filter_map(|c| HeaderValue::from_str(&c).ok())
    .collect()
}

/// Append `Set-Cookie` headers onto a response's header map.
pub fn append_set_cookies(headers: &mut HeaderMap, cookies: Vec<HeaderValue>) {
    for c in cookies {
        headers.append(axum::http::header::SET_COOKIE, c);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> AuthSettings {
        AuthSettings {
            jwt_secret: "s".into(),
            access_token_expiry_mins: 60,
            refresh_token_expiry_days: 7,
            ..AuthSettings::default()
        }
    }

    fn pair() -> TokenPair {
        TokenPair {
            access_token: "jwt-value".into(),
            refresh_token: "rfx_abc".into(),
            access_expires_at: String::new(),
            refresh_expires_at: String::new(),
            token_type: "Bearer".into(),
        }
    }

    #[test]
    fn parses_cookie_header() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("foo=1; aifw_at=tok.en; bar=2"),
        );
        assert_eq!(cookie_value(&h, ACCESS_COOKIE).as_deref(), Some("tok.en"));
        assert_eq!(cookie_value(&h, REFRESH_COOKIE), None);
    }

    #[test]
    fn session_cookies_are_httponly_samesite_strict() {
        for c in session_cookies(&pair(), &settings(), false) {
            let s = c.to_str().unwrap();
            assert!(s.contains("HttpOnly"), "{s}");
            assert!(s.contains("SameSite=Strict"), "{s}");
            assert!(!s.contains("Secure"), "{s}");
        }
    }

    #[test]
    fn secure_flag_follows_tls() {
        for c in session_cookies(&pair(), &settings(), true) {
            assert!(c.to_str().unwrap().contains("; Secure"));
        }
    }

    #[test]
    fn refresh_cookie_is_path_scoped() {
        let cookies = session_cookies(&pair(), &settings(), false);
        let refresh = cookies[1].to_str().unwrap();
        assert!(
            refresh.starts_with("aifw_rt=rfx_abc; Path=/api/v1/auth;"),
            "{refresh}"
        );
        let access = cookies[0].to_str().unwrap();
        assert!(access.starts_with("aifw_at=jwt-value; Path=/;"), "{access}");
    }

    #[test]
    fn clear_cookies_expire_immediately() {
        for c in clear_cookies(false) {
            assert!(c.to_str().unwrap().contains("Max-Age=0"));
        }
    }
}
