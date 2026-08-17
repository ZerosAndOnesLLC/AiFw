//! The request auth middleware plus the RBAC guards: `auth_middleware`
//! resolves a JWT / API-key / WS-ticket credential into an `AuthUser`
//! extension, and the `perm_check!` macro gates routes on a permission.

use axum::{
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
};

use super::api_keys::verify_api_key;
use super::revocation::is_token_revoked;
use super::tokens::{self, verify_access_token};
use super::users::get_user_by_id;

/// PERF-C12: TTL for the user-by-id cache. Short enough that a disabled or
/// role-changed user is locked out / re-scoped within the window; long
/// enough that the dashboard's multi-Hz polls don't all hit SQLite.
const AUTH_USER_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(5);
/// PERF-C12: TTL for the JTI revocation cache. Once a token is revoked it
/// stays revoked for its remaining lifetime; we cache the *positive*
/// not-revoked result for 60 s so logout takes effect within the window.
const AUTH_JTI_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60);
/// PERF-H21: cap on how long a decoded JWT is trusted from cache. Entries are
/// also bounded by the token's own `exp`; this cap only limits how long a
/// rotated `jwt_secret` could keep an old token accepted.
const AUTH_TOKEN_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(60);
/// PERF-H21: soft ceiling on decoded-token cache entries. On reaching it we
/// sweep expired entries before inserting, keeping memory bounded without a
/// background task.
const AUTH_TOKEN_CACHE_MAX: usize = 10_000;

/// PERF-H21: seconds a decoded JWT may stay cached — the smaller of the
/// token's remaining lifetime and [`AUTH_TOKEN_CACHE_TTL`]. Returns 0 for an
/// already-expired token so it is effectively never cached, ensuring an
/// expired token can't be served from a live cache entry.
fn token_cache_ttl_secs(exp_unix: i64, now_unix: i64) -> u64 {
    let remaining = (exp_unix - now_unix).max(0) as u64;
    remaining.min(AUTH_TOKEN_CACHE_TTL.as_secs())
}

pub async fn auth_middleware(
    State(state): State<crate::AppState>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    use aifw_common::permission::PermissionSet;
    use std::time::Instant;

    // Credentials: Authorization: Bearer <jwt>, Authorization: ApiKey <key>,
    // ?ticket=<id> (short-lived, single-use; see auth::ws_ticket), or the
    // HttpOnly session cookie set at login (SEC-M7 #304 — browser UI).
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());

    // The cookie is a fallback only: an Authorization header or ticket wins,
    // so non-browser clients and the WS/SSE ticket flow are unaffected.
    let cookie_token = if auth_header.is_none() && query_ticket(request.uri().query()).is_none() {
        super::cookies::cookie_value(&headers, super::cookies::ACCESS_COOKIE)
    } else {
        None
    };

    // CSRF defense in depth (on top of SameSite=Strict): a cookie is attached
    // by the browser, not the page, so state-changing requests must also carry
    // the custom header only same-origin script can set.
    if cookie_token.is_some()
        && !matches!(
            *request.method(),
            axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
        )
        && !headers.contains_key(super::cookies::CSRF_HEADER)
    {
        return Err(StatusCode::FORBIDDEN);
    }

    // Resolve (user_id, perm_from_token, role_from_token, api_key_name) from the credential
    let (user_id, jwt_perm, jwt_role, api_key_name) = if let Some(token) = auth_header
        .and_then(|h| h.strip_prefix("Bearer "))
        .or(cookie_token.as_deref())
    {
        // PERF-H21: reuse a previously decoded token. The entry deadline
        // is capped at the token's `exp` on insert, so a live cache hit
        // is always still within the token's validity window.
        let now = Instant::now();
        let claims = if let Some(entry) = state.auth_token_cache.get(token)
            && entry.value().1 > now
        {
            entry.value().0.clone()
        } else {
            let claims = verify_access_token(token, &state.auth_settings)
                .map_err(|_| StatusCode::UNAUTHORIZED)?
                .claims;
            // Cap TTL at the token's remaining lifetime (never negative),
            // and at AUTH_TOKEN_CACHE_TTL so a rotated jwt_secret can't
            // keep validating an old token for longer than that window.
            let ttl = std::time::Duration::from_secs(token_cache_ttl_secs(
                claims.exp,
                chrono::Utc::now().timestamp(),
            ));
            // Bound memory: sweep expired entries when the map grows large
            // (these caches are otherwise evicted only lazily).
            if state.auth_token_cache.len() >= AUTH_TOKEN_CACHE_MAX {
                state
                    .auth_token_cache
                    .retain(|_, (_, deadline)| *deadline > now);
            }
            state
                .auth_token_cache
                .insert(token.to_string(), (claims.clone(), now + ttl));
            claims
        };
        let jti = &claims.jti;
        // JTI revocation: positive cache to skip the DB lookup. Cached
        // entry value=true means revoked, value=false means not revoked.
        let revoked = if let Some(entry) = state.auth_jti_cache.get(jti)
            && entry.value().1 > now
        {
            entry.value().0
        } else {
            let r = is_token_revoked(&state.pool, jti).await;
            state
                .auth_jti_cache
                .insert(jti.clone(), (r, now + AUTH_JTI_CACHE_TTL));
            r
        };
        if revoked {
            return Err(StatusCode::UNAUTHORIZED);
        }
        (claims.sub, claims.perm, claims.role, None)
    } else if let Some(key) = auth_header.and_then(|h| h.strip_prefix("ApiKey ")) {
        let (uid, key_name) = verify_api_key(&state.pool, key).await?;
        (uid, None, None, Some(key_name)) // API keys don't carry JWT claims — will do DB lookup
    } else if let Some(ticket_id) = query_ticket(request.uri().query()) {
        let uid = state
            .ws_tickets
            .consume(&ticket_id)
            .await
            .ok_or(StatusCode::UNAUTHORIZED)?;
        (uid, None, None, None) // tickets inherit permissions from the DB row
    } else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    // User-by-id with TTL cache. Disabled-user lockout has up to
    // AUTH_USER_CACHE_TTL latency — acceptable trade for skipping a DB hit
    // on every authenticated request.
    let now = Instant::now();
    let user = if let Some(entry) = state.auth_user_cache.get(&user_id)
        && entry.value().1 > now
    {
        entry.value().0.clone()
    } else {
        let u = get_user_by_id(&state.pool, &user_id)
            .await?
            .ok_or(StatusCode::UNAUTHORIZED)?;
        state
            .auth_user_cache
            .insert(user_id.clone(), (u.clone(), now + AUTH_USER_CACHE_TTL));
        u
    };
    if !user.enabled {
        return Err(StatusCode::UNAUTHORIZED);
    }

    // Resolve permissions: from JWT if present, otherwise DB lookup
    let (perm_set, role_name) = match jwt_perm {
        Some(bits) => (
            PermissionSet::from_bits(bits),
            jwt_role.unwrap_or_else(|| user.role.clone()),
        ),
        None => {
            // Legacy token or API key — resolve from DB
            let (bits, name) =
                tokens::resolve_token_permissions(&state.pool, &user.role, user.role_id.as_deref())
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, "auth: failed to resolve token permissions");
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?;
            (PermissionSet::from_bits(bits), name)
        }
    };

    // Dispatch ApiRequest hook to plugins. Short-circuit on the atomic
    // shadow counter — no plugins running ⇒ no read-lock acquisition.
    if state
        .plugin_running_count
        .load(std::sync::atomic::Ordering::Relaxed)
        > 0
    {
        // PERF-H17 (#361): snapshot under a short read lock, dispatch after
        // dropping it — a slow plugin can't block enable/disable (write()).
        let plugins = state.plugin_manager.read().await.dispatch_set();
        if !plugins.is_empty() {
            let method = request.method().to_string();
            let path = request.uri().path().to_string();
            let event = aifw_plugins::HookEvent {
                hook: aifw_plugins::HookPoint::ApiRequest,
                data: aifw_plugins::hooks::HookEventData::Api {
                    method,
                    path,
                    remote_addr: None,
                },
            };
            let actions = plugins.dispatch(&event).await;
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
        api_key_name,
    });
    Ok(next.run(request).await)
}

/// Extract `ticket=<id>` from a query string. Tickets are URL-safe hex so
/// no percent-decoding is needed. Returns None if the param is absent or
/// contains characters that aren't in our ticket alphabet — those almost
/// certainly indicate a stale `?token=<jwt>` client that hasn't been
/// updated to the ticket flow.
fn query_ticket(q: Option<&str>) -> Option<String> {
    let raw = q?.split('&').find_map(|p| p.strip_prefix("ticket="))?;
    if !raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(raw.to_string())
}

#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: String,
    /// Display name of the acting user — recorded as the actor on
    /// auto-snapshots (config history) so changes are attributable.
    /// Authz itself keys off `user_id` + `permissions`.
    pub username: String,
    pub permissions: aifw_common::PermissionSet,
    pub role: String,
    /// Set when the request authenticated via an API key; None for JWT/ticket auth.
    pub api_key_name: Option<String>,
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

#[cfg(test)]
mod token_cache_tests {
    use super::{AUTH_TOKEN_CACHE_TTL, token_cache_ttl_secs};

    // PERF-H21 safety: an already-expired token must yield a 0s TTL so it is
    // never served from a live cache entry.
    #[test]
    fn expired_token_not_cached() {
        assert_eq!(token_cache_ttl_secs(1_000, 2_000), 0);
        assert_eq!(token_cache_ttl_secs(2_000, 2_000), 0);
    }

    // A token with lots of life left is capped at the rotation-safety window.
    #[test]
    fn long_lived_token_capped_at_ttl() {
        let cap = AUTH_TOKEN_CACHE_TTL.as_secs();
        assert_eq!(token_cache_ttl_secs(10_000, 0), cap);
    }

    // A token expiring inside the cap window is bounded by its own exp.
    #[test]
    fn short_lived_token_bounded_by_exp() {
        let cap = AUTH_TOKEN_CACHE_TTL.as_secs() as i64;
        // 10 seconds of life, which is below the cap.
        assert_eq!(token_cache_ttl_secs(cap - 50 + 10, cap - 50), 10);
    }
}
