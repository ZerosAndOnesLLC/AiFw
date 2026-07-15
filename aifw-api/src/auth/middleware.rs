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

pub async fn auth_middleware(
    State(state): State<crate::AppState>,
    headers: HeaderMap,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    use aifw_common::permission::PermissionSet;
    use std::time::Instant;

    // Credentials: Authorization: Bearer <jwt>, Authorization: ApiKey <key>,
    // or ?ticket=<id> (short-lived, single-use; see auth::ws_ticket).
    let auth_header = headers.get("authorization").and_then(|v| v.to_str().ok());

    // Resolve (user_id, perm_from_token, role_from_token, api_key_name) from the credential
    let (user_id, jwt_perm, jwt_role, api_key_name) =
        if let Some(token) = auth_header.and_then(|h| h.strip_prefix("Bearer ")) {
            let token_data = verify_access_token(token, &state.auth_settings)
                .map_err(|_| StatusCode::UNAUTHORIZED)?;
            let jti = &token_data.claims.jti;
            // JTI revocation: positive cache to skip the DB lookup. Cached
            // entry value=true means revoked, value=false means not revoked.
            let now = Instant::now();
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
            (
                token_data.claims.sub,
                token_data.claims.perm,
                token_data.claims.role,
                None,
            )
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
        let mgr = state.plugin_manager.read().await;
        if mgr.running_count() > 0 {
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
    /// Populated for logging/audit context and future per-request use; not
    /// currently read by any guard (authz keys off `user_id` + `permissions`).
    #[allow(dead_code)]
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
