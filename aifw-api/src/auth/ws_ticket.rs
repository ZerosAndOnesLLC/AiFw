//! Short-lived, single-use tickets for WebSocket and SSE authentication.
//!
//! WebSocket and EventSource APIs in browsers can't set an `Authorization`
//! header, so something has to ride in the URL. Putting the JWT itself in
//! `?token=` leaked it into access logs, browser history, and referrers,
//! and bypassed the CSRF protections that cookie-bound auth enjoys.
//!
//! The ticket flow instead:
//!   1. Client calls `POST /auth/ws-ticket` with normal Bearer auth.
//!   2. Server returns an opaque 256-bit ticket, valid for 30 seconds,
//!      bound to the authenticated user_id, and consumable exactly once.
//!   3. Client opens `wss://.../ws?ticket=<id>`. The middleware consumes
//!      the ticket and injects the associated user into the request.
//!
//! Tickets live in process memory. On restart every connected client has
//! to reconnect anyway, so no persistence is needed. The store also does
//! lazy cleanup on every issue/consume.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use uuid::Uuid;

/// 30 seconds — long enough for a browser to open the socket, short
/// enough that a stolen ticket is near-useless.
const TICKET_TTL: Duration = Duration::from_secs(30);

/// Who a ticket stands for. A ticket must never grant more than the
/// credential that requested it: a role-narrowed API key's ticket carries
/// that key's effective permissions and identity, not its owner's.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TicketGrant {
    pub user_id: String,
    /// Effective permission bits of the issuing credential; the request is
    /// narrowed to these (intersected with the owner's current ones).
    pub permissions: Option<u64>,
    /// Role name to report (the narrowed key's role, when there is one).
    pub role: Option<String>,
    /// Set when an API key requested the ticket.
    pub api_key_id: Option<String>,
    pub api_key_name: Option<String>,
}

#[derive(Clone)]
struct Ticket {
    grant: TicketGrant,
    expires_at: Instant,
}

#[derive(Default)]
pub struct WsTicketStore {
    inner: Mutex<HashMap<String, Ticket>>,
}

impl WsTicketStore {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Issue a fresh ticket for `grant`. Also opportunistically prunes
    /// expired entries so the map can't grow unboundedly from abandoned
    /// tickets.
    pub async fn issue(&self, grant: TicketGrant) -> String {
        // 256 bits of entropy from two v4 UUIDs. Hex is URL-safe so we
        // don't need percent-decoding on the way back in.
        let id = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
        let now = Instant::now();
        let mut map = self.inner.lock().await;
        map.retain(|_, t| t.expires_at > now);
        map.insert(
            id.clone(),
            Ticket {
                grant,
                expires_at: now + TICKET_TTL,
            },
        );
        id
    }

    /// Consume a ticket. Returns its grant if it was valid and unexpired;
    /// removes it either way.
    pub async fn consume(&self, ticket_id: &str) -> Option<TicketGrant> {
        let now = Instant::now();
        let mut map = self.inner.lock().await;
        map.retain(|_, t| t.expires_at > now);
        match map.remove(ticket_id) {
            Some(t) if t.expires_at > now => Some(t.grant),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn g(user: &str) -> TicketGrant {
        TicketGrant {
            user_id: user.to_string(),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn grant_round_trips() {
        let store = WsTicketStore::new();
        let grant = TicketGrant {
            user_id: "u".into(),
            permissions: Some(5),
            role: Some("viewer".into()),
            api_key_id: Some("k".into()),
            api_key_name: Some("ci".into()),
        };
        let t = store.issue(grant.clone()).await;
        assert_eq!(store.consume(&t).await, Some(grant));
    }

    #[tokio::test]
    async fn issue_then_consume_returns_user() {
        let store = WsTicketStore::new();
        let ticket = store.issue(g("user-42")).await;
        assert_eq!(
            store.consume(&ticket).await.map(|g| g.user_id).as_deref(),
            Some("user-42")
        );
    }

    #[tokio::test]
    async fn tickets_are_single_use() {
        let store = WsTicketStore::new();
        let ticket = store.issue(g("user-42")).await;
        assert!(store.consume(&ticket).await.is_some());
        assert!(store.consume(&ticket).await.is_none());
    }

    #[tokio::test]
    async fn unknown_ticket_rejected() {
        let store = WsTicketStore::new();
        assert!(store.consume("deadbeef").await.is_none());
    }

    #[tokio::test]
    async fn ticket_ids_unique() {
        let store = WsTicketStore::new();
        let a = store.issue(g("u")).await;
        let b = store.issue(g("u")).await;
        assert_ne!(a, b);
    }
}
