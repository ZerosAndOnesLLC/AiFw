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

#[derive(Clone)]
struct Ticket {
    user_id: String,
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

    /// Issue a fresh ticket for `user_id`. Also opportunistically prunes
    /// expired entries so the map can't grow unboundedly from abandoned
    /// tickets.
    pub async fn issue(&self, user_id: &str) -> String {
        // 256 bits of entropy from two v4 UUIDs. Hex is URL-safe so we
        // don't need percent-decoding on the way back in.
        let id = format!(
            "{}{}",
            Uuid::new_v4().simple(),
            Uuid::new_v4().simple()
        );
        let now = Instant::now();
        let mut map = self.inner.lock().await;
        map.retain(|_, t| t.expires_at > now);
        map.insert(
            id.clone(),
            Ticket {
                user_id: user_id.to_string(),
                expires_at: now + TICKET_TTL,
            },
        );
        id
    }

    /// Consume a ticket. Returns the bound `user_id` if it was valid and
    /// unexpired; removes it either way.
    pub async fn consume(&self, ticket_id: &str) -> Option<String> {
        let now = Instant::now();
        let mut map = self.inner.lock().await;
        map.retain(|_, t| t.expires_at > now);
        match map.remove(ticket_id) {
            Some(t) if t.expires_at > now => Some(t.user_id),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn issue_then_consume_returns_user() {
        let store = WsTicketStore::new();
        let ticket = store.issue("user-42").await;
        assert_eq!(store.consume(&ticket).await.as_deref(), Some("user-42"));
    }

    #[tokio::test]
    async fn tickets_are_single_use() {
        let store = WsTicketStore::new();
        let ticket = store.issue("user-42").await;
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
        let a = store.issue("u").await;
        let b = store.issue("u").await;
        assert_ne!(a, b);
    }
}
