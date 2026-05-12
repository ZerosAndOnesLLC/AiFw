//! `/api/v1/dns` (legacy) — read/write the rDNS upstream forwarders.
//! Extracted from the legacy 4000-line `routes.rs` God module (#187).
//!
//! The richer `/api/v1/dns/resolver/*` surface lives in `dns_resolver.rs`
//! at the crate root; these two handlers exist for backwards
//! compatibility with the original `/api/v1/dns` endpoint shape, which
//! the OPNsense importer and a few external scripts still call.

use super::*;

#[derive(Debug, Deserialize)]
pub struct DnsConfigRequest {
    pub servers: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DnsConfigResponse {
    pub servers: Vec<String>,
}

pub async fn get_dns(
    State(state): State<AppState>,
) -> Result<Json<DnsConfigResponse>, StatusCode> {
    // Returns the rDNS upstream forwarders (what client DNS queries actually
    // get sent to). Pre-fix this read /etc/resolv.conf, which on a default
    // appliance is `127.0.0.1` — useless to a caller asking "what are my
    // configured upstreams?".
    let servers: Vec<String> = sqlx::query_as::<_, (String,)>(
        "SELECT value FROM dns_resolver_config WHERE key = 'forwarding_servers'",
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    .map(|(v,)| {
        v.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect()
    })
    .unwrap_or_default();
    Ok(Json(DnsConfigResponse { servers }))
}

pub async fn update_dns(
    State(state): State<AppState>,
    Json(req): Json<DnsConfigRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    // Persist for backup/restore round-trip (legacy `auth_config` field is
    // still what the snapshot format reads).
    let dns_json = serde_json::to_string(&req.servers).unwrap_or_default();
    let _ =
        sqlx::query("INSERT OR REPLACE INTO auth_config (key, value) VALUES ('dns_servers', ?1)")
            .bind(&dns_json)
            .execute(&state.pool)
            .await;

    // Program the actual rDNS upstream forwarders. Pre-fix this endpoint
    // wrote `/etc/resolv.conf` directly, which only changed what the
    // appliance OS itself queried — clients still hit 127.0.0.1 (rDNS) with
    // its old upstreams, so RPZ / blocklists / query logging silently lost
    // coverage of the configured DNS servers.
    crate::dns_resolver::set_forwarders(&state, &req.servers).await?;

    Ok(Json(MessageResponse {
        message: "DNS upstream forwarders saved. Apply via /api/v1/dns/resolver/apply.".to_string(),
    }))
}
