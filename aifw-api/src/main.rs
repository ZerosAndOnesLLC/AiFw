mod acme;
mod ai_analysis;
mod aliases;
mod auth;
mod backup;
mod cluster;
mod backup_s3;
mod ca;
mod dhcp;
mod dns_blocklists;
mod dns_resolver;
mod ids;
mod iface;
mod log_tail;
mod metrics_series;
mod multiwan;
mod plugins;
mod reverse_proxy;
mod routes;
mod system;
mod time_service;
mod updates;
mod ws;

#[cfg(test)]
mod tests;

use aifw_conntrack::ConnectionTracker;
use aifw_core::{
    AliasEngine, Database, GatewayEngine, GeoIpEngine, GroupEngine, InstanceEngine, LeakEngine,
    NatEngine, PolicyEngine, PreflightEngine, RuleEngine, ShapingEngine, SlaEngine, TlsEngine,
    VpnEngine,
};
use aifw_pf::PfBackend;
use axum::{
    Router, middleware,
    routing::{delete, get, post, put},
};
use clap::Parser;
use sqlx::sqlite::SqlitePool;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{RwLock, watch};
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::set_header::SetResponseHeaderLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

/// Default dashboard history: 30 minutes at 1 update/sec
pub const METRICS_HISTORY_SIZE_DEFAULT: usize = 1800;

/// Per-IP login attempt tracker for brute-force protection.
/// Two-axis login rate limiter.
///
/// Keys every attempt under both the client-IP-ish value and the
/// username. A request is blocked if **either** key has hit the cap.
/// This matters because X-Forwarded-For is trivially spoofable when
/// the appliance sits behind an untrusted proxy — keying solely by IP
/// lets an attacker change XFF per request and bypass the limit.
/// Keying by username closes that.
#[derive(Clone)]
pub struct LoginRateLimiter {
    by_ip: Arc<RwLock<std::collections::HashMap<String, (u32, chrono::DateTime<chrono::Utc>)>>>,
    by_user: Arc<RwLock<std::collections::HashMap<String, (u32, chrono::DateTime<chrono::Utc>)>>>,
    /// Attempts allowed per window before the key is blocked.
    max_attempts: u32,
    /// Window length, in seconds.
    window_secs: i64,
}

impl Default for LoginRateLimiter {
    fn default() -> Self {
        Self::with_limits(5, 300)
    }
}

impl LoginRateLimiter {
    /// Construct with explicit limits, sourced from AuthSettings at boot.
    pub fn with_limits(max_attempts: u32, window_secs: i64) -> Self {
        Self {
            by_ip: Arc::default(),
            by_user: Arc::default(),
            max_attempts: max_attempts.max(1),
            window_secs: window_secs.max(1),
        }
    }

    /// Record a failed attempt against both axes. Returns true if the
    /// caller is now blocked (either key at the cap).
    pub async fn record_failure(&self, ip: &str, username: &str) -> bool {
        let a = bump(&self.by_ip, ip, self.max_attempts, self.window_secs).await;
        let b = bump(&self.by_user, username, self.max_attempts, self.window_secs).await;
        a || b
    }

    /// Check if this (IP, username) pair is currently blocked on either
    /// axis.
    pub async fn is_blocked(&self, ip: &str, username: &str) -> bool {
        over_cap(&self.by_ip, ip, self.max_attempts, self.window_secs).await
            || over_cap(&self.by_user, username, self.max_attempts, self.window_secs).await
    }

    /// Clear attempts on successful login — clears both axes.
    pub async fn clear(&self, ip: &str, username: &str) {
        self.by_ip.write().await.remove(ip);
        self.by_user.write().await.remove(username);
    }
}

async fn bump(
    map: &Arc<RwLock<std::collections::HashMap<String, (u32, chrono::DateTime<chrono::Utc>)>>>,
    key: &str,
    max_attempts: u32,
    window_secs: i64,
) -> bool {
    let now = chrono::Utc::now();
    let mut m = map.write().await;
    m.retain(|_, (_, since)| (now - *since).num_seconds() <= window_secs);
    let entry = m.entry(key.to_string()).or_insert((0, now));
    if (now - entry.1).num_seconds() > window_secs {
        *entry = (1, now);
        return false;
    }
    entry.0 += 1;
    entry.0 >= max_attempts
}

async fn over_cap(
    map: &Arc<RwLock<std::collections::HashMap<String, (u32, chrono::DateTime<chrono::Utc>)>>>,
    key: &str,
    max_attempts: u32,
    window_secs: i64,
) -> bool {
    let now = chrono::Utc::now();
    let mut m = map.write().await; // upgraded to write — needed for prune
    m.retain(|_, (_, since)| (now - *since).num_seconds() <= window_secs);
    matches!(
        m.get(key),
        Some((count, since))
            if (now - *since).num_seconds() <= window_secs
                && *count >= max_attempts
    )
}

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub pf: Arc<dyn PfBackend>,
    pub rule_engine: Arc<RuleEngine>,
    pub nat_engine: Arc<NatEngine>,
    pub vpn_engine: Arc<VpnEngine>,
    pub geoip_engine: Arc<GeoIpEngine>,
    pub multiwan_engine: Arc<InstanceEngine>,
    pub gateway_engine: Arc<GatewayEngine>,
    pub group_engine: Arc<GroupEngine>,
    pub policy_engine: Arc<PolicyEngine>,
    pub leak_engine: Arc<LeakEngine>,
    pub preflight_engine: Arc<PreflightEngine>,
    pub sla_engine: Arc<SlaEngine>,
    pub alias_engine: Arc<AliasEngine>,
    pub conntrack: Arc<ConnectionTracker>,
    pub ids_client: Arc<aifw_ids_ipc::IdsClient>,
    pub plugin_manager: Arc<RwLock<aifw_plugins::PluginManager>>,
    pub metrics_store: Arc<aifw_metrics::MetricsStore>,
    pub auth_settings: auth::AuthSettings,
    pub cluster_engine: Arc<aifw_core::ClusterEngine>,
    pub shaping_engine: Arc<ShapingEngine>,
    pub tls_engine: Arc<TlsEngine>,
    /// Cached at startup: `sysrc -n aifw_cluster_enabled == YES`.
    /// Never changes without a config write, so a one-shot read is correct.
    pub cluster_enabled: Arc<std::sync::atomic::AtomicBool>,
    pub cluster_events: aifw_common::ClusterEventBus,
    pub metrics_history: Arc<RwLock<VecDeque<String>>>,
    pub metrics_history_max: Arc<std::sync::atomic::AtomicUsize>,
    pub redis: Option<redis::aio::ConnectionManager>,
    pub pending: Arc<RwLock<PendingChanges>>,
    /// Watch channel that fires whenever `pending` changes — drives SSE.
    pub pending_tx: watch::Sender<PendingChanges>,
    pub login_limiter: LoginRateLimiter,
    pub ws_tickets: Arc<auth::ws_ticket::WsTicketStore>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize)]
pub struct PendingChanges {
    pub firewall: bool,
    pub nat: bool,
    pub dns: bool,
}

impl AppState {
    /// Update a pending flag and notify SSE subscribers.
    pub async fn set_pending(&self, f: impl FnOnce(&mut PendingChanges)) {
        let mut p = self.pending.write().await;
        f(&mut p);
        let _ = self.pending_tx.send(p.clone());
    }

    /// Produces (snapshot_data_json, sha256_hex_hash) for cluster replication.
    /// Includes everything backup exports plus IDS rule overrides + suppressions.
    /// Hash is sha256 of the JSON bytes.
    pub async fn cluster_snapshot_data(
        &self,
    ) -> Result<(String, String), aifw_common::AifwError> {
        let payload = crate::backup::cluster_export_payload(self)
            .await
            .map_err(|e| aifw_common::AifwError::Other(format!("export: {e:?}")))?;
        let json = serde_json::to_string(&payload)
            .map_err(|e| aifw_common::AifwError::Other(format!("serialize: {e}")))?;

        let hash = aifw_core::sha256_hex(&json);

        Ok((json, hash))
    }
}

#[derive(Parser)]
#[command(name = "aifw-api", about = "AiFw REST API server")]
struct Args {
    /// Path to the database file
    #[arg(long, default_value = "/var/db/aifw/aifw.db")]
    db: PathBuf,

    /// Listen address (use 0.0.0.0:8080 to listen on all interfaces)
    #[arg(long, default_value = "127.0.0.1:8080")]
    listen: String,

    /// JWT signing secret (development / test override only — production
    /// should leave this unset so the key is read from --jwt-key-file).
    #[arg(long, env = "AIFW_JWT_SECRET", hide = true)]
    jwt_secret: Option<String>,

    /// File holding the JWT signing secret. Created with 0600 perms on
    /// first run; legacy DB-stored secrets are migrated into it.
    #[arg(long, default_value = "/var/db/aifw/jwt.key")]
    jwt_key_file: PathBuf,

    /// CORS allowed origins (comma-separated, or * for any)
    #[arg(long, default_value = "*")]
    cors_origins: String,

    /// Path to static UI build directory (serves web UI if set)
    #[arg(long, env = "AIFW_UI_DIR")]
    ui_dir: Option<PathBuf>,

    /// TLS certificate path (auto-generated self-signed if not found)
    #[arg(long, default_value = "/usr/local/etc/aifw/tls/cert.pem")]
    tls_cert: PathBuf,

    /// TLS private key path
    #[arg(long, default_value = "/usr/local/etc/aifw/tls/key.pem")]
    tls_key: PathBuf,

    /// Disable TLS (serve plain HTTP). Refuses to bind a non-loopback
    /// listener unless --allow-plaintext-external is also passed, so
    /// plaintext creds can't leak onto the wire by operator mistake.
    #[arg(long)]
    no_tls: bool,

    /// Escape hatch for --no-tls on a non-loopback listener. Required
    /// when the daemon sits behind another TLS terminator (nginx, ALB).
    #[arg(long, default_value_t = false)]
    allow_plaintext_external: bool,

    /// Valkey/Redis URL for metrics persistence (optional)
    #[arg(
        long,
        env = "AIFW_VALKEY_URL",
        default_value = "redis://127.0.0.1:6379"
    )]
    valkey_url: String,

    /// Path to aifw-ids Unix socket
    #[arg(long, default_value = "/var/run/aifw/ids.sock")]
    ids_socket: PathBuf,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

pub fn build_router(
    state: AppState,
    ui_dir: Option<&std::path::Path>,
    cors_origins: &str,
    tls_enabled: bool,
) -> Router {
    use tower_http::cors::AllowOrigin;
    let cors = if cors_origins == "*" {
        CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any)
    } else {
        let origins: Vec<_> = cors_origins
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        CorsLayer::new()
            .allow_origin(AllowOrigin::list(origins))
            .allow_methods(Any)
            .allow_headers(Any)
    };

    // Public routes (no auth)
    let public_routes = Router::new()
        .route("/api/v1/auth/login", post(routes::login))
        .route("/api/v1/auth/totp/login", post(routes::totp_login))
        .route("/api/v1/auth/refresh", post(routes::refresh_token))
        .route(
            "/api/v1/auth/oauth/{provider}/authorize",
            get(routes::oauth_authorize),
        )
        .route(
            "/api/v1/auth/oauth/{provider}/callback",
            get(routes::oauth_callback),
        )
        .route("/api/v1/auth/register", post(routes::register));

    use aifw_common::Permission;

    // Auth layer — applied once on the outer protected router
    let auth_layer = middleware::from_fn_with_state(state.clone(), auth::auth_middleware);

    // Self-service routes (auth only, no permission needed)
    let self_service = Router::new()
        .route("/api/v1/auth/logout", post(routes::logout))
        .route("/api/v1/auth/totp/setup", post(routes::totp_setup))
        .route("/api/v1/auth/totp/verify", post(routes::totp_verify))
        .route("/api/v1/auth/totp/disable", post(routes::totp_disable))
        .route("/api/v1/auth/me", get(routes::get_current_user))
        .route("/api/v1/auth/ws-ticket", post(routes::issue_ws_ticket));

    // --- Permission-scoped route groups ---
    // Each group enforces a specific permission via perm_check! middleware.
    // Read routes use GET; write routes use POST/PUT/DELETE.

    // dashboard:view
    let dashboard_view = Router::new()
        .route("/api/v1/status", get(routes::status))
        .route("/api/v1/about", get(routes::about_info))
        .route("/api/v1/metrics", get(routes::metrics))
        .route("/api/v1/metrics/list", get(metrics_series::list))
        .route("/api/v1/metrics/series", get(metrics_series::query))
        .route("/api/v1/ws", get(ws::ws_handler))
        .route("/api/v1/pending/stream", get(routes::pending_stream))
        .route("/api/v1/pending", get(routes::get_pending))
        .layer(middleware::from_fn(perm_check!(Permission::DashboardView)));

    // rules:read
    let rules_read = Router::new()
        .route("/api/v1/rules", get(routes::list_rules))
        .route("/api/v1/rules/{id}", get(routes::get_rule))
        .route("/api/v1/rules/system", get(routes::list_system_rules))
        .route("/api/v1/schedules", get(routes::list_schedules))
        .layer(middleware::from_fn(perm_check!(Permission::RulesRead)));

    // rules:write
    let rules_write = Router::new()
        .route("/api/v1/rules", post(routes::create_rule))
        .route(
            "/api/v1/rules/{id}",
            put(routes::update_rule).delete(routes::delete_rule),
        )
        .route("/api/v1/rules/reorder", put(routes::reorder_rules))
        .route(
            "/api/v1/rules/block-logging",
            post(routes::toggle_block_logging),
        )
        .route("/api/v1/reload", post(routes::reload))
        .route("/api/v1/schedules", post(routes::create_schedule))
        .route(
            "/api/v1/schedules/{id}",
            put(routes::update_schedule).delete(routes::delete_schedule),
        )
        .layer(middleware::from_fn(perm_check!(Permission::RulesWrite)));

    // nat:read
    let nat_read = Router::new()
        .route("/api/v1/nat", get(routes::list_nat_rules))
        .route("/api/v1/nat/pf-output", get(routes::get_nat_pf_output))
        .layer(middleware::from_fn(perm_check!(Permission::NatRead)));

    // nat:write
    let nat_write = Router::new()
        .route("/api/v1/nat", post(routes::create_nat_rule))
        .route(
            "/api/v1/nat/{id}",
            put(routes::update_nat_rule).delete(routes::delete_nat_rule),
        )
        .route("/api/v1/nat/reorder", put(routes::reorder_nat_rules))
        .layer(middleware::from_fn(perm_check!(Permission::NatWrite)));

    // vpn:read
    let vpn_read = Router::new()
        .route("/api/v1/vpn/wg", get(routes::list_wg_tunnels))
        .route("/api/v1/vpn/wg/{id}/peers", get(routes::list_wg_peers))
        .route(
            "/api/v1/vpn/wg/{id}/peers/next-ip",
            get(routes::next_wg_peer_ip),
        )
        .route(
            "/api/v1/vpn/wg/{tid}/peers/{pid}/config",
            get(routes::get_peer_config),
        )
        .route("/api/v1/vpn/wg/{id}/status", get(routes::wg_tunnel_status))
        .route("/api/v1/vpn/ipsec", get(routes::list_ipsec_sas))
        .layer(middleware::from_fn(perm_check!(Permission::VpnRead)));

    // vpn:write
    let vpn_write = Router::new()
        .route("/api/v1/vpn/wg", post(routes::create_wg_tunnel))
        .route(
            "/api/v1/vpn/wg/{id}",
            put(routes::update_wg_tunnel).delete(routes::delete_wg_tunnel),
        )
        .route("/api/v1/vpn/wg/{id}/start", post(routes::start_wg_tunnel))
        .route("/api/v1/vpn/wg/{id}/stop", post(routes::stop_wg_tunnel))
        .route("/api/v1/vpn/wg/{id}/peers", post(routes::create_wg_peer))
        .route(
            "/api/v1/vpn/wg/{tid}/peers/{pid}",
            put(routes::update_wg_peer).delete(routes::delete_wg_peer),
        )
        .route("/api/v1/vpn/ipsec", post(routes::create_ipsec_sa))
        .route("/api/v1/vpn/ipsec/{id}", delete(routes::delete_ipsec_sa))
        .layer(middleware::from_fn(perm_check!(Permission::VpnWrite)));

    // geoip:read
    let geoip_read = Router::new()
        .route("/api/v1/geoip", get(routes::list_geoip_rules))
        .route("/api/v1/geoip/lookup/{ip}", get(routes::geoip_lookup))
        .layer(middleware::from_fn(perm_check!(Permission::GeoipRead)));

    // geoip:write
    let geoip_write = Router::new()
        .route("/api/v1/geoip", post(routes::create_geoip_rule))
        .route(
            "/api/v1/geoip/{id}",
            put(routes::update_geoip_rule).delete(routes::delete_geoip_rule),
        )
        .layer(middleware::from_fn(perm_check!(Permission::GeoipWrite)));

    // ids:read
    let ids_read = Router::new()
        .route("/api/v1/ids/config", get(ids::get_config))
        .route("/api/v1/ids/alerts", get(ids::list_alerts))
        .route("/api/v1/ids/alerts/{id}", get(ids::get_alert))
        .route("/api/v1/ids/rulesets", get(ids::list_rulesets))
        .route("/api/v1/ids/rules", get(ids::list_rules))
        .route("/api/v1/ids/rules/{id}", get(ids::get_rule))
        .route("/api/v1/ids/rules/search", get(ids::search_rules))
        .route("/api/v1/ids/suppressions", get(ids::list_suppressions))
        .route("/api/v1/ids/stats", get(ids::get_stats))
        .route(
            "/api/v1/ids/alerts/buffer-stats",
            get(ids::alert_buffer_stats),
        )
        .route("/api/v1/ai/audit-log", get(ai_analysis::get_audit_log))
        .layer(middleware::from_fn(perm_check!(Permission::IdsRead)));

    // ids:write
    let ids_write = Router::new()
        .route("/api/v1/ids/config", put(ids::update_config))
        .route("/api/v1/ids/alerts", delete(ids::purge_alerts))
        .route(
            "/api/v1/ids/alerts/{id}/acknowledge",
            put(ids::acknowledge_alert),
        )
        .route("/api/v1/ids/alerts/{id}/classify", put(ids::classify_alert))
        .route("/api/v1/ids/rulesets", post(ids::create_ruleset))
        .route(
            "/api/v1/ids/rulesets/{id}",
            put(ids::update_ruleset).delete(ids::delete_ruleset),
        )
        .route("/api/v1/ids/rules/{id}", put(ids::update_rule))
        .route("/api/v1/ids/suppressions", post(ids::create_suppression))
        .route(
            "/api/v1/ids/suppressions/{id}",
            delete(ids::delete_suppression),
        )
        .route("/api/v1/ids/reload", post(ids::reload))
        .route("/api/v1/ai/analyze", post(ai_analysis::trigger_analysis))
        .layer(middleware::from_fn(perm_check!(Permission::IdsWrite)));

    // dns:read
    let dns_read = Router::new()
        .route("/api/v1/dns", get(routes::get_dns))
        .route(
            "/api/v1/dns/resolver/status",
            get(dns_resolver::resolver_status),
        )
        .route(
            "/api/v1/dns/resolver/config",
            get(dns_resolver::get_config_handler),
        )
        .route("/api/v1/dns/resolver/hosts", get(dns_resolver::list_hosts))
        .route(
            "/api/v1/dns/resolver/domains",
            get(dns_resolver::list_domains),
        )
        .route("/api/v1/dns/resolver/acls", get(dns_resolver::list_acls))
        .route(
            "/api/v1/dns/resolver/logs",
            get(dns_resolver::resolver_logs),
        )
        .route("/api/v1/dns/blocklists", get(dns_blocklists::list_sources))
        .route(
            "/api/v1/dns/blocklists/{id}",
            get(dns_blocklists::get_source),
        )
        .route(
            "/api/v1/dns/blocklists/schedule",
            get(dns_blocklists::get_schedule),
        )
        .route("/api/v1/dns/whitelist", get(dns_blocklists::list_whitelist))
        .route(
            "/api/v1/dns/customblocks",
            get(dns_blocklists::list_customblocks),
        )
        .route("/api/v1/dns/stats", get(dns_blocklists::get_stats_snapshot))
        .route("/api/v1/dns/stream", get(dns_blocklists::stream_metrics))
        .layer(middleware::from_fn(perm_check!(Permission::DnsRead)));

    // dns:write
    let dns_write = Router::new()
        .route("/api/v1/dns", put(routes::update_dns))
        .route(
            "/api/v1/dns/resolver/config",
            put(dns_resolver::update_config_handler),
        )
        .route(
            "/api/v1/dns/resolver/hosts",
            post(dns_resolver::create_host),
        )
        .route(
            "/api/v1/dns/resolver/hosts/{id}",
            put(dns_resolver::update_host).delete(dns_resolver::delete_host),
        )
        .route(
            "/api/v1/dns/resolver/domains",
            post(dns_resolver::create_domain),
        )
        .route(
            "/api/v1/dns/resolver/domains/{id}",
            put(dns_resolver::update_domain).delete(dns_resolver::delete_domain),
        )
        .route("/api/v1/dns/resolver/acls", post(dns_resolver::create_acl))
        .route(
            "/api/v1/dns/resolver/acls/{id}",
            delete(dns_resolver::delete_acl),
        )
        .route(
            "/api/v1/dns/resolver/apply",
            post(dns_resolver::apply_resolver),
        )
        .route(
            "/api/v1/dns/resolver/start",
            post(dns_resolver::resolver_start),
        )
        .route(
            "/api/v1/dns/resolver/stop",
            post(dns_resolver::resolver_stop),
        )
        .route(
            "/api/v1/dns/resolver/restart",
            post(dns_resolver::resolver_restart),
        )
        .route(
            "/api/v1/dns/blocklists",
            post(dns_blocklists::create_source),
        )
        .route(
            "/api/v1/dns/blocklists/{id}",
            put(dns_blocklists::update_source).delete(dns_blocklists::delete_source),
        )
        .route(
            "/api/v1/dns/blocklists/{id}/refresh",
            post(dns_blocklists::refresh_one),
        )
        .route(
            "/api/v1/dns/blocklists/refresh-all",
            post(dns_blocklists::refresh_everything),
        )
        .route(
            "/api/v1/dns/blocklists/schedule",
            put(dns_blocklists::put_schedule),
        )
        .route(
            "/api/v1/dns/blocklists/enabled",
            put(dns_blocklists::set_enabled),
        )
        .route(
            "/api/v1/dns/whitelist",
            post(dns_blocklists::create_whitelist),
        )
        .route(
            "/api/v1/dns/whitelist/{id}",
            delete(dns_blocklists::delete_whitelist),
        )
        .route(
            "/api/v1/dns/customblocks",
            post(dns_blocklists::create_customblock),
        )
        .route(
            "/api/v1/dns/customblocks/{id}",
            delete(dns_blocklists::delete_customblock),
        )
        .layer(middleware::from_fn(perm_check!(Permission::DnsWrite)));

    // dhcp:read
    let dhcp_read = Router::new()
        .route("/api/v1/dhcp/status", get(dhcp::dhcp_status))
        .route("/api/v1/dhcp/v4/config", get(dhcp::get_config))
        .route("/api/v1/dhcp/v4/subnets", get(dhcp::list_subnets))
        .route("/api/v1/dhcp/v4/reservations", get(dhcp::list_reservations))
        .route("/api/v1/dhcp/v4/leases", get(dhcp::list_leases))
        .route("/api/v1/dhcp/ddns", get(dhcp::get_ddns_config))
        .route("/api/v1/dhcp/ha/config", get(dhcp::get_ha_config))
        .route("/api/v1/dhcp/ha/status", get(dhcp::get_ha_status))
        .route("/api/v1/dhcp/pool-stats", get(dhcp::get_pool_stats))
        .route("/api/v1/dhcp/metrics", get(dhcp::get_metrics))
        .route("/api/v1/dhcp/logs", get(dhcp::dhcp_logs))
        .layer(middleware::from_fn(perm_check!(Permission::DhcpRead)));

    // dhcp:write
    let dhcp_write = Router::new()
        .route("/api/v1/dhcp/start", post(dhcp::dhcp_start))
        .route("/api/v1/dhcp/stop", post(dhcp::dhcp_stop))
        .route("/api/v1/dhcp/restart", post(dhcp::dhcp_restart))
        .route("/api/v1/dhcp/v4/config", put(dhcp::update_config))
        .route("/api/v1/dhcp/v4/subnets", post(dhcp::create_subnet))
        .route(
            "/api/v1/dhcp/v4/subnets/{id}",
            put(dhcp::update_subnet).delete(dhcp::delete_subnet),
        )
        .route(
            "/api/v1/dhcp/v4/reservations",
            post(dhcp::create_reservation),
        )
        .route(
            "/api/v1/dhcp/v4/reservations/{id}",
            put(dhcp::update_reservation).delete(dhcp::delete_reservation),
        )
        .route("/api/v1/dhcp/v4/leases/{ip}", delete(dhcp::release_lease))
        .route("/api/v1/dhcp/v4/apply", post(dhcp::apply_config))
        .route("/api/v1/dhcp/ddns", put(dhcp::update_ddns_config))
        .route("/api/v1/dhcp/ha/config", put(dhcp::update_ha_config))
        .layer(middleware::from_fn(perm_check!(Permission::DhcpWrite)));

    // aliases:read
    let aliases_read = Router::new()
        .route("/api/v1/aliases", get(aliases::list_aliases))
        .route("/api/v1/aliases/{id}", get(aliases::get_alias))
        .layer(middleware::from_fn(perm_check!(Permission::AliasesRead)));

    // aliases:write
    let aliases_write = Router::new()
        .route("/api/v1/aliases", post(aliases::create_alias))
        .route(
            "/api/v1/aliases/{id}",
            put(aliases::update_alias).delete(aliases::delete_alias),
        )
        .layer(middleware::from_fn(perm_check!(Permission::AliasesWrite)));

    // interfaces:read
    let ifaces_read = Router::new()
        .route("/api/v1/interfaces", get(routes::list_interfaces))
        .route(
            "/api/v1/interfaces/detailed",
            get(iface::list_interfaces_detailed),
        )
        .route("/api/v1/interfaces/roles", get(iface::list_interface_roles))
        .route(
            "/api/v1/interfaces/{name}/stats",
            get(routes::get_interface_stats),
        )
        .route("/api/v1/vlans", get(iface::list_vlans))
        .route("/api/v1/routes", get(routes::list_static_routes))
        .route("/api/v1/routes/system", get(routes::get_system_routes))
        .layer(middleware::from_fn(perm_check!(Permission::InterfacesRead)));

    // interfaces:write
    let ifaces_write = Router::new()
        .route(
            "/api/v1/interfaces/{name}/role",
            put(iface::set_interface_role).delete(iface::delete_interface_role),
        )
        .route(
            "/api/v1/interfaces/config/{name}",
            put(iface::configure_interface),
        )
        .route("/api/v1/vlans", post(iface::create_vlan))
        .route(
            "/api/v1/vlans/{id}",
            put(iface::update_vlan).delete(iface::delete_vlan),
        )
        .route("/api/v1/routes", post(routes::create_static_route))
        .route(
            "/api/v1/routes/{id}",
            put(routes::update_static_route).delete(routes::delete_static_route),
        )
        .layer(middleware::from_fn(perm_check!(
            Permission::InterfacesWrite
        )));

    // connections:view
    let connections_view = Router::new()
        .route("/api/v1/connections", get(routes::list_connections))
        .route("/api/v1/blocked", get(routes::list_blocked_traffic))
        .layer(middleware::from_fn(perm_check!(
            Permission::ConnectionsView
        )));

    // logs:view
    let logs_view = Router::new()
        .route("/api/v1/logs", get(routes::list_logs))
        .layer(middleware::from_fn(perm_check!(Permission::LogsView)));

    // users:read
    let users_read = Router::new()
        .route("/api/v1/auth/users", get(routes::list_users))
        .route("/api/v1/auth/users/{id}", get(routes::get_user))
        .route("/api/v1/auth/audit", get(routes::list_user_audit))
        .route("/api/v1/auth/roles", get(routes::list_roles))
        .route("/api/v1/auth/permissions", get(routes::list_permissions))
        .layer(middleware::from_fn(perm_check!(Permission::UsersRead)));

    // users:write
    let users_write = Router::new()
        .route("/api/v1/auth/users", post(routes::create_user))
        .route(
            "/api/v1/auth/users/{id}",
            put(routes::update_user).delete(routes::delete_user_handler),
        )
        .route("/api/v1/auth/api-keys", post(routes::create_api_key))
        .route("/api/v1/auth/roles", post(routes::create_role))
        .route(
            "/api/v1/auth/roles/{id}",
            put(routes::update_role).delete(routes::delete_role),
        )
        .layer(middleware::from_fn(perm_check!(Permission::UsersWrite)));

    // settings:read
    let settings_read = Router::new()
        .route("/api/v1/auth/settings", get(routes::get_auth_settings))
        .route(
            "/api/v1/auth/oauth/providers",
            get(routes::list_oauth_providers),
        )
        .route("/api/v1/settings/tls", get(routes::get_tls_settings))
        .route("/api/v1/settings/valkey", get(routes::get_valkey_settings))
        .route(
            "/api/v1/settings/dashboard-history",
            get(routes::get_dashboard_history_settings),
        )
        .route(
            "/api/v1/settings/ids-alerts",
            get(routes::get_ids_alert_settings),
        )
        .route("/api/v1/settings/pf-tuning", get(routes::get_pf_tuning))
        .route(
            "/api/v1/settings/{section}",
            get(routes::get_generic_settings),
        )
        .route("/api/v1/settings/ai", get(routes::get_ai_settings))
        .route("/api/v1/settings/ai/models", get(routes::list_ai_models))
        .route("/api/v1/ca", get(ca::get_ca_info))
        .route("/api/v1/ca/cert.pem", get(ca::get_ca_cert_pem))
        .route("/api/v1/ca/crl", get(ca::get_crl))
        .route("/api/v1/ca/certs", get(ca::list_certs))
        .route("/api/v1/ca/certs/{id}", get(ca::get_cert))
        .route("/api/v1/ca/certs/{id}/cert.pem", get(ca::download_cert))
        .route("/api/v1/time/status", get(time_service::time_status))
        .route("/api/v1/time/config", get(time_service::get_config))
        .route("/api/v1/time/sources", get(time_service::list_sources))
        .route("/api/v1/time/logs", get(time_service::time_logs))
        .route("/api/v1/acme/account", get(acme::get_account))
        .route("/api/v1/acme/certs", get(acme::list_certs))
        .route("/api/v1/acme/certs/{id}", get(acme::get_cert))
        .route(
            "/api/v1/acme/certs/{id}/cert.pem",
            get(acme::download_cert_pem),
        )
        .route("/api/v1/acme/dns-providers", get(acme::list_providers))
        .route(
            "/api/v1/acme/certs/{cert_id}/targets",
            get(acme::list_targets),
        )
        .route("/api/v1/ddns/records", get(acme::list_ddns))
        .route("/api/v1/ddns/config", get(acme::get_ddns_config))
        .layer(middleware::from_fn(perm_check!(Permission::SettingsRead)));

    // settings:write
    let settings_write = Router::new()
        .route("/api/v1/auth/settings", put(routes::update_auth_settings))
        .route(
            "/api/v1/auth/oauth/providers",
            post(routes::create_oauth_provider),
        )
        .route(
            "/api/v1/auth/oauth/providers/{id}",
            delete(routes::delete_oauth_provider),
        )
        .route("/api/v1/settings/tls", put(routes::update_tls_settings))
        .route(
            "/api/v1/settings/valkey",
            put(routes::update_valkey_settings),
        )
        .route(
            "/api/v1/settings/dashboard-history",
            put(routes::update_dashboard_history_settings),
        )
        .route(
            "/api/v1/settings/ids-alerts",
            put(routes::update_ids_alert_settings),
        )
        .route("/api/v1/settings/pf-tuning", put(routes::put_pf_tuning))
        .route(
            "/api/v1/settings/{section}",
            put(routes::update_generic_settings),
        )
        .route("/api/v1/settings/ai", put(routes::update_ai_settings))
        .route("/api/v1/settings/ai/test", post(routes::test_ai_provider))
        .route("/api/v1/ca", post(ca::generate_ca))
        .route("/api/v1/ca/certs", post(ca::issue_cert))
        .route("/api/v1/ca/certs/{id}", delete(ca::delete_cert))
        .route("/api/v1/ca/certs/{id}/key.pem", get(ca::download_cert_key))
        .route("/api/v1/ca/certs/{id}/revoke", post(ca::revoke_cert))
        .route("/api/v1/time/config", put(time_service::update_config))
        .route("/api/v1/time/sources", post(time_service::create_source))
        .route(
            "/api/v1/time/sources/{id}",
            put(time_service::update_source).delete(time_service::delete_source),
        )
        .route("/api/v1/time/start", post(time_service::time_start))
        .route("/api/v1/time/stop", post(time_service::time_stop))
        .route("/api/v1/time/restart", post(time_service::time_restart))
        .route("/api/v1/time/apply", post(time_service::apply_config))
        .route("/api/v1/acme/account", put(acme::put_account))
        .route("/api/v1/acme/certs", post(acme::create_cert))
        .route("/api/v1/acme/certs/{id}", delete(acme::delete_cert))
        .route("/api/v1/acme/certs/{id}/renew", post(acme::renew_now))
        .route("/api/v1/acme/certs/{id}/publish", post(acme::publish_now))
        .route(
            "/api/v1/acme/certs/{id}/key.pem",
            get(acme::download_key_pem),
        )
        .route("/api/v1/acme/dns-providers", post(acme::create_provider))
        .route(
            "/api/v1/acme/dns-providers/{id}",
            put(acme::update_provider).delete(acme::delete_provider),
        )
        .route(
            "/api/v1/acme/dns-providers/{id}/test",
            post(acme::test_provider),
        )
        .route(
            "/api/v1/acme/certs/{cert_id}/targets",
            post(acme::create_target),
        )
        .route(
            "/api/v1/acme/export-targets/{id}",
            delete(acme::delete_target),
        )
        .route("/api/v1/ddns/records", post(acme::create_ddns))
        .route(
            "/api/v1/ddns/records/{id}",
            put(acme::update_ddns).delete(acme::delete_ddns),
        )
        .route(
            "/api/v1/ddns/records/{id}/update",
            post(acme::force_update_ddns),
        )
        .route("/api/v1/ddns/config", put(acme::put_ddns_config))
        .layer(middleware::from_fn(perm_check!(Permission::SettingsWrite)));

    // plugins:read
    let plugins_read = Router::new()
        .route("/api/v1/plugins", get(plugins::list_plugins))
        .route("/api/v1/plugins/{name}/logs", get(plugins::get_plugin_logs))
        .route(
            "/api/v1/plugins/{name}/config",
            get(plugins::get_plugin_config),
        )
        .route("/api/v1/plugins/discover", get(plugins::discover_plugins))
        .layer(middleware::from_fn(perm_check!(Permission::PluginsRead)));

    // plugins:write
    let plugins_write = Router::new()
        .route("/api/v1/plugins/toggle", post(plugins::enable_plugin))
        .route(
            "/api/v1/plugins/{name}/config",
            put(plugins::update_plugin_config),
        )
        .layer(middleware::from_fn(perm_check!(Permission::PluginsWrite)));

    // updates:read
    let updates_read = Router::new()
        .route("/api/v1/updates/status", get(updates::update_status))
        .route("/api/v1/updates/check", post(updates::check_updates))
        .route("/api/v1/updates/schedule", get(updates::get_schedule))
        .route("/api/v1/updates/history", get(updates::update_history))
        .route(
            "/api/v1/updates/aifw/status",
            get(updates::aifw_update_status),
        )
        .route(
            "/api/v1/updates/aifw/check",
            post(updates::aifw_check_update),
        )
        .layer(middleware::from_fn(perm_check!(Permission::UpdatesRead)));

    // updates:install
    let updates_install = Router::new()
        .route("/api/v1/updates/install", post(updates::install_updates))
        .route("/api/v1/updates/schedule", put(updates::update_schedule))
        .route(
            "/api/v1/updates/aifw/install",
            post(updates::aifw_install_update),
        )
        .route(
            "/api/v1/updates/aifw/rollback",
            post(updates::aifw_rollback),
        )
        .route(
            "/api/v1/updates/aifw/restart",
            post(updates::aifw_restart_services),
        )
        .route(
            "/api/v1/updates/aifw/reboot",
            post(updates::aifw_reboot),
        )
        .layer(middleware::from_fn(perm_check!(Permission::UpdatesInstall)));

    // Local-tarball install — needs a large body limit (500 MB) for the
    // tarball upload, so it gets its own router with DefaultBodyLimit applied
    // before the auth/permission middleware.  The perm_check is still applied
    // so only UpdatesInstall-capable sessions can trigger it.
    let updates_install_local = Router::new()
        .route(
            "/api/v1/updates/aifw/install-local",
            post(updates::install_aifw_update_local),
        )
        .layer(axum::extract::DefaultBodyLimit::max(500 * 1024 * 1024))
        .layer(middleware::from_fn(perm_check!(Permission::UpdatesInstall)));

    // backup:read
    let backup_read = Router::new()
        .route("/api/v1/config/history", get(backup::config_history))
        .route("/api/v1/config/version", get(backup::get_version))
        .route("/api/v1/config/diff", get(backup::diff_versions))
        .route("/api/v1/config/check", get(backup::check_config))
        .route("/api/v1/config/export", get(routes::export_config))
        .route(
            "/api/v1/config/preview-opnsense",
            post(backup::preview_opnsense),
        )
        .route(
            "/api/v1/config/import-preview",
            post(backup::preview_import),
        )
        .route(
            "/api/v1/config/restore-preview",
            get(backup::preview_restore),
        )
        .route(
            "/api/v1/config/commit-confirm/status",
            get(backup::commit_confirm_status),
        )
        .route("/api/v1/config/retention", get(backup::get_retention))
        .route("/api/v1/backup/s3/config", get(backup_s3::get_s3_config))
        .route("/api/v1/backup/s3/list", get(backup_s3::list_s3))
        .route(
            "/api/v1/notify/smtp/config",
            get(backup_s3::get_smtp_config),
        )
        .layer(middleware::from_fn(perm_check!(Permission::BackupRead)));

    // backup:write
    let backup_write = Router::new()
        .route("/api/v1/config/import", post(routes::import_config))
        .route("/api/v1/config/restore", post(backup::restore_version))
        .route(
            "/api/v1/config/import-opnsense",
            post(backup::import_opnsense),
        )
        .route("/api/v1/config/save", post(backup::save_version))
        .route(
            "/api/v1/config/commit-confirm",
            post(backup::commit_confirm_start),
        )
        .route(
            "/api/v1/config/commit-confirm/confirm",
            post(backup::commit_confirm_accept),
        )
        .route("/api/v1/config/retention", put(backup::put_retention))
        .route("/api/v1/backup/s3/config", put(backup_s3::put_s3_config))
        .route("/api/v1/backup/s3/test", post(backup_s3::test_s3))
        .route("/api/v1/backup/s3/import", post(backup_s3::import_s3))
        .route(
            "/api/v1/notify/smtp/config",
            put(backup_s3::put_smtp_config),
        )
        .route("/api/v1/notify/smtp/test", post(backup_s3::test_smtp))
        .layer(middleware::from_fn(perm_check!(Permission::BackupWrite)));

    // system:read
    let system_read = Router::new()
        .route("/api/v1/system/general", get(system::get_general))
        .route("/api/v1/system/banner", get(system::get_banner))
        .route("/api/v1/system/ssh", get(system::get_ssh))
        .route("/api/v1/system/console", get(system::get_console))
        .route("/api/v1/system/info", get(system::get_info))
        .route("/api/v1/system/timezones", get(system::list_timezones))
        .layer(middleware::from_fn(perm_check!(Permission::SettingsRead)));

    // system:write
    let system_write = Router::new()
        .route("/api/v1/system/general", put(system::put_general))
        .route("/api/v1/system/banner", put(system::put_banner))
        .route("/api/v1/system/ssh", put(system::put_ssh))
        .route("/api/v1/system/console", put(system::put_console))
        .layer(middleware::from_fn(perm_check!(Permission::SettingsWrite)));

    // system:reboot (also governs shutdown — same privilege level)
    let system_reboot = Router::new()
        .route("/api/v1/updates/reboot", post(updates::reboot_system))
        .route("/api/v1/updates/shutdown", post(updates::shutdown_system))
        .layer(middleware::from_fn(perm_check!(Permission::SystemReboot)));

    // proxy:read
    let proxy_read = Router::new()
        .route(
            "/api/v1/reverse-proxy/status",
            get(reverse_proxy::rp_status),
        )
        .route(
            "/api/v1/reverse-proxy/config",
            get(reverse_proxy::get_config),
        )
        .route("/api/v1/reverse-proxy/logs", get(reverse_proxy::rp_logs))
        .route(
            "/api/v1/reverse-proxy/entrypoints",
            get(reverse_proxy::list_entrypoints),
        )
        .route(
            "/api/v1/reverse-proxy/http/routers",
            get(reverse_proxy::list_http_routers),
        )
        .route(
            "/api/v1/reverse-proxy/http/services",
            get(reverse_proxy::list_http_services),
        )
        .route(
            "/api/v1/reverse-proxy/http/middlewares",
            get(reverse_proxy::list_http_middlewares),
        )
        .route(
            "/api/v1/reverse-proxy/tcp/routers",
            get(reverse_proxy::list_tcp_routers),
        )
        .route(
            "/api/v1/reverse-proxy/tcp/services",
            get(reverse_proxy::list_tcp_services),
        )
        .route(
            "/api/v1/reverse-proxy/udp/routers",
            get(reverse_proxy::list_udp_routers),
        )
        .route(
            "/api/v1/reverse-proxy/udp/services",
            get(reverse_proxy::list_udp_services),
        )
        .route(
            "/api/v1/reverse-proxy/tls/certs",
            get(reverse_proxy::list_tls_certs),
        )
        .route(
            "/api/v1/reverse-proxy/tls/options",
            get(reverse_proxy::list_tls_options),
        )
        .route(
            "/api/v1/reverse-proxy/cert-resolvers",
            get(reverse_proxy::list_cert_resolvers),
        )
        .layer(middleware::from_fn(perm_check!(Permission::ProxyRead)));

    // proxy:write
    let proxy_write = Router::new()
        .route(
            "/api/v1/reverse-proxy/config",
            put(reverse_proxy::update_config),
        )
        .route(
            "/api/v1/reverse-proxy/validate",
            post(reverse_proxy::validate_config),
        )
        .route(
            "/api/v1/reverse-proxy/entrypoints",
            post(reverse_proxy::create_entrypoint),
        )
        .route(
            "/api/v1/reverse-proxy/entrypoints/{id}",
            put(reverse_proxy::update_entrypoint).delete(reverse_proxy::delete_entrypoint),
        )
        .route(
            "/api/v1/reverse-proxy/http/routers",
            post(reverse_proxy::create_http_router),
        )
        .route(
            "/api/v1/reverse-proxy/http/routers/{id}",
            put(reverse_proxy::update_http_router).delete(reverse_proxy::delete_http_router),
        )
        .route(
            "/api/v1/reverse-proxy/http/services",
            post(reverse_proxy::create_http_service),
        )
        .route(
            "/api/v1/reverse-proxy/http/services/{id}",
            put(reverse_proxy::update_http_service).delete(reverse_proxy::delete_http_service),
        )
        .route(
            "/api/v1/reverse-proxy/http/middlewares",
            post(reverse_proxy::create_http_middleware),
        )
        .route(
            "/api/v1/reverse-proxy/http/middlewares/{id}",
            put(reverse_proxy::update_http_middleware)
                .delete(reverse_proxy::delete_http_middleware),
        )
        .route(
            "/api/v1/reverse-proxy/tcp/routers",
            post(reverse_proxy::create_tcp_router),
        )
        .route(
            "/api/v1/reverse-proxy/tcp/routers/{id}",
            put(reverse_proxy::update_tcp_router).delete(reverse_proxy::delete_tcp_router),
        )
        .route(
            "/api/v1/reverse-proxy/tcp/services",
            post(reverse_proxy::create_tcp_service),
        )
        .route(
            "/api/v1/reverse-proxy/tcp/services/{id}",
            put(reverse_proxy::update_tcp_service).delete(reverse_proxy::delete_tcp_service),
        )
        .route(
            "/api/v1/reverse-proxy/udp/routers",
            post(reverse_proxy::create_udp_router),
        )
        .route(
            "/api/v1/reverse-proxy/udp/routers/{id}",
            put(reverse_proxy::update_udp_router).delete(reverse_proxy::delete_udp_router),
        )
        .route(
            "/api/v1/reverse-proxy/udp/services",
            post(reverse_proxy::create_udp_service),
        )
        .route(
            "/api/v1/reverse-proxy/udp/services/{id}",
            put(reverse_proxy::update_udp_service).delete(reverse_proxy::delete_udp_service),
        )
        .route(
            "/api/v1/reverse-proxy/tls/certs",
            post(reverse_proxy::create_tls_cert),
        )
        .route(
            "/api/v1/reverse-proxy/tls/certs/{id}",
            put(reverse_proxy::update_tls_cert).delete(reverse_proxy::delete_tls_cert),
        )
        .route(
            "/api/v1/reverse-proxy/tls/options",
            post(reverse_proxy::create_tls_option),
        )
        .route(
            "/api/v1/reverse-proxy/tls/options/{id}",
            put(reverse_proxy::update_tls_option).delete(reverse_proxy::delete_tls_option),
        )
        .route(
            "/api/v1/reverse-proxy/cert-resolvers",
            post(reverse_proxy::create_cert_resolver),
        )
        .route(
            "/api/v1/reverse-proxy/cert-resolvers/{id}",
            put(reverse_proxy::update_cert_resolver).delete(reverse_proxy::delete_cert_resolver),
        )
        .route("/api/v1/reverse-proxy/start", post(reverse_proxy::rp_start))
        .route("/api/v1/reverse-proxy/stop", post(reverse_proxy::rp_stop))
        .route(
            "/api/v1/reverse-proxy/restart",
            post(reverse_proxy::rp_restart),
        )
        .route(
            "/api/v1/reverse-proxy/apply",
            post(reverse_proxy::apply_config),
        )
        .layer(middleware::from_fn(perm_check!(Permission::ProxyWrite)));

    // multiwan:read
    let multiwan_read = Router::new()
        .route("/api/v1/multiwan/instances", get(multiwan::list_instances))
        .route(
            "/api/v1/multiwan/instances/{id}",
            get(multiwan::get_instance),
        )
        .route(
            "/api/v1/multiwan/instances/{id}/members",
            get(multiwan::list_members),
        )
        .route("/api/v1/multiwan/fibs", get(multiwan::list_fibs))
        .route("/api/v1/multiwan/gateways", get(multiwan::list_gateways))
        .route("/api/v1/multiwan/gateways/{id}", get(multiwan::get_gateway))
        .route(
            "/api/v1/multiwan/gateways/{id}/events",
            get(multiwan::list_gateway_events),
        )
        .route("/api/v1/multiwan/groups", get(multiwan::list_groups))
        .route(
            "/api/v1/multiwan/groups/{id}/members",
            get(multiwan::list_group_members),
        )
        .route(
            "/api/v1/multiwan/groups/{id}/active",
            get(multiwan::group_active),
        )
        .route("/api/v1/multiwan/policies", get(multiwan::list_policies))
        .route("/api/v1/multiwan/leaks", get(multiwan::list_leaks))
        .route("/api/v1/multiwan/flows", get(multiwan::list_flows))
        .route("/api/v1/multiwan/gateways/{id}/sla", get(multiwan::get_sla))
        .route("/api/v1/multiwan/config.yaml", get(multiwan::export_config))
        .layer(middleware::from_fn(perm_check!(Permission::MultiWanRead)));

    // multiwan:write
    let multiwan_write = Router::new()
        .route(
            "/api/v1/multiwan/instances",
            post(multiwan::create_instance),
        )
        .route(
            "/api/v1/multiwan/instances/{id}",
            put(multiwan::update_instance).delete(multiwan::delete_instance),
        )
        .route(
            "/api/v1/multiwan/instances/{id}/members",
            post(multiwan::add_member),
        )
        .route(
            "/api/v1/multiwan/instances/{id}/members/{iface}",
            delete(multiwan::remove_member),
        )
        .route("/api/v1/multiwan/gateways", post(multiwan::create_gateway))
        .route(
            "/api/v1/multiwan/gateways/{id}",
            put(multiwan::update_gateway).delete(multiwan::delete_gateway),
        )
        .route(
            "/api/v1/multiwan/gateways/{id}/probe-now",
            post(multiwan::probe_now),
        )
        .route("/api/v1/multiwan/groups", post(multiwan::create_group))
        .route(
            "/api/v1/multiwan/groups/{id}",
            put(multiwan::update_group).delete(multiwan::delete_group),
        )
        .route(
            "/api/v1/multiwan/groups/{id}/members",
            post(multiwan::add_group_member),
        )
        .route(
            "/api/v1/multiwan/groups/{id}/members/{gw}",
            delete(multiwan::remove_group_member),
        )
        .route("/api/v1/multiwan/policies", post(multiwan::create_policy))
        .route(
            "/api/v1/multiwan/policies/{id}",
            put(multiwan::update_policy).delete(multiwan::delete_policy),
        )
        .route("/api/v1/multiwan/apply", post(multiwan::apply_policies))
        .route(
            "/api/v1/multiwan/policies/reorder",
            put(multiwan::reorder_policies),
        )
        .route(
            "/api/v1/multiwan/policies/{id}/duplicate",
            post(multiwan::duplicate_policy),
        )
        .route(
            "/api/v1/multiwan/policies/{id}/toggle",
            put(multiwan::toggle_policy),
        )
        .route("/api/v1/multiwan/leaks", post(multiwan::create_leak))
        .route("/api/v1/multiwan/leaks/{id}", delete(multiwan::delete_leak))
        .route(
            "/api/v1/multiwan/leaks/seed-mgmt",
            post(multiwan::seed_mgmt_escapes),
        )
        .route("/api/v1/multiwan/preview", post(multiwan::preview_policies))
        .route(
            "/api/v1/multiwan/flows/{label}/migrate",
            post(multiwan::migrate_flow),
        )
        .route("/api/v1/multiwan/apply-yaml", post(multiwan::import_config))
        .layer(middleware::from_fn(perm_check!(Permission::MultiWanWrite)));

    // ha:manage
    let cluster_read = cluster::read_routes()
        .layer(middleware::from_fn(perm_check!(Permission::HaManage)));

    let cluster_write = cluster::write_routes()
        .layer(middleware::from_fn(perm_check!(Permission::HaManage)));

    // Merge all permission-scoped groups into one protected router with auth
    let protected_routes = Router::new()
        .merge(self_service)
        .merge(dashboard_view)
        .merge(rules_read)
        .merge(rules_write)
        .merge(nat_read)
        .merge(nat_write)
        .merge(vpn_read)
        .merge(vpn_write)
        .merge(geoip_read)
        .merge(geoip_write)
        .merge(ids_read)
        .merge(ids_write)
        .merge(dns_read)
        .merge(dns_write)
        .merge(dhcp_read)
        .merge(dhcp_write)
        .merge(aliases_read)
        .merge(aliases_write)
        .merge(ifaces_read)
        .merge(ifaces_write)
        .merge(connections_view)
        .merge(logs_view)
        .merge(users_read)
        .merge(users_write)
        .merge(settings_read)
        .merge(settings_write)
        .merge(plugins_read)
        .merge(plugins_write)
        .merge(updates_read)
        .merge(updates_install)
        .merge(updates_install_local)
        .merge(backup_read)
        .merge(backup_write)
        .merge(system_reboot)
        .merge(proxy_read)
        .merge(proxy_write)
        .merge(multiwan_read)
        .merge(multiwan_write)
        .merge(cluster_read)
        .merge(cluster_write)
        .merge(system_read)
        .merge(system_write)
        // Auto-snapshot every successful mutation. Middleware is applied
        // before the auth layer so it runs AFTER auth in the request chain;
        // save_if_changed() de-dupes by hash so no-op writes don't pollute
        // history, and retention pruning keeps the table bounded.
        .layer(middleware::from_fn_with_state(
            state.clone(),
            backup::auto_snapshot_middleware,
        ))
        .layer(auth_layer);

    let mut app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(axum::extract::DefaultBodyLimit::max(10 * 1024 * 1024)) // 10 MB
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                // Compress JSON responses (dashboards, /logs, /connections,
                // /ids/alerts) so a slow uplink doesn't starve the UI. br
                // beats gzip by ~25% on JSON but adds CPU; keep both so
                // clients negotiate.
                .layer(CompressionLayer::new().gzip(true).br(true))
                .layer(cors),
        )
        .with_state(state);

    // HSTS: when TLS is on, tell browsers to refuse plaintext for this
    // host for a year (and preload eligible). Skipped under --no-tls
    // because HSTS over HTTP would pin the user to a broken origin.
    if tls_enabled {
        app = app.layer(SetResponseHeaderLayer::if_not_present(
            axum::http::header::STRICT_TRANSPORT_SECURITY,
            axum::http::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ));
    }

    // Serve static UI if directory is provided.
    //
    // - `precompressed_br` / `precompressed_gzip`: ServeDir auto-serves
    //   `<file>.br` / `<file>.gz` siblings when the request advertises
    //   the matching Accept-Encoding, with the right Content-Encoding
    //   header. The build pipeline writes those siblings under
    //   `aifw-ui/out/`. ~5x reduction on the JS bundle.
    // - Cache-Control headers via per-path layer below: long-lived
    //   `immutable` for fingerprinted `_next/static/*` chunks (Next.js
    //   content-hashes those filenames), short for everything else,
    //   and `no-cache` for HTML so updates are seen immediately.
    if let Some(dir) = ui_dir
        && dir.exists()
    {
        let index = dir.join("index.html");
        let serve = ServeDir::new(dir)
            .precompressed_br()
            .precompressed_gzip()
            .fallback(
                ServeFile::new(index)
                    .precompressed_br()
                    .precompressed_gzip(),
            );
        let layered = tower::ServiceBuilder::new()
            .layer(axum::middleware::from_fn(ui_cache_headers))
            .service(serve);
        app = app.fallback_service(layered);
        info!(
            "Serving web UI from {} (precompressed + cache headers enabled)",
            dir.display()
        );
    }

    app
}

/// Per-path Cache-Control for the static UI. Runs as middleware in front
/// of ServeDir so we can pick the right policy from the URL path before
/// the response is built.
async fn ui_cache_headers(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::header::{CACHE_CONTROL, HeaderValue};

    // Decide the policy from the request path. Header insertion happens
    // after the inner service runs so it overrides anything ServeDir set
    // (currently nothing).
    let path = req.uri().path().to_string();
    let policy: &'static str = if path.starts_with("/_next/static/") {
        // Next.js content-hashes these filenames. Safe to cache for a year
        // and let the browser skip the validate round-trip entirely.
        "public, max-age=31536000, immutable"
    } else if path == "/"
        || path == "/index.html"
        || path.ends_with("/index.html")
        || (!path.contains('.') && !path.starts_with("/api/"))
    {
        // SPA shell + Next-routed pages without a file extension: must
        // revalidate so deploys are seen on next refresh.
        "no-cache, must-revalidate"
    } else {
        // Other static assets: 1 hour shared cache.
        "public, max-age=3600"
    };

    let mut response = next.run(req).await;
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static(policy));
    response
}

pub async fn create_app_state(
    db_path: &std::path::Path,
    auth_settings: auth::AuthSettings,
    ids_socket: PathBuf,
) -> anyhow::Result<AppState> {
    if let Some(parent) = db_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let db = Database::new(db_path).await?;
    create_state_from_db(db, auth_settings, ids_socket).await
}

#[cfg(test)]
pub async fn create_app_state_in_memory(
    auth_settings: auth::AuthSettings,
) -> anyhow::Result<AppState> {
    let db = Database::new_in_memory().await?;
    // Tests point the IDS client at a path that doesn't exist; every IPC
    // call returns Unavailable, which the handlers map to 503. Tests that
    // don't exercise IDS endpoints don't hit it. To exercise IDS endpoints
    // a test should spin up its own stub IPC server with `aifw_ids_ipc::server::serve`.
    let ids_socket = std::env::temp_dir().join(format!(
        "aifw-test-ids-{}-{}.sock",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    create_state_from_db(db, auth_settings, ids_socket).await
}

async fn create_state_from_db(
    db: Database,
    auth_settings: auth::AuthSettings,
    ids_socket: PathBuf,
) -> anyhow::Result<AppState> {
    let pool = db.pool().clone();
    let pf: Arc<dyn PfBackend> = Arc::from(aifw_pf::create_backend());

    // In-memory metrics RRD store + 1s collector tied to pf.
    // Lives for the lifetime of the process; tier retention is 30 min / 6 h / 7 d / 30 d.
    let metrics_store = Arc::new(aifw_metrics::MetricsStore::new());
    let _metrics_task =
        aifw_metrics::MetricsCollector::new(pf.clone(), metrics_store.clone()).start();

    auth::migrate(&pool).await?;

    let rule_engine = Arc::new(RuleEngine::new(db, pf.clone()));
    let nat_engine =
        Arc::new(NatEngine::new(pool.clone(), pf.clone()).with_anchor("aifw-nat".to_string()));
    nat_engine.migrate().await?;
    let vpn_engine = Arc::new(VpnEngine::new(pool.clone(), pf.clone()));
    vpn_engine.migrate().await?;
    let geoip_engine = Arc::new(GeoIpEngine::new(pool.clone(), pf.clone()));
    geoip_engine.migrate().await?;
    let multiwan_engine = Arc::new(InstanceEngine::new(pool.clone(), pf.clone()));
    multiwan_engine
        .migrate()
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    let gateway_engine = Arc::new(GatewayEngine::new(pool.clone()));
    gateway_engine
        .migrate()
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    let group_engine = Arc::new(GroupEngine::new(pool.clone()));
    group_engine
        .migrate()
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    let policy_engine = Arc::new(PolicyEngine::new(pool.clone(), pf.clone()));
    policy_engine
        .migrate()
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    let leak_engine = Arc::new(LeakEngine::new(pool.clone(), pf.clone()));
    leak_engine
        .migrate()
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    let preflight_engine = Arc::new(PreflightEngine::new(pf.clone()));
    let sla_engine = Arc::new(SlaEngine::new(pool.clone()));
    sla_engine.migrate().await.map_err(|e| anyhow::anyhow!(e))?;
    ca::migrate(&pool).await?;
    dhcp::migrate(&pool).await?;
    updates::migrate(&pool).await?;
    iface::migrate(&pool).await?;
    dns_resolver::migrate(&pool).await?;
    dns_blocklists::migrate(&pool).await?;
    aifw_core::s3_backup::migrate(&pool).await?;
    aifw_core::smtp_notify::migrate(&pool).await?;
    aifw_core::acme::migrate(&pool).await?;
    aifw_core::ddns::migrate(&pool).await?;
    reverse_proxy::migrate(&pool).await?;
    system::migrate(&pool).await?;
    time_service::migrate(&pool).await?;
    plugins::migrate(&pool).await?;
    aifw_core::config_manager::ConfigManager::new(pool.clone())
        .migrate()
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    let alias_engine = Arc::new(AliasEngine::new(pool.clone(), pf.clone()));
    alias_engine
        .migrate()
        .await
        .map_err(|e| anyhow::anyhow!(e))?;
    let conntrack = Arc::new(ConnectionTracker::new(pf.clone()));
    let cluster_engine = Arc::new(aifw_core::ClusterEngine::new(pool.clone(), pf.clone()));
    cluster_engine.migrate().await.map_err(|e| anyhow::anyhow!(e))?;
    let shaping_engine = Arc::new(ShapingEngine::new(pool.clone(), pf.clone()));
    shaping_engine.migrate().await.map_err(|e| anyhow::anyhow!(e))?;
    let tls_engine = Arc::new(TlsEngine::new(pool.clone(), pf.clone()));
    tls_engine.migrate().await.map_err(|e| anyhow::anyhow!(e))?;

    // Read aifw_cluster_enabled once at startup. The flag only changes on
    // config writes, so a cached value is always correct for the process lifetime.
    let cluster_enabled_val = tokio::process::Command::new("sysrc")
        .arg("-n")
        .arg("aifw_cluster_enabled")
        .output()
        .await
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "YES")
        .unwrap_or(false);
    let cluster_enabled = Arc::new(std::sync::atomic::AtomicBool::new(cluster_enabled_val));

    // Self-register software version for HA dashboard drift detection.
    // Run once at boot; no-op if this node is not in cluster_nodes yet.
    {
        let our_version = env!("CARGO_PKG_VERSION");
        let our_hostname = tokio::process::Command::new("hostname")
            .output()
            .await
            .ok()
            .and_then(|o| {
                if o.status.success() {
                    Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
                } else {
                    None
                }
            });
        if let Some(name) = our_hostname {
            let _ = sqlx::query(
                "UPDATE cluster_nodes SET software_version = ?1 WHERE name = ?2",
            )
            .bind(our_version)
            .bind(&name)
            .execute(&pool)
            .await;
        }
    }

    let cluster_events = aifw_common::ClusterEventBus::new();

    // Commit 10 (#226): emit ClusterEvent::Metrics every 2s for the HA dashboard sparkline.
    // Short-circuits on non-clustered nodes to avoid spawning ifconfig+pfctl subprocesses
    // every 2s on standalone deployments.
    {
        let bus = cluster_events.clone();
        let cluster_enabled_clone = cluster_enabled.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;

                // Skip emission on non-clustered nodes (O(1) cached read).
                if !cluster_enabled_clone.load(std::sync::atomic::Ordering::Relaxed) {
                    continue;
                }

                let (pfsync_in, pfsync_out, state_count) = sample_pfsync_metrics().await;
                bus.emit(aifw_common::ClusterEvent::Metrics {
                    pfsync_in,
                    pfsync_out,
                    state_count,
                    ts_ms: chrono::Utc::now().timestamp_millis() as u64,
                });
            }
        });
    }

    // IDS engine moved to aifw-ids binary (see PR 5 / spec
    // 2026-04-26-process-hardening-and-ids-extraction-design.md). The API
    // talks to it via this Unix-socket client; reads are TTL-cached inside
    // the client. ids_alerts / ids_suppressions table reads still go
    // direct-DB (no IPC hop for plain SQL pagination).
    let ids_client = Arc::new(aifw_ids_ipc::IdsClient::new(ids_socket));

    // Initialize plugin system
    let plugin_ctx = aifw_plugins::PluginContext::new(pf.clone());
    let mut plugin_mgr = aifw_plugins::PluginManager::new(plugin_ctx);

    // Register built-in plugins (disabled by default — user enables via UI)
    let _ = plugin_mgr
        .register(
            Box::new(aifw_plugins::examples::LoggingPlugin::new()),
            aifw_plugins::PluginConfig {
                enabled: false,
                ..Default::default()
            },
        )
        .await;
    let _ = plugin_mgr
        .register(
            Box::new(aifw_plugins::examples::IpReputationPlugin::new()),
            aifw_plugins::PluginConfig {
                enabled: false,
                ..Default::default()
            },
        )
        .await;
    let _ = plugin_mgr
        .register(
            Box::new(aifw_plugins::examples::WebhookPlugin::new()),
            aifw_plugins::PluginConfig {
                enabled: false,
                ..Default::default()
            },
        )
        .await;

    // Load persisted plugin enable states from DB
    let enabled_plugins: Vec<(String,)> =
        sqlx::query_as("SELECT name FROM plugin_config WHERE enabled = 1")
            .fetch_all(&pool)
            .await
            .unwrap_or_default();
    for (name,) in &enabled_plugins {
        // Unload disabled version and re-register as enabled
        let _ = plugin_mgr.unload(name).await;
        let plugin: Option<Box<dyn aifw_plugins::Plugin>> = match name.as_str() {
            "logging" => Some(Box::new(aifw_plugins::examples::LoggingPlugin::new())),
            "ip_reputation" => Some(Box::new(aifw_plugins::examples::IpReputationPlugin::new())),
            "webhook" => Some(Box::new(aifw_plugins::examples::WebhookPlugin::new())),
            _ => None,
        };
        if let Some(p) = plugin {
            let _ = plugin_mgr
                .register(
                    p,
                    aifw_plugins::PluginConfig {
                        enabled: true,
                        ..Default::default()
                    },
                )
                .await;
        }
    }

    tracing::info!(
        plugins = plugin_mgr.count(),
        running = plugin_mgr.running_count(),
        "plugin system initialized"
    );

    // Load configurable dashboard history size from DB (default 30 min = 1800 entries)
    let history_max = sqlx::query_as::<_, (String,)>(
        "SELECT value FROM auth_config WHERE key = 'dashboard_history_seconds'",
    )
    .fetch_optional(&pool)
    .await
    .ok()
    .flatten()
    .and_then(|r| r.0.parse::<usize>().ok())
    .unwrap_or(METRICS_HISTORY_SIZE_DEFAULT);

    Ok(AppState {
        pool,
        pf,
        rule_engine,
        nat_engine,
        vpn_engine,
        geoip_engine,
        multiwan_engine,
        gateway_engine,
        group_engine,
        policy_engine,
        leak_engine,
        preflight_engine,
        sla_engine,
        alias_engine,
        conntrack,
        ids_client,
        plugin_manager: Arc::new(RwLock::new(plugin_mgr)),
        metrics_store: metrics_store.clone(),
        auth_settings,
        cluster_engine,
        shaping_engine,
        tls_engine,
        cluster_enabled,
        cluster_events,
        metrics_history: Arc::new(RwLock::new(VecDeque::with_capacity(history_max.min(86400)))),
        metrics_history_max: Arc::new(std::sync::atomic::AtomicUsize::new(history_max)),
        redis: None,
        pending: Arc::new(RwLock::new(PendingChanges::default())),
        pending_tx: watch::channel(PendingChanges::default()).0,
        login_limiter: LoginRateLimiter::default(),
        ws_tickets: auth::ws_ticket::WsTicketStore::new(),
    })
}

/// Sample pfsync(4) packet counters and the pf state table size.
/// Returns (pfsync_in_pkts, pfsync_out_pkts, state_count).
/// On non-FreeBSD (dev/CI) all three are 0.
async fn sample_pfsync_metrics() -> (u64, u64, u64) {
    let pfsync_text = tokio::process::Command::new("ifconfig")
        .arg("pfsync0")
        .output()
        .await
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    // pfsync(4) ifconfig output contains lines like:
    //   input:  12345 packets, 67890 bytes
    //   output: 23456 packets, 78901 bytes
    let parse = |label: &str| -> u64 {
        for line in pfsync_text.lines() {
            let line = line.trim();
            if let Some(rest) = line.strip_prefix(label) {
                if let Some(num) = rest.split_whitespace().next() {
                    return num.replace(',', "").parse().unwrap_or(0);
                }
            }
        }
        0
    };
    let pfsync_in = parse("input:");
    let pfsync_out = parse("output:");

    let state_count = pfsync_state_count_from_si().await;

    (pfsync_in, pfsync_out, state_count)
}

/// Parse `pfctl -si` "current entries" line to get the pf state table size in O(1).
/// Format on FreeBSD:
///   State Table                          Total             Rate
///     current entries                    12345
async fn pfsync_state_count_from_si() -> u64 {
    let out = tokio::process::Command::new("pfctl")
        .args(["-si"])
        .output()
        .await;
    match out {
        Ok(o) if o.status.success() => {
            let text = String::from_utf8_lossy(&o.stdout);
            for line in text.lines() {
                let line = line.trim_start();
                if let Some(rest) = line.strip_prefix("current entries") {
                    if let Some(num) = rest.trim().split_whitespace().next() {
                        return num.parse().unwrap_or(0);
                    }
                }
            }
            0
        }
        _ => 0,
    }
}

fn ensure_tls_cert(cert_path: &std::path::Path, key_path: &std::path::Path) -> anyhow::Result<()> {
    if cert_path.exists() && key_path.exists() {
        info!("Using existing TLS certificate: {}", cert_path.display());
        return Ok(());
    }

    info!("Generating self-signed TLS certificate...");

    if let Some(parent) = cert_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut params = rcgen::CertificateParams::new(vec!["aifw.local".to_string()])?;
    params.subject_alt_names = vec![
        rcgen::SanType::DnsName("aifw.local".try_into()?),
        rcgen::SanType::DnsName("localhost".try_into()?),
        rcgen::SanType::IpAddress(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))),
    ];
    params.distinguished_name.push(
        rcgen::DnType::CommonName,
        rcgen::DnValue::Utf8String("AiFw Firewall".to_string()),
    );
    params.distinguished_name.push(
        rcgen::DnType::OrganizationName,
        rcgen::DnValue::Utf8String("AiFw".to_string()),
    );

    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    std::fs::write(cert_path, cert.pem())?;
    std::fs::write(key_path, key_pair.serialize_pem())?;

    // Restrict key file permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))?;
    }

    info!(
        "Self-signed TLS certificate generated: {}",
        cert_path.display()
    );
    Ok(())
}

/// One-shot rc.conf migration for appliances upgraded from versions that
/// predate a newer service (notably aifw_ids in v5.76.0). The in-product
/// updater drops the binary + rc.d script in place but never sets the
/// rcvar, so `service aifw_ids restart` is a silent no-op — aifw-api
/// then can't reach `/var/run/aifw/ids.sock` and every IDS endpoint
/// returns 503. Idempotent: rerunning sysrc with the same value is free.
///
/// After enabling, we also kick `aifw_ids` ourselves so the appliance
/// recovers without waiting for the operator to click "Restart Now" on
/// the very first boot of the new version.
#[cfg(target_os = "freebsd")]
async fn ensure_rc_services_enabled() {
    use tokio::process::Command;

    // Self-bootstrap libexec scripts FIRST, before kicking the watchdog
    // service — its rc.d execs /usr/local/libexec/aifw-watchdog.sh and
    // will respawn-fail in a tight loop if the file is missing. This is
    // the dominant case during a transitional upgrade where the running
    // updater predates `libexec/` iteration.
    aifw_core::updater::ensure_libexec_scripts().await;
    // Patch sudoers to allow `sudo /usr/sbin/daemon -f *` so the
    // detached restart driver actually works. Older sudoers files
    // (written before v5.81.0) lack this entry and silently break the
    // restart_services() spawn — see ensure_sudoers_daemon for details.
    aifw_core::updater::ensure_sudoers_daemon().await;
    aifw_core::updater::ensure_rcvars().await;

    // For each rcvar-managed AiFw service that isn't running, kick it.
    // Order matters: aifw_ids before aifw_api (we're aifw_api so we
    // don't kick ourselves) and aifw_watchdog last so it doesn't see
    // transient down-states from the others as "needs heal."
    for svc in ["aifw_ids", "aifw_watchdog"] {
        let status = Command::new("service")
            .args([svc, "status"])
            .output()
            .await;
        let already_running = status.map(|o| o.status.success()).unwrap_or(false);
        if already_running {
            continue;
        }
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["service", svc, "start"])
            .output()
            .await;
        info!(service = svc, "started by aifw-api startup migration");
    }
}

#[cfg(not(target_os = "freebsd"))]
async fn ensure_rc_services_enabled() {}

/// Ensure AiFw anchors are present in /usr/local/etc/aifw/pf.conf.aifw.
///
/// Works line-by-line (never substring-match) so `anchor "aifw"` cannot
/// accidentally match inside `nat-anchor "aifw"` or `rdr-anchor "aifw"`.
///
/// - Adds `rdr-anchor "aifw-nat"` after `nat-anchor "aifw-nat"` if missing
///   (fix for older installs that predated rdr support).
/// - Inserts multi-WAN filter anchors (`aifw-pbr`, `aifw-mwan-leak`,
///   `aifw-mwan-reply`) right before the first standalone `anchor "aifw"`
///   line (i.e. the filter-anchors section, never the nat/rdr section).
/// - Writes the patched file via `sudo tee` and reloads pf **only if**
///   `pfctl -nf` validates it first. If validation fails we log a loud
///   warning and leave the original file untouched.
async fn ensure_rdr_anchor() {
    let pf_path = "/usr/local/etc/aifw/pf.conf.aifw";
    let Ok(content) = tokio::fs::read_to_string(pf_path).await else {
        return;
    };

    let lines: Vec<&str> = content.lines().collect();
    let mut out: Vec<String> = Vec::with_capacity(lines.len() + 8);
    let mut changed = false;

    let has_rdr = lines.iter().any(|l| l.trim() == "rdr-anchor \"aifw-nat\"");
    let mwan_anchors = ["aifw-pbr", "aifw-mwan-leak", "aifw-mwan-reply"];
    let has_mwan: Vec<bool> = mwan_anchors
        .iter()
        .map(|a| {
            let wanted = format!("anchor \"{a}\"");
            lines.iter().any(|l| l.trim() == wanted)
        })
        .collect();

    let mut mwan_inserted = false;

    for line in lines.iter() {
        let t = line.trim();

        // 1. After `nat-anchor "aifw-nat"` inject `rdr-anchor "aifw-nat"` if absent.
        if t == "nat-anchor \"aifw-nat\"" {
            out.push((*line).to_string());
            if !has_rdr {
                out.push("rdr-anchor \"aifw-nat\"".to_string());
                changed = true;
            }
            continue;
        }

        // 2. Before the filter-section `anchor "aifw"` (trimmed EXACTLY — won't
        //    match nat-anchor or rdr-anchor), inject any missing mwan anchors.
        if !mwan_inserted && t == "anchor \"aifw\"" {
            for (i, a) in mwan_anchors.iter().enumerate() {
                if !has_mwan[i] {
                    out.push(format!("anchor \"{a}\""));
                    changed = true;
                }
            }
            mwan_inserted = true;
            out.push((*line).to_string());
            continue;
        }

        out.push((*line).to_string());
    }

    if !changed {
        return;
    }

    let patched = out.join("\n") + "\n";

    // Dry-run validate before committing. Write to a temp file, pfctl -nf it,
    // and only replace the real pf.conf.aifw if validation passes.
    let tmp_path = "/tmp/aifw-pf.conf.aifw.patched";
    if tokio::fs::write(tmp_path, &patched).await.is_err() {
        tracing::warn!("Failed to stage patched pf.conf at {tmp_path}; aborting patch");
        return;
    }
    let validate = tokio::process::Command::new("/usr/local/bin/sudo")
        .args(["/sbin/pfctl", "-nf", tmp_path])
        .output()
        .await;
    match validate {
        Ok(o) if o.status.success() => {}
        Ok(o) => {
            let err = String::from_utf8_lossy(&o.stderr).into_owned();
            tracing::warn!(
                "Patched pf.conf did NOT validate — leaving original in place. pfctl -nf: {err}"
            );
            let _ = tokio::fs::remove_file(tmp_path).await;
            return;
        }
        Err(e) => {
            tracing::warn!("pfctl -nf failed to run: {e}");
            let _ = tokio::fs::remove_file(tmp_path).await;
            return;
        }
    }

    // Validation passed — commit.
    if let Ok(mut child) = tokio::process::Command::new("/usr/local/bin/sudo")
        .args(["tee", pf_path])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
    {
        if let Some(ref mut stdin) = child.stdin {
            let _ = tokio::io::AsyncWriteExt::write_all(stdin, patched.as_bytes()).await;
        }
        drop(child.stdin.take());
        let _ = child.wait().await;
        let _ = tokio::process::Command::new("/usr/local/bin/sudo")
            .args(["/sbin/pfctl", "-f", pf_path])
            .output()
            .await;
        info!("Patched pf.conf with missing AiFw anchors and reloaded");
    }
    let _ = tokio::fs::remove_file(tmp_path).await;
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Fail closed when another instance actually holds the lock; fail open
    // when the lockfile path isn't writable (e.g. an appliance whose rc.d
    // never got upgraded to pre-create /var/run/aifw-api.lock owned by aifw).
    // The latter case lets the binary still come up so the in-product
    // updater can ship the rc.d fix that solves it. rc.d retains its own
    // singleton enforcement via the daemon-pair pidfiles.
    #[cfg(unix)]
    let _instance_lock = match aifw_common::single_instance::acquire("aifw-api") {
        Ok(lock) => Some(lock),
        Err(aifw_common::single_instance::InstanceLockError::AlreadyRunning(pid)) => {
            eprintln!("aifw-api: another instance is already running (pid {pid})");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("aifw-api: warning: singleton lock unavailable: {e} (continuing)");
            None
        }
    };

    // axum-server 0.8 + aws-sdk-* both pull in rustls 0.23 with multiple
    // crypto providers enabled (aws-lc-rs from one, ring from the other).
    // Without an explicit choice, rustls panics on the first TLS handshake
    // with "Could not automatically determine the process-level
    // CryptoProvider". Pin to aws-lc-rs since the AWS SDK already requires
    // it; doing this before any TLS is used.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| args.log_level.parse().unwrap_or_default()),
        )
        .init();

    // Temporary AuthSettings so create_app_state has a DB pool. The real
    // JWT secret is loaded from the key file below, then swapped in.
    let auth_settings = auth::AuthSettings::default();

    let mut state = create_app_state(&args.db, auth_settings, args.ids_socket.clone()).await?;

    // Resolve the JWT secret: explicit override > key file (migrating any
    // legacy DB-stored secret on first run) > freshly generated in file.
    if let Some(secret) = args.jwt_secret {
        warn!("using JWT secret from CLI/env — intended for dev only");
        state.auth_settings.jwt_secret = secret;
    } else {
        state.auth_settings.jwt_secret =
            auth::jwt_key::load_or_create(&args.jwt_key_file, &state.pool)
                .await
                .map_err(|e| anyhow::anyhow!("JWT key file: {e}"))?;
    }

    // Load non-secret auth settings from DB.
    let loaded = auth::AuthSettings::load(&state.pool).await;
    state.auth_settings.access_token_expiry_mins = loaded.access_token_expiry_mins;
    state.auth_settings.refresh_token_expiry_days = loaded.refresh_token_expiry_days;
    state.auth_settings.require_totp = loaded.require_totp;
    state.auth_settings.require_totp_for_oauth = loaded.require_totp_for_oauth;
    state.auth_settings.auto_create_oauth_users = loaded.auto_create_oauth_users;
    state.auth_settings.max_login_attempts = loaded.max_login_attempts;
    state.auth_settings.lockout_duration_secs = loaded.lockout_duration_secs;

    // Apply operator-configurable login rate-limit thresholds.
    state.login_limiter = LoginRateLimiter::with_limits(
        loaded.max_login_attempts,
        loaded.lockout_duration_secs as i64,
    );

    info!(
        "Auth settings: token expiry={}min, refresh={}days, lockout {}/{}s",
        state.auth_settings.access_token_expiry_mins,
        state.auth_settings.refresh_token_expiry_days,
        state.auth_settings.max_login_attempts,
        state.auth_settings.lockout_duration_secs,
    );

    // Connect to Valkey/Redis for metrics persistence (optional, with timeout)
    match redis::Client::open(args.valkey_url.as_str()) {
        Ok(client) => {
            match tokio::time::timeout(
                std::time::Duration::from_secs(3),
                redis::aio::ConnectionManager::new(client),
            )
            .await
            {
                Ok(inner) => match inner {
                    Ok(mut conn) => {
                        info!("Connected to Valkey for metrics persistence");
                        let max = state
                            .metrics_history_max
                            .load(std::sync::atomic::Ordering::Relaxed)
                            as i64;
                        let history: Vec<String> = redis::cmd("LRANGE")
                            .arg("aifw:metrics:history")
                            .arg(0i64)
                            .arg(max - 1)
                            .query_async(&mut conn)
                            .await
                            .unwrap_or_default();
                        if !history.is_empty() {
                            let mut buf = state.metrics_history.write().await;
                            for entry in history.into_iter().rev() {
                                buf.push_back(entry);
                            }
                            info!("Loaded {} historical metrics from Valkey", buf.len());
                        }
                        state.redis = Some(conn);
                    }
                    Err(e) => {
                        info!("Valkey not available ({}), using in-memory metrics only", e);
                    }
                },
                Err(_) => {
                    info!("Valkey connection timed out, using in-memory metrics only");
                }
            }
        }
        Err(e) => {
            info!(
                "Valkey not configured ({}), using in-memory metrics only",
                e
            );
        }
    }

    // Apply all enabled static routes from DB (survives reboot)
    routes::apply_all_routes(&state.pool).await;

    // Restore DNS servers from DB to /etc/resolv.conf (survives DHCP renewal)
    if let Ok(Some((dns_json,))) =
        sqlx::query_as::<_, (String,)>("SELECT value FROM auth_config WHERE key = 'dns_servers'")
            .fetch_optional(&state.pool)
            .await
        && let Ok(servers) = serde_json::from_str::<Vec<String>>(&dns_json)
        && !servers.is_empty()
    {
        let content: String = servers
            .iter()
            .map(|s| format!("nameserver {s}"))
            .collect::<Vec<_>>()
            .join("\n");
        if let Ok(mut child) = tokio::process::Command::new("/usr/local/bin/sudo")
            .args(["tee", "/etc/resolv.conf"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
        {
            if let Some(ref mut stdin) = child.stdin {
                let _ = tokio::io::AsyncWriteExt::write_all(stdin, content.as_bytes()).await;
            }
            drop(child.stdin.take());
            let _ = child.wait().await;
            info!("DNS servers restored from DB: {}", servers.join(", "));
        }
    }

    // Ensure rdr-anchor exists in pf.conf (required for DNAT/port forwarding)
    ensure_rdr_anchor().await;

    // Self-heal rc.conf for appliances upgraded from a version that
    // shipped before aifw_ids. Sets the rcvar and starts aifw_ids if it
    // wasn't already running. See `ensure_rc_services_enabled` for the
    // full reasoning.
    ensure_rc_services_enabled().await;

    // Collect VPN pass rules and inject into rule engine so they appear
    // before the default block in the aifw anchor
    match state.vpn_engine.collect_vpn_rules().await {
        Ok(vpn_rules) => {
            state.rule_engine.set_extra_rules(vpn_rules).await;
            tracing::info!("VPN pass rules injected into rule engine");
        }
        Err(e) => tracing::warn!("Failed to collect VPN rules: {e}"),
    }

    // Apply firewall filter rules (includes VPN pass rules) and NAT rules
    if let Err(e) = state.rule_engine.apply_rules().await {
        tracing::warn!("Failed to apply filter rules on startup: {e}");
    } else {
        tracing::info!("Filter rules applied on startup");
    }
    if let Err(e) = state.nat_engine.apply_rules().await {
        tracing::warn!("Failed to apply NAT rules on startup: {e}");
    } else {
        tracing::info!("NAT rules applied on startup");
    }

    // Also load VPN rules into their own anchor (for NAT, etc.)
    if let Err(e) = state.vpn_engine.apply_vpn_rules().await {
        tracing::warn!("Failed to apply VPN pf rules on startup: {e}");
    } else {
        tracing::info!("VPN pf rules applied on startup");
    }
    match state.vpn_engine.start_active_tunnels().await {
        Ok(n) if n > 0 => tracing::info!(count = n, "WireGuard tunnels restarted on startup"),
        Ok(_) => {}
        Err(e) => tracing::warn!("Failed to restart WireGuard tunnels: {e}"),
    }

    // Start persistent pflog0 live capture for blocked traffic page (background, non-blocking)
    ws::start_pflog_collector(state.plugin_manager.clone());

    // Start plugin timer hook — fires every 60 seconds for cron-like plugins
    {
        let pmgr = state.plugin_manager.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let mgr = pmgr.read().await;
                if mgr.running_count() > 0 {
                    let event = aifw_plugins::HookEvent {
                        hook: aifw_plugins::HookPoint::Timer,
                        data: aifw_plugins::hooks::HookEventData::Tick {
                            timestamp: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs(),
                        },
                    };
                    let _ = mgr.dispatch(&event).await;
                }
            }
        });
    }

    // Start AI analysis background task — reviews unclassified critical/high alerts every 5 minutes.
    // Now reads alerts directly from the SQLite ids_alerts table, since the
    // in-memory AlertBuffer lives in aifw-ids (other process). This keeps AI
    // analysis decoupled from the IPC layer; if aifw-ids isn't writing alerts
    // the analyzer simply finds nothing to do.
    {
        let pool = state.pool.clone();
        tokio::spawn(async move {
            // Wait 60s after startup before first run
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                match ai_analysis::run_analysis(&pool).await {
                    Ok(0) => {} // No alerts to classify
                    Ok(n) => tracing::info!(count = n, "AI classified alerts"),
                    Err(e) => tracing::debug!(error = %e, "AI analysis skipped"),
                }
            }
        });
    }

    // Periodic SQLite WAL checkpoint (every 5 minutes) to prevent WAL file bloat
    {
        let pool = state.pool.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
            loop {
                interval.tick().await;
                let _ = sqlx::query("PRAGMA wal_checkpoint(PASSIVE)")
                    .execute(&pool)
                    .await;
            }
        });
    }

    // Memory-stats heartbeat — logs per-subsystem sizes every 60s so we can
    // isolate which cache/buffer is responsible when RSS grows. Cheap: just reads
    // existing counters; no allocation. Output goes to /var/log/aifw/api.log.
    {
        let mem_state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                let hist_entries = mem_state.metrics_history.read().await.len();
                let hist_bytes: usize = mem_state
                    .metrics_history
                    .read()
                    .await
                    .iter()
                    .map(|s| s.len())
                    .sum();
                let pf_states = mem_state
                    .pf
                    .get_stats()
                    .await
                    .map(|s| s.states_count)
                    .unwrap_or(0);
                let conns = mem_state.conntrack.get_connections().await.len();
                let pmgr = mem_state.plugin_manager.read().await;
                let plugins_total = pmgr.count();
                let plugins_running = pmgr.running_count();
                drop(pmgr);
                // IDS counters now come over IPC from aifw-ids. If aifw-ids is
                // down, these stay 0 — the heartbeat keeps emitting so the
                // operator can correlate the IPC outage with API memstats.
                let ids_stats = mem_state.ids_client.get_stats().await.ok();
                let ids_rules = ids_stats.as_ref().map(|s| s.rules_loaded).unwrap_or(0);
                let flow_count = ids_stats.as_ref().map(|s| s.flow_count).unwrap_or(0);
                let flow_reassembly_kb = ids_stats
                    .as_ref()
                    .map(|s| s.flow_reassembly_bytes / 1024)
                    .unwrap_or(0);
                let (ids_alerts_db,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM ids_alerts")
                    .fetch_one(&mem_state.pool)
                    .await
                    .unwrap_or((0,));
                let rss_kb = tokio::process::Command::new("ps")
                    .args(["-o", "rss=", "-p", &std::process::id().to_string()])
                    .output()
                    .await
                    .ok()
                    .and_then(|o| {
                        String::from_utf8_lossy(&o.stdout)
                            .trim()
                            .parse::<u64>()
                            .ok()
                    })
                    .unwrap_or(0);

                tracing::info!(
                    target: "aifw_api::memstats",
                    rss_mb = rss_kb / 1024,
                    ids_alerts_total = ids_stats.as_ref().map(|s| s.alerts_total).unwrap_or(0),
                    flow_count = flow_count,
                    flow_reassembly_kb = flow_reassembly_kb,
                    ids_alerts_db = ids_alerts_db,
                    ids_rules_loaded = ids_rules,
                    metrics_history_entries = hist_entries,
                    metrics_history_kb = hist_bytes / 1024,
                    pf_states = pf_states,
                    conntrack_entries = conns,
                    plugins_total = plugins_total,
                    plugins_running = plugins_running,
                    "memstats heartbeat"
                );
            }
        });
    }

    let tls_enabled = !args.no_tls;
    let app = build_router(
        state,
        args.ui_dir.as_deref(),
        &args.cors_origins,
        tls_enabled,
    );

    if args.no_tls {
        // Refuse to serve plaintext on a reachable address unless the
        // operator has explicitly opted in — protects against accidental
        // exposure of Authorization bearer tokens.
        let bind_addr: std::net::SocketAddr = args.listen.parse()?;
        let ip = bind_addr.ip();
        let is_loopback = ip.is_loopback();
        if !is_loopback && !args.allow_plaintext_external {
            anyhow::bail!(
                "refusing to bind {} without TLS; pass --allow-plaintext-external to override",
                bind_addr
            );
        }
        if !is_loopback {
            warn!(
                "serving plaintext HTTP on {}; bearer tokens will travel in the clear",
                bind_addr
            );
        }
        let listener = tokio::net::TcpListener::bind(&args.listen).await?;
        info!("AiFw API listening on http://{}", args.listen);
        axum::serve(listener, app).await?;
    } else {
        ensure_tls_cert(&args.tls_cert, &args.tls_key)?;
        let tls_config =
            axum_server::tls_rustls::RustlsConfig::from_pem_file(&args.tls_cert, &args.tls_key)
                .await?;
        let addr: std::net::SocketAddr = args.listen.parse()?;
        info!("AiFw API listening on https://{}", addr);
        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service())
            .await?;
    }

    Ok(())
}

#[cfg(test)]
mod login_limiter_tests {
    use super::*;

    #[tokio::test]
    async fn login_limiter_prunes_expired_entries() {
        let limiter = LoginRateLimiter::with_limits(5, 1); // 1-second window
        limiter.record_failure("1.1.1.1", "alice").await;
        limiter.record_failure("2.2.2.2", "bob").await;
        assert_eq!(limiter.by_ip.read().await.len(), 2);

        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        // Any subsequent call should opportunistically prune both expired
        // entries before doing its own work.
        limiter.record_failure("3.3.3.3", "carol").await;
        assert_eq!(
            limiter.by_ip.read().await.len(),
            1,
            "expired entries should have been pruned"
        );
    }
}
