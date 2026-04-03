mod aliases;
mod auth;
mod backup;
mod ca;
mod dhcp;
mod dns_resolver;
mod iface;
mod plugins;
mod reverse_proxy;
mod routes;
mod time_service;
mod updates;
mod ws;

#[cfg(test)]
mod tests;

use aifw_conntrack::ConnectionTracker;
use aifw_core::{AliasEngine, Database, GeoIpEngine, NatEngine, RuleEngine, VpnEngine};
use aifw_pf::PfBackend;
use axum::{
    Router,
    middleware,
    routing::{delete, get, post, put},
};
use clap::Parser;
use sqlx::sqlite::SqlitePool;
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::{RwLock, watch};
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::{ServeDir, ServeFile};
use tower_http::trace::TraceLayer;
use tracing::info;

pub const METRICS_HISTORY_SIZE: usize = 1800; // 30 min at 1/sec

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub pf: Arc<dyn PfBackend>,
    pub rule_engine: Arc<RuleEngine>,
    pub nat_engine: Arc<NatEngine>,
    pub vpn_engine: Arc<VpnEngine>,
    pub geoip_engine: Arc<GeoIpEngine>,
    pub alias_engine: Arc<AliasEngine>,
    pub conntrack: Arc<ConnectionTracker>,
    pub plugin_manager: Arc<RwLock<aifw_plugins::PluginManager>>,
    pub auth_settings: auth::AuthSettings,
    pub metrics_history: Arc<RwLock<VecDeque<String>>>,
    pub redis: Option<redis::aio::ConnectionManager>,
    pub pending: Arc<RwLock<PendingChanges>>,
    /// Watch channel that fires whenever `pending` changes — drives SSE.
    pub pending_tx: watch::Sender<PendingChanges>,
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
}

#[derive(Parser)]
#[command(name = "aifw-api", about = "AiFw REST API server")]
struct Args {
    /// Path to the database file
    #[arg(long, default_value = "/var/db/aifw/aifw.db")]
    db: PathBuf,

    /// Listen address
    #[arg(long, default_value = "0.0.0.0:8080")]
    listen: String,

    /// JWT secret (auto-generated if not provided)
    #[arg(long, env = "AIFW_JWT_SECRET")]
    jwt_secret: Option<String>,

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

    /// Disable TLS (serve plain HTTP)
    #[arg(long)]
    no_tls: bool,

    /// Valkey/Redis URL for metrics persistence (optional)
    #[arg(long, env = "AIFW_VALKEY_URL", default_value = "redis://127.0.0.1:6379")]
    valkey_url: String,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

pub fn build_router(state: AppState, ui_dir: Option<&std::path::Path>) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Public routes (no auth)
    let public_routes = Router::new()
        .route("/api/v1/auth/login", post(routes::login))
        .route("/api/v1/auth/totp/login", post(routes::totp_login))
        .route("/api/v1/auth/refresh", post(routes::refresh_token))
        .route("/api/v1/auth/oauth/{provider}/authorize", get(routes::oauth_authorize))
        .route("/api/v1/auth/oauth/{provider}/callback", get(routes::oauth_callback))
        .route("/api/v1/auth/register", post(routes::create_user))
        .route("/api/v1/ws", get(ws::ws_handler))
        .route("/api/v1/pending/stream", get(routes::pending_stream));

    // Protected routes (require auth)
    let protected_routes = Router::new()
        .route("/api/v1/ca", get(ca::get_ca_info).post(ca::generate_ca))
        .route("/api/v1/ca/cert.pem", get(ca::get_ca_cert_pem))
        .route("/api/v1/ca/crl", get(ca::get_crl))
        .route("/api/v1/ca/certs", get(ca::list_certs).post(ca::issue_cert))
        .route("/api/v1/ca/certs/{id}", get(ca::get_cert).delete(ca::delete_cert))
        .route("/api/v1/ca/certs/{id}/cert.pem", get(ca::download_cert))
        .route("/api/v1/ca/certs/{id}/key.pem", get(ca::download_cert_key))
        .route("/api/v1/ca/certs/{id}/revoke", post(ca::revoke_cert))
        .route("/api/v1/dhcp/status", get(dhcp::dhcp_status))
        .route("/api/v1/dhcp/start", post(dhcp::dhcp_start))
        .route("/api/v1/dhcp/stop", post(dhcp::dhcp_stop))
        .route("/api/v1/dhcp/restart", post(dhcp::dhcp_restart))
        .route("/api/v1/dhcp/v4/config", get(dhcp::get_config).put(dhcp::update_config))
        .route("/api/v1/dhcp/v4/subnets", get(dhcp::list_subnets).post(dhcp::create_subnet))
        .route("/api/v1/dhcp/v4/subnets/{id}", put(dhcp::update_subnet).delete(dhcp::delete_subnet))
        .route("/api/v1/dhcp/v4/reservations", get(dhcp::list_reservations).post(dhcp::create_reservation))
        .route("/api/v1/dhcp/v4/reservations/{id}", put(dhcp::update_reservation).delete(dhcp::delete_reservation))
        .route("/api/v1/dhcp/v4/leases", get(dhcp::list_leases))
        .route("/api/v1/dhcp/v4/leases/{ip}", delete(dhcp::release_lease))
        .route("/api/v1/dhcp/v4/apply", post(dhcp::apply_config))
        .route("/api/v1/dhcp/ddns", get(dhcp::get_ddns_config).put(dhcp::update_ddns_config))
        .route("/api/v1/dhcp/ha/config", get(dhcp::get_ha_config).put(dhcp::update_ha_config))
        .route("/api/v1/dhcp/ha/status", get(dhcp::get_ha_status))
        .route("/api/v1/dhcp/pool-stats", get(dhcp::get_pool_stats))
        .route("/api/v1/dhcp/metrics", get(dhcp::get_metrics))
        .route("/api/v1/dhcp/logs", get(dhcp::dhcp_logs))
        .route("/api/v1/dns/resolver/status", get(dns_resolver::resolver_status))
        .route("/api/v1/dns/resolver/config", get(dns_resolver::get_config_handler).put(dns_resolver::update_config_handler))
        .route("/api/v1/dns/resolver/apply", post(dns_resolver::apply_resolver))
        .route("/api/v1/dns/resolver/start", post(dns_resolver::resolver_start))
        .route("/api/v1/dns/resolver/stop", post(dns_resolver::resolver_stop))
        .route("/api/v1/dns/resolver/restart", post(dns_resolver::resolver_restart))
        .route("/api/v1/dns/resolver/hosts", get(dns_resolver::list_hosts).post(dns_resolver::create_host))
        .route("/api/v1/dns/resolver/hosts/{id}", put(dns_resolver::update_host).delete(dns_resolver::delete_host))
        .route("/api/v1/dns/resolver/domains", get(dns_resolver::list_domains).post(dns_resolver::create_domain))
        .route("/api/v1/dns/resolver/domains/{id}", put(dns_resolver::update_domain).delete(dns_resolver::delete_domain))
        .route("/api/v1/dns/resolver/acls", get(dns_resolver::list_acls).post(dns_resolver::create_acl))
        .route("/api/v1/dns/resolver/acls/{id}", delete(dns_resolver::delete_acl))
        .route("/api/v1/dns/resolver/logs", get(dns_resolver::resolver_logs))
        .route("/api/v1/updates/status", get(updates::update_status))
        .route("/api/v1/updates/check", post(updates::check_updates))
        .route("/api/v1/updates/install", post(updates::install_updates))
        .route("/api/v1/updates/reboot", post(updates::reboot_system))
        .route("/api/v1/updates/schedule", get(updates::get_schedule).put(updates::update_schedule))
        .route("/api/v1/updates/history", get(updates::update_history))
        .route("/api/v1/updates/aifw/status", get(updates::aifw_update_status))
        .route("/api/v1/updates/aifw/check", post(updates::aifw_check_update))
        .route("/api/v1/updates/aifw/install", post(updates::aifw_install_update))
        .route("/api/v1/updates/aifw/rollback", post(updates::aifw_rollback))
        // Reverse Proxy (TrafficCop)
        .route("/api/v1/reverse-proxy/status", get(reverse_proxy::rp_status))
        .route("/api/v1/reverse-proxy/start", post(reverse_proxy::rp_start))
        .route("/api/v1/reverse-proxy/stop", post(reverse_proxy::rp_stop))
        .route("/api/v1/reverse-proxy/restart", post(reverse_proxy::rp_restart))
        .route("/api/v1/reverse-proxy/config", get(reverse_proxy::get_config).put(reverse_proxy::update_config))
        .route("/api/v1/reverse-proxy/apply", post(reverse_proxy::apply_config))
        .route("/api/v1/reverse-proxy/validate", post(reverse_proxy::validate_config))
        .route("/api/v1/reverse-proxy/logs", get(reverse_proxy::rp_logs))
        .route("/api/v1/reverse-proxy/entrypoints", get(reverse_proxy::list_entrypoints).post(reverse_proxy::create_entrypoint))
        .route("/api/v1/reverse-proxy/entrypoints/{id}", put(reverse_proxy::update_entrypoint).delete(reverse_proxy::delete_entrypoint))
        .route("/api/v1/reverse-proxy/http/routers", get(reverse_proxy::list_http_routers).post(reverse_proxy::create_http_router))
        .route("/api/v1/reverse-proxy/http/routers/{id}", put(reverse_proxy::update_http_router).delete(reverse_proxy::delete_http_router))
        .route("/api/v1/reverse-proxy/http/services", get(reverse_proxy::list_http_services).post(reverse_proxy::create_http_service))
        .route("/api/v1/reverse-proxy/http/services/{id}", put(reverse_proxy::update_http_service).delete(reverse_proxy::delete_http_service))
        .route("/api/v1/reverse-proxy/http/middlewares", get(reverse_proxy::list_http_middlewares).post(reverse_proxy::create_http_middleware))
        .route("/api/v1/reverse-proxy/http/middlewares/{id}", put(reverse_proxy::update_http_middleware).delete(reverse_proxy::delete_http_middleware))
        .route("/api/v1/reverse-proxy/tcp/routers", get(reverse_proxy::list_tcp_routers).post(reverse_proxy::create_tcp_router))
        .route("/api/v1/reverse-proxy/tcp/routers/{id}", put(reverse_proxy::update_tcp_router).delete(reverse_proxy::delete_tcp_router))
        .route("/api/v1/reverse-proxy/tcp/services", get(reverse_proxy::list_tcp_services).post(reverse_proxy::create_tcp_service))
        .route("/api/v1/reverse-proxy/tcp/services/{id}", put(reverse_proxy::update_tcp_service).delete(reverse_proxy::delete_tcp_service))
        .route("/api/v1/reverse-proxy/udp/routers", get(reverse_proxy::list_udp_routers).post(reverse_proxy::create_udp_router))
        .route("/api/v1/reverse-proxy/udp/routers/{id}", put(reverse_proxy::update_udp_router).delete(reverse_proxy::delete_udp_router))
        .route("/api/v1/reverse-proxy/udp/services", get(reverse_proxy::list_udp_services).post(reverse_proxy::create_udp_service))
        .route("/api/v1/reverse-proxy/udp/services/{id}", put(reverse_proxy::update_udp_service).delete(reverse_proxy::delete_udp_service))
        .route("/api/v1/reverse-proxy/tls/certs", get(reverse_proxy::list_tls_certs).post(reverse_proxy::create_tls_cert))
        .route("/api/v1/reverse-proxy/tls/certs/{id}", put(reverse_proxy::update_tls_cert).delete(reverse_proxy::delete_tls_cert))
        .route("/api/v1/reverse-proxy/tls/options", get(reverse_proxy::list_tls_options).post(reverse_proxy::create_tls_option))
        .route("/api/v1/reverse-proxy/tls/options/{id}", put(reverse_proxy::update_tls_option).delete(reverse_proxy::delete_tls_option))
        .route("/api/v1/reverse-proxy/cert-resolvers", get(reverse_proxy::list_cert_resolvers).post(reverse_proxy::create_cert_resolver))
        .route("/api/v1/reverse-proxy/cert-resolvers/{id}", put(reverse_proxy::update_cert_resolver).delete(reverse_proxy::delete_cert_resolver))
        // Time Service (rTIME)
        .route("/api/v1/time/status", get(time_service::time_status))
        .route("/api/v1/time/start", post(time_service::time_start))
        .route("/api/v1/time/stop", post(time_service::time_stop))
        .route("/api/v1/time/restart", post(time_service::time_restart))
        .route("/api/v1/time/config", get(time_service::get_config).put(time_service::update_config))
        .route("/api/v1/time/apply", post(time_service::apply_config))
        .route("/api/v1/time/sources", get(time_service::list_sources).post(time_service::create_source))
        .route("/api/v1/time/sources/{id}", put(time_service::update_source).delete(time_service::delete_source))
        .route("/api/v1/time/logs", get(time_service::time_logs))
        // Plugins
        .route("/api/v1/plugins", get(plugins::list_plugins))
        .route("/api/v1/plugins/toggle", post(plugins::enable_plugin))
        .route("/api/v1/config/export", get(routes::export_config))
        .route("/api/v1/config/import", post(routes::import_config))
        .route("/api/v1/config/history", get(backup::config_history))
        .route("/api/v1/config/version", get(backup::get_version))
        .route("/api/v1/config/diff", get(backup::diff_versions))
        .route("/api/v1/config/save", post(backup::save_version))
        .route("/api/v1/config/restore", post(backup::restore_version))
        .route("/api/v1/config/check", get(backup::check_config))
        .route("/api/v1/config/import-opnsense", post(backup::import_opnsense))
        .route("/api/v1/config/preview-opnsense", post(backup::preview_opnsense))
        .route("/api/v1/config/commit-confirm", post(backup::commit_confirm_start))
        .route("/api/v1/config/commit-confirm/confirm", post(backup::commit_confirm_accept))
        .route("/api/v1/config/commit-confirm/status", get(backup::commit_confirm_status))
        .route("/api/v1/schedules", get(routes::list_schedules).post(routes::create_schedule))
        .route("/api/v1/schedules/{id}", put(routes::update_schedule).delete(routes::delete_schedule))
        .route("/api/v1/rules/system", get(routes::list_system_rules))
        .route("/api/v1/rules", get(routes::list_rules).post(routes::create_rule))
        .route("/api/v1/rules/{id}", get(routes::get_rule).put(routes::update_rule).delete(routes::delete_rule))
        .route("/api/v1/rules/block-logging", post(routes::toggle_block_logging))
        .route("/api/v1/nat", get(routes::list_nat_rules).post(routes::create_nat_rule))
        .route("/api/v1/nat/pf-output", get(routes::get_nat_pf_output))
        .route("/api/v1/nat/{id}", put(routes::update_nat_rule).delete(routes::delete_nat_rule))
        .route("/api/v1/rules/reorder", put(routes::reorder_rules))
        .route("/api/v1/nat/reorder", put(routes::reorder_nat_rules))
        .route("/api/v1/dns", get(routes::get_dns).put(routes::update_dns))
        .route("/api/v1/settings/tls", get(routes::get_tls_settings).put(routes::update_tls_settings))
        .route("/api/v1/settings/valkey", get(routes::get_valkey_settings).put(routes::update_valkey_settings))
        .route("/api/v1/routes", get(routes::list_static_routes).post(routes::create_static_route))
        .route("/api/v1/routes/{id}", put(routes::update_static_route).delete(routes::delete_static_route))
        .route("/api/v1/routes/system", get(routes::get_system_routes))
        .route("/api/v1/interfaces", get(routes::list_interfaces))
        .route("/api/v1/interfaces/detailed", get(iface::list_interfaces_detailed))
        .route("/api/v1/interfaces/roles", get(iface::list_interface_roles))
        .route("/api/v1/interfaces/{name}/role", put(iface::set_interface_role).delete(iface::delete_interface_role))
        .route("/api/v1/interfaces/config/{name}", put(iface::configure_interface))
        .route("/api/v1/vlans", get(iface::list_vlans).post(iface::create_vlan))
        .route("/api/v1/vlans/{id}", put(iface::update_vlan).delete(iface::delete_vlan))
        .route("/api/v1/interfaces/{name}/stats", get(routes::get_interface_stats))
        .route("/api/v1/aliases", get(aliases::list_aliases).post(aliases::create_alias))
        .route("/api/v1/aliases/{id}", get(aliases::get_alias).put(aliases::update_alias).delete(aliases::delete_alias))
        .route("/api/v1/geoip", get(routes::list_geoip_rules).post(routes::create_geoip_rule))
        .route("/api/v1/geoip/{id}", put(routes::update_geoip_rule).delete(routes::delete_geoip_rule))
        .route("/api/v1/geoip/lookup/{ip}", get(routes::geoip_lookup))
        .route("/api/v1/vpn/wg", get(routes::list_wg_tunnels).post(routes::create_wg_tunnel))
        .route("/api/v1/vpn/wg/{id}", put(routes::update_wg_tunnel).delete(routes::delete_wg_tunnel))
        .route("/api/v1/vpn/wg/{id}/peers", get(routes::list_wg_peers).post(routes::create_wg_peer))
        .route("/api/v1/vpn/wg/{tid}/peers/{pid}", delete(routes::delete_wg_peer))
        .route("/api/v1/vpn/ipsec", get(routes::list_ipsec_sas).post(routes::create_ipsec_sa))
        .route("/api/v1/vpn/ipsec/{id}", delete(routes::delete_ipsec_sa))
        .route("/api/v1/pending", get(routes::get_pending))
        .route("/api/v1/status", get(routes::status))
        .route("/api/v1/connections", get(routes::list_connections))
        .route("/api/v1/blocked", get(routes::list_blocked_traffic))
        .route("/api/v1/reload", post(routes::reload))
        .route("/api/v1/metrics", get(routes::metrics))
        .route("/api/v1/logs", get(routes::list_logs))
        .route("/api/v1/auth/users", get(routes::list_users).post(routes::create_user))
        .route("/api/v1/auth/users/{id}", get(routes::get_user).put(routes::update_user).delete(routes::delete_user_handler))
        .route("/api/v1/auth/audit", get(routes::list_user_audit))
        .route("/api/v1/auth/api-keys", post(routes::create_api_key))
        .route("/api/v1/auth/logout", post(routes::logout))
        .route("/api/v1/auth/totp/setup", post(routes::totp_setup))
        .route("/api/v1/auth/totp/verify", post(routes::totp_verify))
        .route("/api/v1/auth/totp/disable", post(routes::totp_disable))
        .route("/api/v1/auth/settings", get(routes::get_auth_settings).put(routes::update_auth_settings))
        .route("/api/v1/auth/oauth/providers", get(routes::list_oauth_providers).post(routes::create_oauth_provider))
        .route("/api/v1/auth/oauth/providers/{id}", delete(routes::delete_oauth_provider))
        .layer(middleware::from_fn_with_state(state.clone(), auth::auth_middleware));

    let mut app = Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(cors),
        )
        .with_state(state);

    // Serve static UI if directory is provided
    if let Some(dir) = ui_dir {
        if dir.exists() {
            let index = dir.join("index.html");
            app = app.fallback_service(ServeDir::new(dir).fallback(ServeFile::new(index)));
            info!("Serving web UI from {}", dir.display());
        }
    }

    app
}

pub async fn create_app_state(
    db_path: &std::path::Path,
    auth_settings: auth::AuthSettings,
) -> anyhow::Result<AppState> {
    if let Some(parent) = db_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }

    let db = Database::new(db_path).await?;
    create_state_from_db(db, auth_settings).await
}

#[cfg(test)]
pub async fn create_app_state_in_memory(
    auth_settings: auth::AuthSettings,
) -> anyhow::Result<AppState> {
    let db = Database::new_in_memory().await?;
    create_state_from_db(db, auth_settings).await
}

async fn create_state_from_db(
    db: Database,
    auth_settings: auth::AuthSettings,
) -> anyhow::Result<AppState> {
    let pool = db.pool().clone();
    let pf: Arc<dyn PfBackend> = Arc::from(aifw_pf::create_backend());

    auth::migrate(&pool).await?;

    let rule_engine = Arc::new(RuleEngine::new(db, pf.clone()));
    let nat_engine = Arc::new(NatEngine::new(pool.clone(), pf.clone()));
    nat_engine.migrate().await?;
    let vpn_engine = Arc::new(VpnEngine::new(pool.clone(), pf.clone()));
    vpn_engine.migrate().await?;
    let geoip_engine = Arc::new(GeoIpEngine::new(pool.clone(), pf.clone()));
    geoip_engine.migrate().await?;
    ca::migrate(&pool).await?;
    dhcp::migrate(&pool).await?;
    updates::migrate(&pool).await?;
    iface::migrate(&pool).await?;
    dns_resolver::migrate(&pool).await?;
    reverse_proxy::migrate(&pool).await?;
    time_service::migrate(&pool).await?;
    plugins::migrate(&pool).await?;
    aifw_core::config_manager::ConfigManager::new(pool.clone()).migrate().await.map_err(|e| anyhow::anyhow!(e))?;
    let alias_engine = Arc::new(AliasEngine::new(pool.clone(), pf.clone()));
    alias_engine.migrate().await.map_err(|e| anyhow::anyhow!(e))?;
    let conntrack = Arc::new(ConnectionTracker::new(pf.clone()));

    // Initialize plugin system
    let plugin_ctx = aifw_plugins::PluginContext::new(pf.clone());
    let mut plugin_mgr = aifw_plugins::PluginManager::new(plugin_ctx);

    // Register built-in plugins (disabled by default — user enables via UI)
    let _ = plugin_mgr.register(
        Box::new(aifw_plugins::examples::LoggingPlugin::new()),
        aifw_plugins::PluginConfig { enabled: false, ..Default::default() },
    ).await;
    let _ = plugin_mgr.register(
        Box::new(aifw_plugins::examples::IpReputationPlugin::new()),
        aifw_plugins::PluginConfig { enabled: false, ..Default::default() },
    ).await;
    let _ = plugin_mgr.register(
        Box::new(aifw_plugins::examples::WebhookPlugin::new()),
        aifw_plugins::PluginConfig { enabled: false, ..Default::default() },
    ).await;

    // Load persisted plugin enable states from DB
    let enabled_plugins: Vec<(String,)> = sqlx::query_as("SELECT name FROM plugin_config WHERE enabled = 1")
        .fetch_all(&pool).await.unwrap_or_default();
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
            let _ = plugin_mgr.register(p, aifw_plugins::PluginConfig { enabled: true, ..Default::default() }).await;
        }
    }

    tracing::info!(plugins = plugin_mgr.count(), running = plugin_mgr.running_count(), "plugin system initialized");

    Ok(AppState {
        pool,
        pf,
        rule_engine,
        nat_engine,
        vpn_engine,
        geoip_engine,
        alias_engine,
        conntrack,
        plugin_manager: Arc::new(RwLock::new(plugin_mgr)),
        auth_settings,
        metrics_history: Arc::new(RwLock::new(VecDeque::with_capacity(METRICS_HISTORY_SIZE))),
        redis: None,
        pending: Arc::new(RwLock::new(PendingChanges::default())),
        pending_tx: watch::channel(PendingChanges::default()).0,
    })
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

    info!("Self-signed TLS certificate generated: {}", cert_path.display());
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| args.log_level.parse().unwrap_or_default()),
        )
        .init();

    // Create state first to get the DB pool, then load settings from DB
    let mut auth_settings = auth::AuthSettings::default();
    if let Some(ref secret) = args.jwt_secret {
        auth_settings.jwt_secret = secret.clone();
    }

    let mut state = create_app_state(&args.db, auth_settings).await?;

    // Load auth settings from DB (overrides defaults with saved values)
    let loaded = auth::AuthSettings::load(&state.pool).await;
    // Preserve the JWT secret from CLI arg if provided, otherwise use DB/generated
    if let Some(secret) = args.jwt_secret {
        state.auth_settings.jwt_secret = secret;
    } else if loaded.jwt_secret != state.auth_settings.jwt_secret {
        // DB has a persisted secret — use it
        state.auth_settings.jwt_secret = loaded.jwt_secret;
    }
    state.auth_settings.access_token_expiry_mins = loaded.access_token_expiry_mins;
    state.auth_settings.refresh_token_expiry_days = loaded.refresh_token_expiry_days;
    state.auth_settings.require_totp = loaded.require_totp;
    state.auth_settings.require_totp_for_oauth = loaded.require_totp_for_oauth;
    state.auth_settings.auto_create_oauth_users = loaded.auto_create_oauth_users;

    // Persist the JWT secret to DB if not already saved (so it survives restarts)
    let _ = auth::AuthSettings::save_setting(&state.pool, "jwt_secret", &state.auth_settings.jwt_secret).await;

    info!("Auth settings: token expiry={}min, refresh={}days", state.auth_settings.access_token_expiry_mins, state.auth_settings.refresh_token_expiry_days);

    // Connect to Valkey/Redis for metrics persistence (optional, with timeout)
    match redis::Client::open(args.valkey_url.as_str()) {
        Ok(client) => {
            match tokio::time::timeout(
                std::time::Duration::from_secs(3),
                redis::aio::ConnectionManager::new(client),
            ).await {
            Ok(inner) => match inner {
                Ok(mut conn) => {
                    info!("Connected to Valkey for metrics persistence");
                    let history: Vec<String> = redis::cmd("LRANGE")
                        .arg("aifw:metrics:history")
                        .arg(0i64)
                        .arg(METRICS_HISTORY_SIZE as i64 - 1)
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
            info!("Valkey not configured ({}), using in-memory metrics only", e);
        }
    }

    // Start persistent pflog0 live capture for blocked traffic page
    ws::start_pflog_collector(state.plugin_manager.clone()).await;

    let app = build_router(state, args.ui_dir.as_deref());

    if args.no_tls {
        let listener = tokio::net::TcpListener::bind(&args.listen).await?;
        info!("AiFw API listening on http://{}", args.listen);
        axum::serve(listener, app).await?;
    } else {
        ensure_tls_cert(&args.tls_cert, &args.tls_key)?;
        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
            &args.tls_cert,
            &args.tls_key,
        )
        .await?;
        let addr: std::net::SocketAddr = args.listen.parse()?;
        info!("AiFw API listening on https://{}", addr);
        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service())
            .await?;
    }

    Ok(())
}
