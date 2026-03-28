mod auth;
mod ca;
mod routes;
mod ws;

#[cfg(test)]
mod tests;

use aifw_conntrack::ConnectionTracker;
use aifw_core::{Database, GeoIpEngine, NatEngine, RuleEngine, VpnEngine};
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
use tokio::sync::RwLock;
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
    pub conntrack: Arc<ConnectionTracker>,
    pub auth_settings: auth::AuthSettings,
    pub metrics_history: Arc<RwLock<VecDeque<String>>>,
    pub redis: Option<redis::aio::ConnectionManager>,
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
        .route("/api/v1/ws", get(ws::ws_handler));

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
        .route("/api/v1/config/export", get(routes::export_config))
        .route("/api/v1/config/import", post(routes::import_config))
        .route("/api/v1/rules/system", get(routes::list_system_rules))
        .route("/api/v1/rules", get(routes::list_rules).post(routes::create_rule))
        .route("/api/v1/rules/{id}", get(routes::get_rule).put(routes::update_rule).delete(routes::delete_rule))
        .route("/api/v1/nat", get(routes::list_nat_rules).post(routes::create_nat_rule))
        .route("/api/v1/nat/{id}", put(routes::update_nat_rule).delete(routes::delete_nat_rule))
        .route("/api/v1/rules/reorder", put(routes::reorder_rules))
        .route("/api/v1/nat/reorder", put(routes::reorder_nat_rules))
        .route("/api/v1/dns", get(routes::get_dns).put(routes::update_dns))
        .route("/api/v1/settings/valkey", get(routes::get_valkey_settings).put(routes::update_valkey_settings))
        .route("/api/v1/routes", get(routes::list_static_routes).post(routes::create_static_route))
        .route("/api/v1/routes/{id}", put(routes::update_static_route).delete(routes::delete_static_route))
        .route("/api/v1/routes/system", get(routes::get_system_routes))
        .route("/api/v1/interfaces", get(routes::list_interfaces))
        .route("/api/v1/interfaces/{name}/stats", get(routes::get_interface_stats))
        .route("/api/v1/geoip", get(routes::list_geoip_rules).post(routes::create_geoip_rule))
        .route("/api/v1/geoip/{id}", put(routes::update_geoip_rule).delete(routes::delete_geoip_rule))
        .route("/api/v1/geoip/lookup/{ip}", get(routes::geoip_lookup))
        .route("/api/v1/vpn/wg", get(routes::list_wg_tunnels).post(routes::create_wg_tunnel))
        .route("/api/v1/vpn/wg/{id}", put(routes::update_wg_tunnel).delete(routes::delete_wg_tunnel))
        .route("/api/v1/vpn/wg/{id}/peers", get(routes::list_wg_peers).post(routes::create_wg_peer))
        .route("/api/v1/vpn/wg/{tid}/peers/{pid}", delete(routes::delete_wg_peer))
        .route("/api/v1/vpn/ipsec", get(routes::list_ipsec_sas).post(routes::create_ipsec_sa))
        .route("/api/v1/vpn/ipsec/{id}", delete(routes::delete_ipsec_sa))
        .route("/api/v1/status", get(routes::status))
        .route("/api/v1/connections", get(routes::list_connections))
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
    let conntrack = Arc::new(ConnectionTracker::new(pf.clone()));

    Ok(AppState {
        pool,
        pf,
        rule_engine,
        nat_engine,
        vpn_engine,
        geoip_engine,
        conntrack,
        auth_settings,
        metrics_history: Arc::new(RwLock::new(VecDeque::with_capacity(METRICS_HISTORY_SIZE))),
        redis: None,
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
