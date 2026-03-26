mod auth;
mod routes;

#[cfg(test)]
mod tests;

use aifw_conntrack::ConnectionTracker;
use aifw_core::{Database, NatEngine, RuleEngine};
use aifw_pf::PfBackend;
use axum::{
    Router,
    middleware,
    routing::{delete, get, post},
};
use clap::Parser;
use sqlx::sqlite::SqlitePool;
use std::path::PathBuf;
use std::sync::Arc;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing::info;

#[derive(Clone)]
pub struct AppState {
    pub pool: SqlitePool,
    pub pf: Arc<dyn PfBackend>,
    pub rule_engine: Arc<RuleEngine>,
    pub nat_engine: Arc<NatEngine>,
    pub conntrack: Arc<ConnectionTracker>,
    pub auth_settings: auth::AuthSettings,
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

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

pub fn build_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Public routes (no auth)
    let public_routes = Router::new()
        .route("/api/v1/auth/login", post(routes::login))
        .route("/api/v1/auth/totp/login", post(routes::totp_login))
        .route("/api/v1/auth/refresh", post(routes::refresh_token))
        .route("/api/v1/auth/users", post(routes::create_user))
        .route("/api/v1/auth/oauth/{provider}/authorize", get(routes::oauth_authorize))
        .route("/api/v1/auth/oauth/{provider}/callback", get(routes::oauth_callback));

    // Protected routes (require auth)
    let protected_routes = Router::new()
        .route("/api/v1/rules", get(routes::list_rules).post(routes::create_rule))
        .route("/api/v1/rules/{id}", get(routes::get_rule).delete(routes::delete_rule))
        .route("/api/v1/nat", get(routes::list_nat_rules).post(routes::create_nat_rule))
        .route("/api/v1/nat/{id}", delete(routes::delete_nat_rule))
        .route("/api/v1/status", get(routes::status))
        .route("/api/v1/connections", get(routes::list_connections))
        .route("/api/v1/reload", post(routes::reload))
        .route("/api/v1/metrics", get(routes::metrics))
        .route("/api/v1/logs", get(routes::list_logs))
        .route("/api/v1/auth/api-keys", post(routes::create_api_key))
        .route("/api/v1/auth/logout", post(routes::logout))
        .route("/api/v1/auth/totp/setup", post(routes::totp_setup))
        .route("/api/v1/auth/totp/verify", post(routes::totp_verify))
        .route("/api/v1/auth/totp/disable", post(routes::totp_disable))
        .route("/api/v1/auth/settings", get(routes::get_auth_settings).put(routes::update_auth_settings))
        .route("/api/v1/auth/oauth/providers", get(routes::list_oauth_providers).post(routes::create_oauth_provider))
        .route("/api/v1/auth/oauth/providers/{id}", delete(routes::delete_oauth_provider))
        .layer(middleware::from_fn_with_state(state.clone(), auth::auth_middleware));

    Router::new()
        .merge(public_routes)
        .merge(protected_routes)
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(cors),
        )
        .with_state(state)
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
    let conntrack = Arc::new(ConnectionTracker::new(pf.clone()));

    Ok(AppState {
        pool,
        pf,
        rule_engine,
        nat_engine,
        conntrack,
        auth_settings,
    })
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

    let mut auth_settings = auth::AuthSettings::default();
    if let Some(secret) = args.jwt_secret {
        auth_settings.jwt_secret = secret;
    }

    let state = create_app_state(&args.db, auth_settings).await?;
    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(&args.listen).await?;
    info!("AiFw API listening on {}", args.listen);

    axum::serve(listener, app).await?;

    Ok(())
}
