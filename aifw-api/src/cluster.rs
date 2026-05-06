//! Cluster / HA REST handlers.

use crate::AppState;
use aifw_common::{
    CarpLatencyProfile, CarpVip, ClusterEvent, ClusterNode, ClusterRole, HealthCheck,
    HealthCheckType, Interface, PfsyncConfig,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post, put},
    Extension, Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

/// Name of the API key that the aifw-daemon registers during setup.
/// Only requests authenticated with this key are accepted on the
/// `/cluster/internal/*` endpoints.
const DAEMON_LOOPBACK_KEY_NAME: &str = "aifw-daemon-loopback";


pub fn read_routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/cluster/carp", get(list_carp))
        .route("/api/v1/cluster/carp/{id}", get(get_carp))
        .route("/api/v1/cluster/pfsync", get(get_pfsync))
        .route("/api/v1/cluster/nodes", get(list_nodes))
        .route("/api/v1/cluster/nodes/{id}", get(get_node))
        .route("/api/v1/cluster/health", get(list_health))
        .route("/api/v1/cluster/status", get(get_status))
        .route("/api/v1/cluster/snapshot/hash", get(snapshot_hash))
        .route("/api/v1/cluster/snapshot", get(snapshot_get))
        .route("/api/v1/cluster/failover-history", get(failover_history))
        .route("/api/v1/cluster/health-summary", get(health_summary))
}

pub fn write_routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/cluster/health/run", post(run_health_checks))
        .route("/api/v1/cluster/carp", post(create_carp))
        .route(
            "/api/v1/cluster/carp/{id}",
            put(update_carp).delete(delete_carp),
        )
        .route("/api/v1/cluster/pfsync", put(update_pfsync))
        .route("/api/v1/cluster/nodes", post(create_node))
        .route(
            "/api/v1/cluster/nodes/{id}",
            put(update_node).delete(delete_node),
        )
        .route(
            "/api/v1/cluster/nodes/{id}/generate-key",
            post(generate_node_key),
        )
        .route("/api/v1/cluster/health", post(create_health))
        .route(
            "/api/v1/cluster/health/{id}",
            put(update_health).delete(delete_health),
        )
        .route("/api/v1/cluster/promote", post(promote))
        .route("/api/v1/cluster/demote", post(demote))
        .route("/api/v1/cluster/snapshot", put(snapshot_put))
        .route("/api/v1/cluster/snapshot/force", post(snapshot_force))
        .route("/api/v1/cluster/cert-push", post(cert_push))
        .route(
            "/api/v1/cluster/loopback-key/generate",
            post(generate_loopback_key),
        )
        // Internal endpoints — called by aifw-daemon's RoleWatcher and HealthProber.
        // Protected by the same Permission::HaManage middleware as the rest of
        // cluster_write; the daemon authenticates via AIFW_LOOPBACK_API_KEY.
        .route(
            "/api/v1/cluster/internal/role-changed",
            post(internal_role_changed),
        )
        .route(
            "/api/v1/cluster/internal/health-changed",
            post(internal_health_changed),
        )
}

#[derive(Serialize)]
pub struct StatusResponse {
    pub role: String,
    pub peer_reachable: bool,
    pub pfsync_state_count: u64,
    pub last_snapshot_hash: Option<String>,
}

async fn get_status(State(state): State<AppState>) -> Result<Json<StatusResponse>, StatusCode> {
    // Fetch nodes + local role first so we can identify the peer address,
    // then fan out state-count and ping concurrently.
    let (role, nodes_result) = tokio::join!(
        read_local_role(),
        state.cluster_engine.list_nodes(),
    );

    let peer_addr = match &nodes_result {
        Ok(nodes) => {
            let local = ClusterRole::parse(&role).unwrap_or(ClusterRole::Standalone);
            nodes.iter().find(|n| n.role != local).map(|n| n.address)
        }
        Err(_) => None,
    };

    // Fan out: pfsync state count + peer ping run concurrently.
    let (pfsync_state_count, peer_reachable) = tokio::join!(
        pfsync_state_count(),
        async move {
            match peer_addr {
                Some(addr) => ping_once(&addr).await,
                None => false,
            }
        },
    );

    let last_snapshot_hash = state
        .cluster_engine
        .last_applied_snapshot_hash()
        .await
        .ok()
        .flatten();

    Ok(Json(StatusResponse {
        role,
        peer_reachable,
        pfsync_state_count,
        last_snapshot_hash,
    }))
}

/// Parse `pfctl -si` "current entries" for O(1) state count.
async fn pfsync_state_count() -> u64 {
    let out = tokio::process::Command::new("pfctl")
        .args(["-si"])
        .output()
        .await;
    match out {
        Ok(o) if o.status.success() => {
            parse_pfctl_si_state_count(&String::from_utf8_lossy(&o.stdout))
        }
        _ => 0,
    }
}

/// Extract the "current entries" count from `pfctl -si` stdout.
/// Exposed for unit testing on Linux/WSL without running pfctl.
fn parse_pfctl_si_state_count(stdout: &str) -> u64 {
    for line in stdout.lines() {
        let line = line.trim_start();
        if let Some(rest) = line.strip_prefix("current entries") {
            if let Some(num) = rest.trim().split_whitespace().next() {
                return num.parse().unwrap_or(0);
            }
        }
    }
    0
}

pub(crate) async fn read_local_role() -> String {
    // Live CARP role from ifconfig (authoritative after failover); fall
    // back to sysrc only when no CARP iface has reported state yet.
    let live = tokio::process::Command::new("sh")
        .arg("-c")
        .arg("ifconfig 2>/dev/null | awk '/carp:/ {print tolower($2); exit}'")
        .output()
        .await
        .ok();
    if let Some(o) = live {
        if o.status.success() {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            match s.as_str() {
                "master" => return "primary".into(),
                "backup" => return "secondary".into(),
                _ => {} // fall through to sysrc fallback
            }
        }
    }
    tokio::process::Command::new("sysrc")
        .arg("-n")
        .arg("aifw_cluster_role")
        .output()
        .await
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_else(|| "standalone".into())
}

async fn ping_once(addr: &IpAddr) -> bool {
    let cmd = if addr.is_ipv6() { "ping6" } else { "ping" };
    tokio::process::Command::new(cmd)
        .args(["-c", "1", "-W", "1000"])
        .arg(addr.to_string())
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

async fn get_carp(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<CarpVip>, StatusCode> {
    s.cluster_engine
        .list_carp_vips()
        .await
        .map_err(|e| {
            tracing::warn!(?e, "list_carp_vips");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .into_iter()
        .find(|v| v.id == id)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn get_node(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ClusterNode>, StatusCode> {
    s.cluster_engine
        .list_nodes()
        .await
        .map_err(|e| {
            tracing::warn!(?e, "list_nodes");
            StatusCode::INTERNAL_SERVER_ERROR
        })?
        .into_iter()
        .find(|n| n.id == id)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn list_carp(State(s): State<AppState>) -> Result<Json<Vec<CarpVip>>, StatusCode> {
    s.cluster_engine
        .list_carp_vips()
        .await
        .map(Json)
        .map_err(|e| {
            tracing::warn!(?e, "list_carp_vips");
            StatusCode::INTERNAL_SERVER_ERROR
        })
}

#[derive(Deserialize)]
struct CarpReq {
    pub vhid: u8,
    pub virtual_ip: IpAddr,
    pub prefix: u8,
    pub interface: String,
    pub password: String,
}

async fn create_carp(
    State(s): State<AppState>,
    Json(r): Json<CarpReq>,
) -> Result<Json<CarpVip>, StatusCode> {
    let vip = CarpVip::new(
        r.vhid,
        r.virtual_ip,
        r.prefix,
        Interface(r.interface),
        r.password,
    );
    let vip = s
        .cluster_engine
        .add_carp_vip(vip)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    s.cluster_engine
        .apply_ha_rules()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(vip))
}

async fn update_carp(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    Json(r): Json<CarpReq>,
) -> Result<Json<CarpVip>, StatusCode> {
    let mut vip = CarpVip::new(
        r.vhid,
        r.virtual_ip,
        r.prefix,
        Interface(r.interface),
        r.password,
    );
    vip.id = id;
    s.cluster_engine
        .update_carp_vip(&vip)
        .await
        .map_err(|e| match e {
            aifw_common::AifwError::NotFound(_) => StatusCode::NOT_FOUND,
            _ => {
                tracing::warn!(?e, "update_carp_vip failed");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        })?;
    s.cluster_engine
        .apply_ha_rules()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(vip))
}

async fn delete_carp(State(s): State<AppState>, Path(id): Path<Uuid>) -> StatusCode {
    match s.cluster_engine.delete_carp_vip(id).await {
        Ok(_) => {
            let _ = s.cluster_engine.apply_ha_rules().await;
            StatusCode::NO_CONTENT
        }
        Err(_) => StatusCode::NOT_FOUND,
    }
}

async fn get_pfsync(
    State(s): State<AppState>,
) -> Result<Json<Option<PfsyncConfig>>, StatusCode> {
    s.cluster_engine
        .get_pfsync()
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[derive(Deserialize)]
struct PfsyncReq {
    pub sync_interface: String,
    pub sync_peer: Option<IpAddr>,
    pub defer: bool,
    pub enabled: bool,
    pub latency_profile: CarpLatencyProfile,
    pub heartbeat_iface: Option<String>,
    pub heartbeat_interval_ms: Option<u32>,
    pub dhcp_link: bool,
}

async fn update_pfsync(
    State(s): State<AppState>,
    Json(r): Json<PfsyncReq>,
) -> Result<Json<PfsyncConfig>, StatusCode> {
    let mut p = s
        .cluster_engine
        .get_pfsync()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .unwrap_or_else(|| PfsyncConfig::new(Interface(r.sync_interface.clone())));
    p.sync_interface = Interface(r.sync_interface);
    p.sync_peer = r.sync_peer;
    p.defer = r.defer;
    p.enabled = r.enabled;
    p.latency_profile = r.latency_profile;
    p.heartbeat_iface = r.heartbeat_iface.map(Interface);
    p.heartbeat_interval_ms = r.heartbeat_interval_ms;
    p.dhcp_link = r.dhcp_link;
    let p = s
        .cluster_engine
        .set_pfsync(p)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    s.cluster_engine
        .apply_ha_rules()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(p))
}

async fn list_nodes(State(s): State<AppState>) -> Result<Json<Vec<ClusterNode>>, StatusCode> {
    s.cluster_engine
        .list_nodes()
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[derive(Deserialize)]
struct NodeReq {
    pub name: String,
    pub address: IpAddr,
    pub role: ClusterRole,
}

async fn create_node(
    State(s): State<AppState>,
    Json(r): Json<NodeReq>,
) -> Result<Json<ClusterNode>, StatusCode> {
    let node = ClusterNode::new(r.name, r.address, r.role);
    let node = s
        .cluster_engine
        .add_node(node)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(node))
}

async fn update_node(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    Json(r): Json<NodeReq>,
) -> Result<Json<ClusterNode>, StatusCode> {
    let mut n = ClusterNode::new(r.name, r.address, r.role);
    n.id = id;
    s.cluster_engine
        .update_node(&n)
        .await
        .map_err(|e| match e {
            aifw_common::AifwError::NotFound(_) => StatusCode::NOT_FOUND,
            _ => {
                tracing::warn!(?e, "update_node failed");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        })?;
    Ok(Json(n))
}

async fn delete_node(State(s): State<AppState>, Path(id): Path<Uuid>) -> StatusCode {
    match s.cluster_engine.delete_node(id).await {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::NOT_FOUND,
    }
}

#[derive(Serialize)]
struct GenerateKeyResponse {
    pub key: String,
}

/// Generate (or regenerate) the per-peer API key for a cluster node.
///
/// The returned key is stored in `cluster_nodes.peer_api_key` on this node so
/// that replication, snapshot/force, and cert-push can authenticate to the peer.
/// The key is returned ONCE here; the operator must copy it to the peer node's
/// API keys table (via the peer's Users → API Keys page) before dismissing.
async fn generate_node_key(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<GenerateKeyResponse>, StatusCode> {
    let key = s
        .cluster_engine
        .generate_peer_api_key(id)
        .await
        .map_err(|e| match e {
            aifw_common::AifwError::NotFound(_) => StatusCode::NOT_FOUND,
            _ => {
                tracing::warn!(?e, "generate_peer_api_key failed");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        })?;
    Ok(Json(GenerateKeyResponse { key }))
}

async fn list_health(State(s): State<AppState>) -> Result<Json<Vec<HealthCheck>>, StatusCode> {
    s.cluster_engine
        .list_health_checks()
        .await
        .map(Json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

#[derive(Deserialize)]
struct HealthReq {
    pub name: String,
    pub check_type: HealthCheckType,
    pub target: String,
    #[serde(default = "default_interval")]
    pub interval_secs: u32,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u32,
    #[serde(default = "default_failures")]
    pub failures_before_down: u32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

fn default_interval() -> u32 {
    10
}

fn default_timeout() -> u32 {
    5
}

fn default_failures() -> u32 {
    3
}

fn default_enabled() -> bool {
    true
}

async fn create_health(
    State(s): State<AppState>,
    Json(r): Json<HealthReq>,
) -> Result<Json<HealthCheck>, StatusCode> {
    let mut h = HealthCheck::new(r.name, r.check_type, r.target);
    h.interval_secs = r.interval_secs;
    h.timeout_secs = r.timeout_secs;
    h.failures_before_down = r.failures_before_down;
    h.enabled = r.enabled;
    let h = s
        .cluster_engine
        .add_health_check(h)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(h))
}

async fn update_health(
    State(s): State<AppState>,
    Path(id): Path<Uuid>,
    Json(r): Json<HealthReq>,
) -> Result<Json<HealthCheck>, StatusCode> {
    let mut h = HealthCheck::new(r.name, r.check_type, r.target);
    h.id = id;
    h.interval_secs = r.interval_secs;
    h.timeout_secs = r.timeout_secs;
    h.failures_before_down = r.failures_before_down;
    h.enabled = r.enabled;
    s.cluster_engine
        .update_health_check(&h)
        .await
        .map_err(|e| match e {
            aifw_common::AifwError::NotFound(_) => StatusCode::NOT_FOUND,
            _ => {
                tracing::warn!(?e, "update_health_check failed");
                StatusCode::INTERNAL_SERVER_ERROR
            }
        })?;
    Ok(Json(h))
}

async fn delete_health(State(s): State<AppState>, Path(id): Path<Uuid>) -> StatusCode {
    match s.cluster_engine.delete_health_check(id).await {
        Ok(_) => StatusCode::NO_CONTENT,
        Err(_) => StatusCode::NOT_FOUND,
    }
}

async fn promote(State(s): State<AppState>) -> StatusCode {
    let ok = tokio::process::Command::new("sysctl")
        .arg("net.inet.carp.demotion=0")
        .status()
        .await
        .map(|st| st.success())
        .unwrap_or(false);
    if !ok {
        tracing::warn!("ha: failed to set net.inet.carp.demotion=0 (promote)");
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    s.cluster_events.emit(ClusterEvent::RoleChanged {
        from: aifw_common::ClusterRole::Secondary.to_string(),
        to: aifw_common::ClusterRole::Primary.to_string(),
        vhid: 0,
    });
    StatusCode::NO_CONTENT
}

async fn demote(State(s): State<AppState>) -> StatusCode {
    let ok = tokio::process::Command::new("sysctl")
        .arg("net.inet.carp.demotion=240")
        .status()
        .await
        .map(|st| st.success())
        .unwrap_or(false);
    if !ok {
        tracing::warn!("ha: failed to set net.inet.carp.demotion=240 (demote)");
        return StatusCode::INTERNAL_SERVER_ERROR;
    }
    s.cluster_events.emit(ClusterEvent::RoleChanged {
        from: aifw_common::ClusterRole::Primary.to_string(),
        to: aifw_common::ClusterRole::Secondary.to_string(),
        vhid: 0,
    });
    StatusCode::NO_CONTENT
}

// ============================================================
// Internal endpoints (Commit 7 #219)
// Called by aifw-daemon's RoleWatcher and HealthProber over the loopback.
// ============================================================

#[derive(Deserialize)]
struct RoleChangedReq {
    from: String,
    to: String,
    vhid: u8,
}

async fn internal_role_changed(
    State(s): State<AppState>,
    Extension(auth): Extension<crate::auth::AuthUser>,
    Json(r): Json<RoleChangedReq>,
) -> StatusCode {
    // Only the aifw-daemon loopback API key may call this endpoint.
    // Any HaManage holder (operator used to have it, but no longer) or other
    // admin with a stolen key cannot manipulate the failover audit history.
    if auth.api_key_name.as_deref() != Some(DAEMON_LOOPBACK_KEY_NAME) {
        tracing::warn!(
            key_name = ?auth.api_key_name,
            "internal_role_changed: rejected non-daemon caller"
        );
        return StatusCode::FORBIDDEN;
    }
    s.cluster_events.emit(ClusterEvent::RoleChanged {
        from: r.from.clone(),
        to: r.to.clone(),
        vhid: r.vhid,
    });
    if let Err(e) = s
        .cluster_engine
        .record_failover_event(&r.from, &r.to, "carp_transition", None)
        .await
    {
        tracing::warn!(?e, "internal_role_changed: record_failover_event");
    }
    StatusCode::NO_CONTENT
}

/// Maximum allowed byte length for the `detail` field in HealthChangedReq.
const HEALTH_DETAIL_MAX: usize = 1024;

#[derive(Deserialize)]
struct HealthChangedReq {
    check: String,
    healthy: bool,
    detail: Option<String>,
}

async fn internal_health_changed(
    State(s): State<AppState>,
    Extension(auth): Extension<crate::auth::AuthUser>,
    Json(r): Json<HealthChangedReq>,
) -> StatusCode {
    // Only the aifw-daemon loopback API key may call this endpoint.
    if auth.api_key_name.as_deref() != Some(DAEMON_LOOPBACK_KEY_NAME) {
        tracing::warn!(
            key_name = ?auth.api_key_name,
            "internal_health_changed: rejected non-daemon caller"
        );
        return StatusCode::FORBIDDEN;
    }
    // Cap detail field to prevent oversized log entries.
    if r.detail.as_ref().map(|s| s.len()).unwrap_or(0) > HEALTH_DETAIL_MAX {
        tracing::warn!("internal_health_changed: detail field exceeds 1024 bytes — rejected");
        return StatusCode::PAYLOAD_TOO_LARGE;
    }
    s.cluster_events.emit(ClusterEvent::HealthChanged {
        check: r.check,
        healthy: r.healthy,
        detail: r.detail,
    });
    StatusCode::NO_CONTENT
}

// ============================================================
// Snapshot endpoints (Task 5.4, Commit 5 #218)
// ============================================================

async fn snapshot_hash(State(s): State<AppState>) -> Result<String, StatusCode> {
    // Hash returned here may differ from /snapshot's body hash if config mutates between requests;
    // this endpoint is for probes/dashboards that don't require atomicity.
    let (_data, hash) = s.cluster_snapshot_data().await.map_err(|e| {
        tracing::warn!(?e, "snapshot_hash");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(hash)
}

async fn snapshot_get(State(s): State<AppState>) -> Result<String, StatusCode> {
    let (data, _hash) = s.cluster_snapshot_data().await.map_err(|e| {
        tracing::warn!(?e, "snapshot_get");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(data)
}

async fn snapshot_put(State(s): State<AppState>, body: String) -> StatusCode {
    // Master never accepts pushes — split-brain protection
    if is_carp_master_locally().await {
        return StatusCode::CONFLICT;
    }
    match apply_snapshot_data(&s, &body).await {
        Ok(hash) => {
            // Use Uuid::nil as node_id placeholder (peer identity improvable later
            // once per-peer API key is cross-referenced with the authenticated key)
            let _ = s
                .cluster_engine
                .record_snapshot_apply(Uuid::nil(), &hash, "peer")
                .await;
            StatusCode::NO_CONTENT
        }
        Err(e) => {
            tracing::warn!(?e, "snapshot apply failed");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

async fn snapshot_force(State(s): State<AppState>) -> StatusCode {
    // Look up the primary peer, fetch its snapshot, and apply locally.
    let nodes = match s.cluster_engine.list_nodes().await {
        Ok(n) => n,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
    };
    let peer = match nodes
        .iter()
        .find(|n| matches!(n.role, ClusterRole::Primary))
    {
        Some(p) => p.clone(),
        None => return StatusCode::PRECONDITION_FAILED,
    };
    let key = match s.cluster_engine.peer_api_key(peer.id).await {
        Ok(Some(k)) => k,
        _ => return StatusCode::PRECONDITION_FAILED,
    };

    let url = format!(
        "https://{}:{}/api/v1/cluster/snapshot",
        peer.address,
        aifw_common::DEFAULT_LOOPBACK_API_PORT
    );
    let client = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
    };

    let data = match client
        .get(&url)
        .header("Authorization", format!("ApiKey {key}"))
        .send()
        .await
    {
        Ok(r) => match r.text().await {
            Ok(s) => s,
            Err(_) => return StatusCode::BAD_GATEWAY,
        },
        Err(_) => return StatusCode::BAD_GATEWAY,
    };

    match apply_snapshot_data(&s, &data).await {
        Ok(hash) => {
            let _ = s
                .cluster_engine
                .record_snapshot_apply(peer.id, &hash, &peer.address.to_string())
                .await;
            StatusCode::NO_CONTENT
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

// Thin wrapper that delegates to the single shared implementation in aifw-core.
// This avoids duplicating the ifconfig grep across cluster.rs and acme_engine.rs.
async fn is_carp_master_locally() -> bool {
    aifw_core::is_local_master().await
}

async fn apply_snapshot_data(
    state: &AppState,
    body: &str,
) -> Result<String, anyhow::Error> {
    let hash = aifw_core::sha256_hex(body);
    crate::backup::apply_cluster_snapshot(state, body).await?;
    Ok(hash)
}

// ============================================================
// Failover history endpoint (Commit 10 #226)
// ============================================================

#[derive(Serialize, sqlx::FromRow)]
pub struct FailoverEvent {
    pub id: String,
    pub ts: String,
    pub from_role: String,
    pub to_role: String,
    pub cause: String,
    pub detail: Option<String>,
}

async fn failover_history(
    State(s): State<AppState>,
) -> Result<Json<Vec<FailoverEvent>>, StatusCode> {
    sqlx::query_as::<_, FailoverEvent>(
        "SELECT id, ts, from_role, to_role, cause, detail FROM cluster_failover_events
         WHERE ts >= datetime('now', '-1 day')
         ORDER BY ts DESC",
    )
    .fetch_all(&s.pool)
    .await
    .map(Json)
    .map_err(|e| {
        tracing::warn!(?e, "failover_history");
        StatusCode::INTERNAL_SERVER_ERROR
    })
}

// ============================================================
// On-demand health-check trigger (A10)
// ============================================================

async fn run_health_checks(_state: State<AppState>) -> StatusCode {
    // Signal the daemon to probe immediately. The HealthProber daemon runs on
    // its own 1-second tick; this endpoint returns 202 Accepted so the CLI
    // surface exists and the response is well-defined. A future implementation
    // may use an internal channel to wake the prober out of band.
    StatusCode::ACCEPTED
}

// ============================================================
// Cert-push endpoint (Commit 9 #222)
// Master pushes renewed ACME certs to standby peers.
// Standby applies; master rejects (split-brain protection).
// ============================================================

#[derive(Deserialize)]
struct CertPushReq {
    cert_id: i64,
    fullchain_pem: String,
    private_key_pem: String,
}

async fn cert_push(
    State(s): State<AppState>,
    Json(r): Json<CertPushReq>,
) -> StatusCode {
    // Master never accepts cert pushes — defends against a stale standby
    // pushing back during a network partition.
    if aifw_core::is_local_master().await {
        return StatusCode::CONFLICT;
    }

    // Note: we deliberately do NOT bump cluster_nodes.last_pushed_cert_at
    // on the standby side. That column is master-side bookkeeping ("we last
    // pushed cert X to peer N at time T") populated by acme_engine after a
    // successful push. The standby has no equivalent receipt timestamp; if
    // one is needed for the dashboard, add a separate column rather than
    // overloading this one.

    match aifw_core::acme_engine::import_external_cert(
        &s.pool,
        r.cert_id,
        &r.fullchain_pem,
        &r.private_key_pem,
    )
    .await
    {
        Ok(_) => {
            tracing::info!(cert_id = r.cert_id, "ha: accepted cert push from master");
            StatusCode::NO_CONTENT
        }
        Err(e) => {
            tracing::warn!(error = ?e, "ha: cert_push apply failed");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

// ============================================================
// Health summary (D2 — onboarding warnings)
// ============================================================

#[derive(Serialize)]
struct HealthSummary {
    missing_peer_keys: Vec<String>,
    loopback_key_missing: bool,
    warnings: Vec<String>,
}

async fn health_summary(State(s): State<AppState>) -> Result<Json<HealthSummary>, StatusCode> {
    let nodes = s
        .cluster_engine
        .list_nodes()
        .await
        .map_err(|e| {
            tracing::warn!(?e, "health_summary: list_nodes");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let local_role_str = read_local_role().await;
    let local_role = ClusterRole::parse(&local_role_str).unwrap_or(ClusterRole::Standalone);

    let mut missing: Vec<String> = Vec::new();
    for node in nodes.iter().filter(|n| n.role != local_role) {
        if s.cluster_engine
            .peer_api_key(node.id)
            .await
            .ok()
            .flatten()
            .is_none()
        {
            missing.push(node.name.clone());
        }
    }

    let loopback_key_missing = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM api_keys WHERE name = 'aifw-daemon-loopback'",
    )
    .fetch_one(&s.pool)
    .await
    .unwrap_or(0)
        == 0;

    let mut warnings: Vec<String> = Vec::new();
    if !missing.is_empty() {
        warnings.push(format!(
            "Replication will not flow to: {}. Click 'Generate Peer Key' on each node, copy the key, and register it on the peer.",
            missing.join(", ")
        ));
    }
    if loopback_key_missing && local_role != ClusterRole::Standalone {
        warnings.push(
            "Loopback API key not registered — cluster background tasks (replicator, role watcher, health prober) are disabled. Generate it below or re-run aifw-setup.".to_string(),
        );
    }

    Ok(Json(HealthSummary {
        missing_peer_keys: missing,
        loopback_key_missing,
        warnings,
    }))
}

// ============================================================
// Generate loopback key (D4 — post-install key generation)
// ============================================================

// ============================================================
// E4/E5 deferred: snapshot_put and cert_push reject when local role = MASTER.
// Both endpoints call is_carp_master_locally() which shells to ifconfig.
// On Linux/WSL dev there are no CARP interfaces so is_carp_master_locally()
// always returns false — the MASTER-rejection branch cannot be exercised
// without a CARP-enabled FreeBSD host. These cases are deferred to FreeBSD CI.
// See: aifw-core/src/ha.rs::current_local_role (is_local_master delegates here).
// ============================================================

async fn generate_loopback_key(
    State(s): State<AppState>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    // Generate 256 bits of entropy (two UUID simple strings = 64 hex chars).
    let key = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let prefix = key[..12].to_string();
    let hash = crate::auth::hash_password(&key)?;

    // Find or create the system user that owns this key.
    // Try to reuse an existing user named "aifw-daemon"; if absent, insert one.
    let existing_user_id: Option<String> =
        sqlx::query_scalar("SELECT id FROM users WHERE username = 'aifw-daemon' LIMIT 1")
            .fetch_optional(&s.pool)
            .await
            .map_err(|e| {
                tracing::warn!(?e, "loopback key: user lookup");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;

    let user_id = match existing_user_id {
        Some(id) => id,
        None => {
            // Create a locked system user — no password, no login.
            let uid = Uuid::new_v4().to_string();
            let dummy = crate::auth::hash_password(&format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()))?;
            sqlx::query(
                "INSERT INTO users (id, username, password_hash, totp_enabled, auth_provider, created_at) \
                 VALUES (?1, 'aifw-daemon', ?2, 0, 'system', ?3)",
            )
            .bind(&uid)
            .bind(&dummy)
            .bind(chrono::Utc::now().to_rfc3339())
            .execute(&s.pool)
            .await
            .map_err(|e| {
                tracing::warn!(?e, "loopback key: user insert");
                StatusCode::INTERNAL_SERVER_ERROR
            })?;
            uid
        }
    };

    // Delete any pre-existing loopback key then insert the new one.
    let _ = sqlx::query("DELETE FROM api_keys WHERE name = 'aifw-daemon-loopback'")
        .execute(&s.pool)
        .await;

    sqlx::query(
        "INSERT INTO api_keys (id, name, key_hash, prefix, user_id, created_at) \
         VALUES (?1, 'aifw-daemon-loopback', ?2, ?3, ?4, ?5)",
    )
    .bind(Uuid::new_v4().to_string())
    .bind(&hash)
    .bind(&prefix)
    .bind(&user_id)
    .bind(chrono::Utc::now().to_rfc3339())
    .execute(&s.pool)
    .await
    .map_err(|e| {
        tracing::warn!(?e, "loopback key: api_key insert");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    // Write plaintext key to disk (mode 640, root:aifw on FreeBSD).
    let key_path = std::path::Path::new("/usr/local/etc/aifw/daemon.key");
    if let Some(parent) = key_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Err(e) = std::fs::write(key_path, &key) {
        tracing::warn!(error = %e, "loopback key: write daemon.key (non-FreeBSD dev env — skipped)");
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(key_path) {
                let mut perms = meta.permissions();
                perms.set_mode(0o640);
                let _ = std::fs::set_permissions(key_path, perms);
            }
        }
        #[cfg(target_os = "freebsd")]
        {
            let _ = std::process::Command::new("chown")
                .arg("root:aifw")
                .arg(key_path)
                .status();
        }
    }

    tracing::info!("loopback API key (re)generated via UI");
    Ok(Json(serde_json::json!({
        "ok": true,
        "message": "Loopback key generated. Restart aifw-daemon to activate (run: service aifw_daemon restart)."
    })))
}

// ============================================================
// E9 — parse_pfctl_si_state_count unit tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::parse_pfctl_si_state_count;

    #[test]
    fn pfctl_si_parses_normal() {
        let stdout = concat!(
            "State Table                          Total             Rate\n",
            "  current entries                    12345\n",
            "  searches                       9876543210         12345.6/s\n",
        );
        assert_eq!(parse_pfctl_si_state_count(stdout), 12345);
    }

    #[test]
    fn pfctl_si_parses_zero() {
        let stdout = concat!(
            "State Table                          Total             Rate\n",
            "  current entries                        0\n",
        );
        assert_eq!(parse_pfctl_si_state_count(stdout), 0);
    }

    #[test]
    fn pfctl_si_no_state_line() {
        let stdout = "garbage\nno state line here\n";
        assert_eq!(parse_pfctl_si_state_count(stdout), 0);
    }

    #[test]
    fn pfctl_si_nonnumeric_value() {
        let stdout = "  current entries                    foo\n";
        assert_eq!(parse_pfctl_si_state_count(stdout), 0);
    }

    #[test]
    fn pfctl_si_empty_input() {
        assert_eq!(parse_pfctl_si_state_count(""), 0);
    }
}
