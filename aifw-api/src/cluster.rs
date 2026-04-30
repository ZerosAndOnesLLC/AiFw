//! Cluster / HA REST handlers.

use crate::AppState;
use aifw_common::{
    CarpLatencyProfile, CarpVip, ClusterEvent, ClusterNode, ClusterRole, HealthCheck,
    HealthCheckType, Interface, PfsyncConfig,
};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::{delete, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;


pub fn read_routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/cluster/carp", get(list_carp))
        .route("/api/v1/cluster/pfsync", get(get_pfsync))
        .route("/api/v1/cluster/nodes", get(list_nodes))
        .route("/api/v1/cluster/health", get(list_health))
        .route("/api/v1/cluster/status", get(get_status))
        .route("/api/v1/cluster/snapshot/hash", get(snapshot_hash))
        .route("/api/v1/cluster/snapshot", get(snapshot_get))
        .route("/api/v1/cluster/failover-history", get(failover_history))
}

pub fn write_routes() -> Router<AppState> {
    Router::new()
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
        .route("/api/v1/cluster/health/{id}", delete(delete_health))
        .route("/api/v1/cluster/promote", post(promote))
        .route("/api/v1/cluster/demote", post(demote))
        .route("/api/v1/cluster/snapshot", put(snapshot_put))
        .route("/api/v1/cluster/snapshot/force", post(snapshot_force))
        .route("/api/v1/cluster/cert-push", post(cert_push))
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
    let (role, pfsync_state_count, nodes_result) = tokio::join!(
        read_local_role(),
        pfsync_state_count(),
        state.cluster_engine.list_nodes(),
    );

    let peer_reachable = match nodes_result {
        Ok(nodes) => {
            let local = ClusterRole::parse(&role).unwrap_or(ClusterRole::Standalone);
            match nodes.iter().find(|n| n.role != local) {
                Some(peer) => ping_once(&peer.address).await,
                None => false,
            }
        }
        Err(_) => false,
    };

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

async fn pfsync_state_count() -> u64 {
    tokio::process::Command::new("sh")
        .arg("-c")
        .arg("pfctl -ss 2>/dev/null | wc -l")
        .output()
        .await
        .ok()
        .and_then(|o| {
            String::from_utf8_lossy(&o.stdout)
                .trim()
                .parse::<u64>()
                .ok()
        })
        .unwrap_or(0)
}

pub(crate) async fn read_local_role() -> String {
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
}

fn default_interval() -> u32 {
    10
}

async fn create_health(
    State(s): State<AppState>,
    Json(r): Json<HealthReq>,
) -> Result<Json<HealthCheck>, StatusCode> {
    let mut h = HealthCheck::new(r.name, r.check_type, r.target);
    h.interval_secs = r.interval_secs;
    let h = s
        .cluster_engine
        .add_health_check(h)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
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
    Json(r): Json<RoleChangedReq>,
) -> StatusCode {
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

#[derive(Deserialize)]
struct HealthChangedReq {
    check: String,
    healthy: bool,
    detail: Option<String>,
}

async fn internal_health_changed(
    State(s): State<AppState>,
    Json(r): Json<HealthChangedReq>,
) -> StatusCode {
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

    let url = format!("https://{}:8080/api/v1/cluster/snapshot", peer.address);
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

async fn failover_history(
    State(s): State<AppState>,
) -> Result<Json<Vec<serde_json::Value>>, StatusCode> {
    let rows: Vec<(String, String, String, String, String, Option<String>)> = sqlx::query_as(
        "SELECT id, ts, from_role, to_role, cause, detail FROM cluster_failover_events
         WHERE ts >= datetime('now', '-1 day')
         ORDER BY ts DESC",
    )
    .fetch_all(&s.pool)
    .await
    .map_err(|e| {
        tracing::warn!(?e, "failover_history");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(
        rows.into_iter()
            .map(|(id, ts, from_role, to_role, cause, detail)| {
                serde_json::json!({
                    "id": id,
                    "ts": ts,
                    "from_role": from_role,
                    "to_role": to_role,
                    "cause": cause,
                    "detail": detail,
                })
            })
            .collect(),
    ))
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
