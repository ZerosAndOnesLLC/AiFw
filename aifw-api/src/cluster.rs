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
        .route("/api/v1/cluster/health", post(create_health))
        .route("/api/v1/cluster/health/{id}", delete(delete_health))
        .route("/api/v1/cluster/promote", post(promote))
        .route("/api/v1/cluster/demote", post(demote))
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

async fn read_local_role() -> String {
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
