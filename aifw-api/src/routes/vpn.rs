//! `/api/v1/vpn` handlers — WireGuard tunnels and peers, plus IPsec SAs.

use super::*;

#[derive(Debug, Deserialize)]
pub struct CreateWgTunnelRequest {
    pub name: String,
    pub listen_port: u16,
    pub address: String,
    pub private_key: Option<String>,
    pub dns: Option<String>,
    pub mtu: Option<u16>,
    pub listen_interface: Option<String>,
    /// Comma-separated CIDRs to advertise as split-tunnel AllowedIPs.
    /// When empty/omitted, falls back to the tunnel's network CIDR.
    pub split_routes: Option<String>,
}

pub async fn list_wg_tunnels(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<WgTunnel>>>, StatusCode> {
    let tunnels = state
        .vpn_engine
        .list_wg_tunnels()
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: tunnels }))
}

pub async fn create_wg_tunnel(
    State(state): State<AppState>,
    Json(req): Json<CreateWgTunnelRequest>,
) -> Result<(StatusCode, Json<ApiResponse<WgTunnel>>), StatusCode> {
    let address = Address::parse(&req.address).map_err(|_| bad_request())?;
    // FreeBSD requires short interface names: wg0, wg1, etc. (not wg51820)
    let existing = state.vpn_engine.list_wg_tunnels().await.unwrap_or_default();
    let used_indices: std::collections::HashSet<u32> = existing
        .iter()
        .filter_map(|t| {
            t.interface
                .0
                .strip_prefix("wg")
                .and_then(|n| n.parse().ok())
        })
        .collect();
    let next_idx = (0u32..).find(|i| !used_indices.contains(i)).unwrap_or(0);
    let iface_name = format!("wg{next_idx}");
    let mut tunnel = WgTunnel::new(req.name, Interface(iface_name), req.listen_port, address);
    if let Some(ref pk) = req.private_key {
        tunnel.private_key = pk.clone();
    }
    tunnel.dns = req.dns;
    tunnel.mtu = req.mtu;
    tunnel.listen_interface = req.listen_interface;
    tunnel.split_routes = req
        .split_routes
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let tunnel = state
        .vpn_engine
        .add_wg_tunnel(tunnel)
        .await
        .map_err(|_| bad_request())?;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: tunnel })))
}

pub async fn update_wg_tunnel(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateWgTunnelRequest>,
) -> Result<Json<ApiResponse<WgTunnel>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let mut tunnel = state
        .vpn_engine
        .get_wg_tunnel(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    tunnel.name = req.name;
    tunnel.listen_port = req.listen_port;
    tunnel.address = Address::parse(&req.address).map_err(|_| bad_request())?;
    tunnel.dns = req.dns;
    tunnel.mtu = req.mtu;
    tunnel.listen_interface = req.listen_interface;
    tunnel.split_routes = req
        .split_routes
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    tunnel.updated_at = chrono::Utc::now();
    let tunnel = state
        .vpn_engine
        .update_wg_tunnel(tunnel)
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: tunnel }))
}

pub async fn delete_wg_tunnel(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    // Stop tunnel if running before deleting
    let _ = state.vpn_engine.stop_tunnel(uuid).await;
    state
        .vpn_engine
        .delete_wg_tunnel(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(MessageResponse {
        message: format!("WG tunnel {id} deleted"),
    }))
}

pub async fn start_wg_tunnel(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    state.vpn_engine.start_tunnel(uuid).await.map_err(|e| {
        tracing::error!("Failed to start tunnel: {e}");
        internal()
    })?;
    // start_tunnel refreshed the aifw-vpn anchor (pass + NAT); also
    // re-inject the pass rules into the aifw anchor ahead of its block rule
    if let Ok(vpn_rules) = state.vpn_engine.collect_vpn_rules().await {
        state.rule_engine.set_extra_rules(vpn_rules).await;
        let _ = state.rule_engine.apply_rules().await;
    }
    Ok(Json(MessageResponse {
        message: "Tunnel started".to_string(),
    }))
}

pub async fn stop_wg_tunnel(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    state
        .vpn_engine
        .stop_tunnel(uuid)
        .await
        .map_err(|_| internal())?;
    // Drop this tunnel's pass rules from the aifw anchor extras too
    if let Ok(vpn_rules) = state.vpn_engine.collect_vpn_rules().await {
        state.rule_engine.set_extra_rules(vpn_rules).await;
        let _ = state.rule_engine.apply_rules().await;
    }
    Ok(Json(MessageResponse {
        message: "Tunnel stopped".to_string(),
    }))
}

pub async fn wg_tunnel_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let status = state
        .vpn_engine
        .tunnel_status(uuid)
        .await
        .map_err(|_| internal())?;
    Ok(Json(status))
}

pub async fn next_wg_peer_ip(
    State(state): State<AppState>,
    Path(tunnel_id): Path<String>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let tid = Uuid::parse_str(&tunnel_id).map_err(|_| bad_request())?;
    let ip = state
        .vpn_engine
        .next_peer_ip(tid)
        .await
        .map_err(|_| internal())?;
    Ok(Json(serde_json::json!({ "next_ip": ip })))
}

// --- VPN: WireGuard Peers ---

#[derive(Debug, Deserialize)]
pub struct CreateWgPeerRequest {
    pub name: Option<String>,
    pub public_key: Option<String>,
    pub preshared_key: Option<String>,
    pub auto_generate_key: Option<bool>,
    pub endpoint: Option<String>,
    pub allowed_ips: String,
    pub keepalive: Option<u16>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateWgPeerRequest {
    pub name: Option<String>,
    pub endpoint: Option<String>,
    pub allowed_ips: Option<String>,
    pub keepalive: Option<u16>,
    pub preshared_key: Option<String>,
}

pub async fn list_wg_peers(
    State(state): State<AppState>,
    Path(tunnel_id): Path<String>,
) -> Result<Json<ApiResponse<Vec<WgPeer>>>, StatusCode> {
    let uuid = Uuid::parse_str(&tunnel_id).map_err(|_| bad_request())?;
    let peers = state
        .vpn_engine
        .list_wg_peers(uuid)
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: peers }))
}

pub async fn create_wg_peer(
    State(state): State<AppState>,
    Path(tunnel_id): Path<String>,
    Json(req): Json<CreateWgPeerRequest>,
) -> Result<(StatusCode, Json<ApiResponse<WgPeer>>), StatusCode> {
    let tid = Uuid::parse_str(&tunnel_id).map_err(|_| bad_request())?;
    // Auto-assign IP if allowed_ips is empty or "auto"
    let ips_str = if req.allowed_ips.trim().is_empty() || req.allowed_ips.trim() == "auto" {
        state
            .vpn_engine
            .next_peer_ip(tid)
            .await
            .map_err(|_| bad_request())?
    } else {
        req.allowed_ips.clone()
    };
    let allowed_ips: Vec<Address> = ips_str
        .split(',')
        .map(|s| Address::parse(s.trim()))
        .collect::<aifw_common::Result<Vec<_>>>()
        .map_err(|_| bad_request())?;

    let auto_gen = req.auto_generate_key.unwrap_or(false);
    let mut peer = if auto_gen {
        WgPeer::new_with_generated_key(tid, req.name.unwrap_or_default())
    } else {
        let pk = req.public_key.unwrap_or_default();
        if pk.is_empty() {
            return Err(bad_request());
        }
        WgPeer::new(tid, req.name.unwrap_or_default(), pk)
    };
    peer.allowed_ips = allowed_ips;
    peer.endpoint = req.endpoint;
    peer.persistent_keepalive = req.keepalive;
    peer.preshared_key = req.preshared_key;
    let peer = state
        .vpn_engine
        .add_wg_peer(peer)
        .await
        .map_err(|_| bad_request())?;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: peer })))
}

pub async fn update_wg_peer(
    State(state): State<AppState>,
    Path((_tid, pid)): Path<(String, String)>,
    Json(req): Json<UpdateWgPeerRequest>,
) -> Result<Json<ApiResponse<WgPeer>>, StatusCode> {
    let uuid = Uuid::parse_str(&pid).map_err(|_| bad_request())?;
    let mut peer = state
        .vpn_engine
        .get_wg_peer(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    if let Some(name) = req.name {
        peer.name = name;
    }
    if let Some(ep) = req.endpoint {
        peer.endpoint = if ep.is_empty() { None } else { Some(ep) };
    }
    if let Some(ref ips) = req.allowed_ips {
        peer.allowed_ips = ips
            .split(',')
            .map(|s| Address::parse(s.trim()))
            .collect::<aifw_common::Result<Vec<_>>>()
            .map_err(|_| bad_request())?;
    }
    if let Some(ka) = req.keepalive {
        peer.persistent_keepalive = if ka == 0 { None } else { Some(ka) };
    }
    if let Some(psk) = req.preshared_key {
        peer.preshared_key = if psk.is_empty() { None } else { Some(psk) };
    }
    state
        .vpn_engine
        .update_wg_peer(&peer)
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: peer }))
}

/// Get the WAN IP address for use as WireGuard endpoint in client configs.
async fn get_wan_ip(state: &AppState) -> Option<String> {
    // Find the WAN interface name from interface_roles
    let row: Option<(String,)> =
        sqlx::query_as("SELECT interface_name FROM interface_roles WHERE role = 'WAN' LIMIT 1")
            .fetch_optional(&state.pool)
            .await
            .ok()?;
    let wan_iface = row?.0;
    // Get the IP from ifconfig output
    let output = tokio::process::Command::new("ifconfig")
        .arg(&wan_iface)
        .output()
        .await
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    // Parse "inet X.X.X.X" from ifconfig output
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("inet ")
            && let Some(ip) = rest.split_whitespace().next()
        {
            return Some(ip.to_string());
        }
    }
    None
}

pub async fn get_peer_config(
    State(state): State<AppState>,
    Path((tid, pid)): Path<(String, String)>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let tunnel_id = Uuid::parse_str(&tid).map_err(|_| bad_request())?;
    let peer_id = Uuid::parse_str(&pid).map_err(|_| bad_request())?;
    let tunnel = state
        .vpn_engine
        .get_wg_tunnel(tunnel_id)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let peer = state
        .vpn_engine
        .get_wg_peer(peer_id)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    // Use the WAN IP as the server endpoint (not the tunnel's internal VPN address)
    let server_endpoint = get_wan_ip(&state).await.unwrap_or_else(|| {
        // Fallback: strip CIDR from tunnel address
        let addr = tunnel.address.to_string();
        addr.split('/').next().unwrap_or(&addr).to_string()
    });
    let full_tunnel = peer.to_client_config(&tunnel, &server_endpoint, false);
    let split_tunnel = peer.to_client_config(&tunnel, &server_endpoint, true);
    Ok(Json(serde_json::json!({
        "full_tunnel": full_tunnel,
        "split_tunnel": split_tunnel,
    })))
}

pub async fn delete_wg_peer(
    State(state): State<AppState>,
    Path((_tid, pid)): Path<(String, String)>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&pid).map_err(|_| bad_request())?;
    state
        .vpn_engine
        .delete_wg_peer(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(MessageResponse {
        message: format!("WG peer {pid} deleted"),
    }))
}

// --- VPN: IPsec ---

#[allow(dead_code)] // retained as the documented request shape while creation is disabled
#[derive(Debug, Deserialize)]
pub struct CreateIpsecSaRequest {
    pub name: String,
    pub local_addr: String,
    pub remote_addr: String,
    pub protocol: String,
    pub mode: String,
}

pub async fn list_ipsec_sas(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<IpsecSa>>>, StatusCode> {
    let sas = state
        .vpn_engine
        .list_ipsec_sas()
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: sas }))
}

pub async fn create_ipsec_sa(
    State(_state): State<AppState>,
    Json(_req): Json<CreateIpsecSaRequest>,
) -> Result<(StatusCode, Json<ApiResponse<IpsecSa>>), StatusCode> {
    // Preserve existing rows for migration, but do not create records that
    // look active when no IKE or kernel SA/SP backend exists.
    Err(StatusCode::NOT_IMPLEMENTED)
}

pub async fn delete_ipsec_sa(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    state
        .vpn_engine
        .delete_ipsec_sa(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(MessageResponse {
        message: format!("IPsec SA {id} deleted"),
    }))
}
