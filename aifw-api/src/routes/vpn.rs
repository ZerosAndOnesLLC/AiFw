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
    let mut tunnel = WgTunnel::new(req.name, Interface(iface_name), req.listen_port, address)
        .map_err(|_| internal())?;
    if let Some(ref pk) = req.private_key {
        // Re-derive the public key so the stored pair is always related (#541)
        tunnel.public_key = aifw_common::vpn::derive_wg_pubkey(pk).map_err(|_| bad_request())?;
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
        WgPeer::new_with_generated_key(tid, req.name.unwrap_or_default()).map_err(|_| internal())?
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

// --- VPN: IPsec (legacy ipsec_sas records — read/delete only, #530) ---

/// Legacy SA record plus an explicit legacy marker so no client can
/// mistake these configuration-only rows for live tunnels.
#[derive(Debug, Serialize)]
pub struct LegacyIpsecSa {
    #[serde(flatten)]
    pub sa: IpsecSa,
    /// Always true: this record predates the real data plane and
    /// carries no traffic.
    pub legacy: bool,
}

pub async fn list_ipsec_sas(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<LegacyIpsecSa>>>, StatusCode> {
    let sas = state
        .vpn_engine
        .list_ipsec_sas()
        .await
        .map_err(|_| internal())?;
    let sas = sas
        .into_iter()
        .map(|sa| LegacyIpsecSa { sa, legacy: true })
        .collect();
    Ok(Json(ApiResponse { data: sas }))
}

/// POST /vpn/ipsec is gone (#530): the pre-data-plane SA records could
/// never carry traffic, so creating more of them is not allowed. Point
/// callers at the tunnel API.
pub async fn create_ipsec_sa_gone() -> (StatusCode, Json<MessageResponse>) {
    (
        StatusCode::GONE,
        Json(MessageResponse {
            message: "legacy IPsec SA records are read-only; use /api/v1/vpn/ipsec/tunnels"
                .to_string(),
        }),
    )
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

// --- VPN: IPsec tunnels (real data plane, #530) ---

type IpsecError = (StatusCode, Json<MessageResponse>);

/// Map engine errors to a status + message so validation problems and
/// charon's negotiation/load diagnostics reach the caller instead of a
/// bare 500.
fn ipsec_err(e: aifw_common::AifwError) -> IpsecError {
    use aifw_common::AifwError;
    let status = match &e {
        AifwError::Validation(_) => StatusCode::BAD_REQUEST,
        AifwError::NotFound(_) => StatusCode::NOT_FOUND,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (
        status,
        Json(MessageResponse {
            message: e.to_string(),
        }),
    )
}

fn ipsec_bad_request(msg: &str) -> IpsecError {
    (
        StatusCode::BAD_REQUEST,
        Json(MessageResponse {
            message: msg.to_string(),
        }),
    )
}

/// Create/update payload. Omitted optional fields keep defaults on
/// create and keep current values on update; `psk`/`local_key_pem`
/// equal to the redaction marker (or omitted) keep the stored secret.
#[derive(Debug, Deserialize)]
pub struct IpsecTunnelRequest {
    pub name: String,
    pub remote_addr: String,
    pub local_ts: Vec<String>,
    pub remote_ts: Vec<String>,
    pub enabled: Option<bool>,
    pub local_addr: Option<String>,
    pub local_id: Option<String>,
    pub remote_id: Option<String>,
    pub auth_method: Option<String>,
    pub psk: Option<String>,
    pub cert_source: Option<String>,
    pub acme_cert_id: Option<i64>,
    pub local_cert_pem: Option<String>,
    pub local_key_pem: Option<String>,
    pub ca_cert_pem: Option<String>,
    pub ike_proposal: Option<String>,
    pub esp_proposal: Option<String>,
    pub ike_lifetime_secs: Option<u32>,
    pub esp_lifetime_secs: Option<u32>,
    pub dpd_delay_secs: Option<u32>,
    pub start_action: Option<String>,
}

/// Fold a request into a tunnel record. Secrets are only overwritten
/// when the request carries a real (non-redacted) value.
fn apply_tunnel_request(
    tunnel: &mut aifw_common::IpsecTunnel,
    req: IpsecTunnelRequest,
) -> Result<(), IpsecError> {
    use aifw_common::{IpsecAuthMethod, IpsecCertSource, IpsecStartAction};

    tunnel.name = req.name;
    tunnel.remote_addr = req.remote_addr;
    tunnel.local_ts = req.local_ts;
    tunnel.remote_ts = req.remote_ts;
    if let Some(enabled) = req.enabled {
        tunnel.enabled = enabled;
    }
    if let Some(v) = req.local_addr {
        tunnel.local_addr = v;
    }
    if let Some(v) = req.local_id {
        tunnel.local_id = v;
    }
    if let Some(v) = req.remote_id {
        tunnel.remote_id = v;
    }
    if let Some(ref v) = req.auth_method {
        tunnel.auth_method = IpsecAuthMethod::parse(v).map_err(ipsec_err)?;
    }
    if let Some(psk) = req.psk
        && psk != "REDACTED"
    {
        tunnel.psk = psk;
    }
    if let Some(ref v) = req.cert_source {
        tunnel.cert_source = if v.is_empty() {
            None
        } else {
            Some(IpsecCertSource::parse(v).map_err(ipsec_err)?)
        };
    }
    if req.acme_cert_id.is_some() {
        tunnel.acme_cert_id = req.acme_cert_id;
    }
    if let Some(v) = req.local_cert_pem {
        tunnel.local_cert_pem = v;
    }
    if let Some(key) = req.local_key_pem
        && key != "REDACTED"
    {
        tunnel.local_key_pem = key;
    }
    if let Some(v) = req.ca_cert_pem {
        tunnel.ca_cert_pem = v;
    }
    if let Some(v) = req.ike_proposal {
        tunnel.ike_proposal = v;
    }
    if let Some(v) = req.esp_proposal {
        tunnel.esp_proposal = v;
    }
    if let Some(v) = req.ike_lifetime_secs {
        tunnel.ike_lifetime_secs = v;
    }
    if let Some(v) = req.esp_lifetime_secs {
        tunnel.esp_lifetime_secs = v;
    }
    if let Some(v) = req.dpd_delay_secs {
        tunnel.dpd_delay_secs = v;
    }
    if let Some(ref v) = req.start_action {
        tunnel.start_action = IpsecStartAction::parse(v).map_err(ipsec_err)?;
    }
    if tunnel.auth_method == IpsecAuthMethod::Cert && tunnel.cert_source.is_none() {
        return Err(ipsec_bad_request("cert auth requires cert_source"));
    }
    Ok(())
}

/// Refresh the pass rules the aifw anchor mirrors from the VPN engines
/// after any IPsec apply (same dance the WG start/stop handlers do).
async fn refresh_vpn_pf(state: &AppState) {
    let _ = state.vpn_engine.apply_vpn_rules().await;
    if let Ok(vpn_rules) = state.vpn_engine.collect_vpn_rules().await {
        state.rule_engine.set_extra_rules(vpn_rules).await;
        let _ = state.rule_engine.apply_rules().await;
    }
}

pub async fn list_ipsec_tunnels(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<aifw_common::IpsecTunnel>>>, StatusCode> {
    let tunnels = state
        .ipsec_engine
        .list_tunnels()
        .await
        .map_err(|_| internal())?;
    let tunnels = tunnels.iter().map(|t| t.redacted()).collect();
    Ok(Json(ApiResponse { data: tunnels }))
}

pub async fn get_ipsec_tunnel(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<aifw_common::IpsecTunnel>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let tunnel = state
        .ipsec_engine
        .get_tunnel(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(ApiResponse {
        data: tunnel.redacted(),
    }))
}

pub async fn create_ipsec_tunnel(
    State(state): State<AppState>,
    Json(req): Json<IpsecTunnelRequest>,
) -> Result<(StatusCode, Json<ApiResponse<aifw_common::IpsecTunnel>>), IpsecError> {
    let mut tunnel = aifw_common::IpsecTunnel::new(
        String::new(),
        String::new(),
        String::new(),
        Vec::new(),
        Vec::new(),
    );
    apply_tunnel_request(&mut tunnel, req)?;
    let tunnel = state
        .ipsec_engine
        .create_tunnel_applied(tunnel)
        .await
        .map_err(ipsec_err)?;
    refresh_vpn_pf(&state).await;
    Ok((
        StatusCode::CREATED,
        Json(ApiResponse {
            data: tunnel.redacted(),
        }),
    ))
}

pub async fn update_ipsec_tunnel(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<IpsecTunnelRequest>,
) -> Result<Json<ApiResponse<aifw_common::IpsecTunnel>>, IpsecError> {
    let uuid = Uuid::parse_str(&id).map_err(|_| ipsec_bad_request("invalid tunnel id"))?;
    let mut tunnel = state
        .ipsec_engine
        .get_tunnel(uuid)
        .await
        .map_err(ipsec_err)?;
    apply_tunnel_request(&mut tunnel, req)?;
    let tunnel = state
        .ipsec_engine
        .update_tunnel_applied(tunnel)
        .await
        .map_err(ipsec_err)?;
    refresh_vpn_pf(&state).await;
    Ok(Json(ApiResponse {
        data: tunnel.redacted(),
    }))
}

pub async fn delete_ipsec_tunnel(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, IpsecError> {
    let uuid = Uuid::parse_str(&id).map_err(|_| ipsec_bad_request("invalid tunnel id"))?;
    state
        .ipsec_engine
        .delete_tunnel_applied(uuid)
        .await
        .map_err(ipsec_err)?;
    refresh_vpn_pf(&state).await;
    Ok(Json(MessageResponse {
        message: format!("IPsec tunnel {id} deleted"),
    }))
}

pub async fn start_ipsec_tunnel(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, IpsecError> {
    let uuid = Uuid::parse_str(&id).map_err(|_| ipsec_bad_request("invalid tunnel id"))?;
    state
        .ipsec_engine
        .start_tunnel(uuid)
        .await
        .map_err(ipsec_err)?;
    Ok(Json(MessageResponse {
        message: "Tunnel initiated".to_string(),
    }))
}

pub async fn stop_ipsec_tunnel(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, IpsecError> {
    let uuid = Uuid::parse_str(&id).map_err(|_| ipsec_bad_request("invalid tunnel id"))?;
    state
        .ipsec_engine
        .stop_tunnel(uuid)
        .await
        .map_err(ipsec_err)?;
    Ok(Json(MessageResponse {
        message: "Tunnel terminated".to_string(),
    }))
}

pub async fn ipsec_tunnel_status(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ApiResponse<aifw_common::IpsecLiveStatus>>, StatusCode> {
    let uuid = Uuid::parse_str(&id).map_err(|_| bad_request())?;
    let status = state
        .ipsec_engine
        .tunnel_status(uuid)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(ApiResponse { data: status }))
}

pub async fn ipsec_status_all(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<aifw_common::IpsecLiveStatus>>>, StatusCode> {
    let statuses = state
        .ipsec_engine
        .live_status()
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: statuses }))
}
