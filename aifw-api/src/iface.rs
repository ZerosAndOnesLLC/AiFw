use axum::{extract::{Path, State}, http::StatusCode, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use tokio::process::Command;

use crate::AppState;

// ============================================================
// Types
// ============================================================

#[derive(Debug, Serialize, Clone)]
pub struct InterfaceDetail {
    pub name: String,
    pub mac: Option<String>,
    pub ipv4: Option<String>,
    pub ipv4_netmask: Option<String>,
    pub ipv6: Option<String>,
    pub status: String,
    pub mtu: u32,
    pub media: Option<String>,
    pub description: Option<String>,
    pub is_vlan: bool,
    pub vlan_id: Option<u16>,
    pub vlan_parent: Option<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub errors_in: u64,
    pub errors_out: u64,
    pub gateway: Option<String>,
    pub ipv4_mode: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ConfigureInterfaceRequest {
    pub ipv4_mode: Option<String>,     // "dhcp" | "static" | "none"
    pub ipv4_address: Option<String>,  // e.g. "192.168.1.1/24"
    pub gateway: Option<String>,       // e.g. "192.168.1.254"
    pub ipv6_address: Option<String>,
    pub mtu: Option<u32>,
    pub enabled: Option<bool>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VlanConfig {
    pub id: String,
    pub vlan_id: u16,
    pub parent: String,
    pub ipv4_mode: String,
    pub ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
    pub mtu: u32,
    pub enabled: bool,
    pub description: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateVlanRequest {
    pub vlan_id: u16,
    pub parent: String,
    pub ipv4_mode: Option<String>,
    pub ipv4_address: Option<String>,
    pub ipv6_address: Option<String>,
    pub mtu: Option<u32>,
    pub enabled: Option<bool>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> { pub data: T }
#[derive(Debug, Serialize)]
pub struct MessageResponse { pub message: String }

fn internal() -> StatusCode { StatusCode::INTERNAL_SERVER_ERROR }
fn bad_request() -> StatusCode { StatusCode::BAD_REQUEST }

// ============================================================
// DB
// ============================================================

pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS vlans (
            id TEXT PRIMARY KEY,
            vlan_id INTEGER NOT NULL,
            parent TEXT NOT NULL,
            ipv4_mode TEXT NOT NULL DEFAULT 'none',
            ipv4_address TEXT,
            ipv6_address TEXT,
            mtu INTEGER NOT NULL DEFAULT 1500,
            enabled INTEGER NOT NULL DEFAULT 1,
            description TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(vlan_id, parent)
        )
    "#).execute(pool).await?;
    Ok(())
}

// ============================================================
// Helpers
// ============================================================

/// Get the current default gateway and its interface from the routing table
async fn get_default_gateway() -> (Option<String>, Option<String>) {
    let output = match Command::new("route").args(["-n", "get", "default"]).output().await {
        Ok(o) if o.status.success() => o,
        _ => return (None, None),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut gw = None;
    let mut iface = None;
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("gateway:") {
            gw = trimmed.strip_prefix("gateway:").map(|s| s.trim().to_string());
        }
        if trimmed.starts_with("interface:") {
            iface = trimmed.strip_prefix("interface:").map(|s| s.trim().to_string());
        }
    }
    (gw, iface)
}

/// Get the persisted IPv4 mode for an interface from rc.conf
async fn get_rc_ipv4_mode(name: &str) -> Option<String> {
    let output = Command::new("sysrc").args(["-n", &format!("ifconfig_{}", name)]).output().await.ok()?;
    if !output.status.success() { return None; }
    let val = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if val.eq_ignore_ascii_case("dhcp") {
        Some("dhcp".to_string())
    } else if val.starts_with("inet ") {
        Some("static".to_string())
    } else if val.is_empty() {
        None
    } else {
        Some("static".to_string())
    }
}

async fn parse_ifconfig() -> Vec<InterfaceDetail> {
    let output = Command::new("ifconfig").arg("-a").output().await
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let (gateway, gateway_iface) = get_default_gateway().await;

    let mut interfaces = Vec::new();
    let mut current: Option<InterfaceDetail> = None;

    for line in output.lines() {
        if !line.starts_with('\t') && !line.starts_with(' ') && line.contains(':') {
            if let Some(iface) = current.take() {
                interfaces.push(iface);
            }
            let name = line.split(':').next().unwrap_or("").to_string();
            let flags = line.to_string();
            let status = if flags.contains("UP") { "up" } else { "down" };
            let mtu_val = flags.split("mtu ").nth(1).and_then(|s| s.split_whitespace().next())
                .and_then(|s| s.parse().ok()).unwrap_or(1500);

            let is_vlan = name.starts_with("vlan");
            current = Some(InterfaceDetail {
                name, mac: None, ipv4: None, ipv4_netmask: None, ipv6: None,
                status: status.to_string(), mtu: mtu_val, media: None, description: None,
                is_vlan, vlan_id: None, vlan_parent: None,
                bytes_in: 0, bytes_out: 0, packets_in: 0, packets_out: 0, errors_in: 0, errors_out: 0,
                gateway: None, ipv4_mode: None,
            });
        }
        if let Some(ref mut iface) = current {
            let trimmed = line.trim();
            if trimmed.starts_with("inet ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 { iface.ipv4 = Some(parts[1].to_string()); }
                if let Some(idx) = parts.iter().position(|&p| p == "netmask") {
                    if let Some(nm) = parts.get(idx + 1) { iface.ipv4_netmask = Some(nm.to_string()); }
                }
            }
            if trimmed.starts_with("inet6 ") && !trimmed.contains("scopeid") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 { iface.ipv6 = Some(parts[1].to_string()); }
            }
            if trimmed.starts_with("ether ") {
                iface.mac = Some(trimmed.split_whitespace().nth(1).unwrap_or("").to_string());
            }
            if trimmed.starts_with("media: ") {
                iface.media = Some(trimmed.strip_prefix("media: ").unwrap_or("").to_string());
            }
            if trimmed.starts_with("description: ") {
                iface.description = Some(trimmed.strip_prefix("description: ").unwrap_or("").to_string());
            }
            if trimmed.starts_with("vlan: ") {
                let vid = trimmed.split("vlan: ").nth(1).and_then(|s| s.split_whitespace().next())
                    .and_then(|s| s.parse().ok());
                iface.vlan_id = vid;
                if let Some(parent) = trimmed.split("parent interface: ").nth(1) {
                    iface.vlan_parent = Some(parent.trim().to_string());
                }
            }
        }
    }
    if let Some(iface) = current { interfaces.push(iface); }

    // Get traffic stats via netstat
    let stats_out = Command::new("netstat").args(["-I", "", "-b", "-n", "--libxo", "json"]).output().await;
    for iface in &mut interfaces {
        if let Ok(output) = Command::new("netstat").args(["-I", &iface.name, "-b", "-n"]).output().await {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 11 && parts[0] == iface.name {
                    iface.packets_in = parts[4].parse().unwrap_or(0);
                    iface.bytes_in = parts[7].parse().unwrap_or(0);
                    iface.packets_out = parts[8].parse().unwrap_or(0);
                    iface.bytes_out = parts[10].parse().unwrap_or(0);
                    iface.errors_in = parts[5].parse().unwrap_or(0);
                    iface.errors_out = parts[9].parse().unwrap_or(0);
                    break;
                }
            }
        }
    }

    // Enrich with persisted mode and gateway
    for iface in &mut interfaces {
        iface.ipv4_mode = get_rc_ipv4_mode(&iface.name).await;
        // Only show gateway on the interface that actually routes default traffic
        if gateway_iface.as_deref() == Some(&iface.name) {
            iface.gateway = gateway.clone();
        }
    }

    // Filter out pseudo interfaces
    interfaces.retain(|i| !i.name.starts_with("pflog") && !i.name.starts_with("pfsync") && !i.name.starts_with("enc"));
    let _ = stats_out;
    interfaces
}

// ============================================================
// Handlers
// ============================================================

pub async fn list_interfaces_detailed() -> Result<Json<ApiResponse<Vec<InterfaceDetail>>>, StatusCode> {
    let interfaces = parse_ifconfig().await;
    Ok(Json(ApiResponse { data: interfaces }))
}

pub async fn configure_interface(
    Path(name): Path<String>,
    Json(req): Json<ConfigureInterfaceRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    // Validate inputs before applying anything
    if let Some(ref mode) = req.ipv4_mode {
        if !["dhcp", "static", "none"].contains(&mode.as_str()) {
            return Ok(Json(MessageResponse { message: "Invalid IPv4 mode. Must be dhcp, static, or none.".to_string() }));
        }
        if mode == "static" {
            if let Some(ref addr) = req.ipv4_address {
                if let Err(e) = validate_cidr(addr) {
                    return Ok(Json(MessageResponse { message: e }));
                }
            } else {
                return Ok(Json(MessageResponse { message: "Static mode requires an IPv4 address (e.g. 192.168.1.1/24).".to_string() }));
            }
        }
    }
    if let Some(ref gw) = req.gateway {
        if !gw.is_empty() {
            if let Err(e) = validate_ip(gw) {
                return Ok(Json(MessageResponse { message: format!("Invalid gateway: {}", e) }));
            }
        }
    }
    if let Some(ref ipv6) = req.ipv6_address {
        if !ipv6.is_empty() && !ipv6.contains(':') {
            return Ok(Json(MessageResponse { message: "Invalid IPv6 address.".to_string() }));
        }
    }
    if let Some(mtu) = req.mtu {
        if mtu < 68 || mtu > 9000 {
            return Ok(Json(MessageResponse { message: "MTU must be between 68 and 9000.".to_string() }));
        }
    }

    let mut msgs = Vec::new();

    // Handle enable/disable
    if let Some(enabled) = req.enabled {
        if enabled {
            let _ = run_cmd(&format!("sudo /sbin/ifconfig {} up", name)).await;
        } else {
            let _ = run_cmd(&format!("sudo /sbin/ifconfig {} down", name)).await;
        }
    }

    // Handle MTU
    if let Some(mtu) = req.mtu {
        let _ = run_cmd(&format!("sudo /sbin/ifconfig {} mtu {}", name, mtu)).await;
    }

    // Handle IPv4 mode change
    if let Some(ref mode) = req.ipv4_mode {
        match mode.as_str() {
            "dhcp" => {
                // Kill any existing dhclient, remove static address, then start dhclient
                let _ = run_cmd(&format!("sudo pkill -f 'dhclient.*{}'", name)).await;
                let _ = run_cmd(&format!("sudo /sbin/ifconfig {} delete 2>/dev/null || true", name)).await;
                let _ = run_cmd(&format!("sudo /sbin/dhclient {}", name)).await;
                // Persist
                let _ = Command::new("sudo").args(["/usr/sbin/sysrc", &format!("ifconfig_{}=DHCP", name)]).output().await;
                // Remove static defaultrouter if we're switching to DHCP (DHCP will set it)
                msgs.push("Set to DHCP".to_string());
            }
            "static" => {
                // Kill dhclient first so it doesn't overwrite our static IP
                let _ = run_cmd(&format!("sudo pkill -f 'dhclient.*{}'", name)).await;
                // Brief pause for dhclient to fully exit
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;

                if let Some(ref addr) = req.ipv4_address {
                    // Remove ALL existing IPv4 addresses from the interface first
                    // FreeBSD ifconfig won't replace — it adds aliases. Must delete first.
                    let current = get_iface_ipv4s(&name).await;
                    for old_ip in &current {
                        let _ = Command::new("sudo").args(["/sbin/ifconfig", &name, "inet", old_ip, "-alias"]).output().await;
                    }
                    // Set the new static IP
                    let _ = Command::new("sudo").args(["/sbin/ifconfig", &name, "inet", addr]).output().await;
                    let _ = Command::new("sudo").args(["/sbin/ifconfig", &name, "up"]).output().await;

                    // Persist in rc.conf
                    let _ = Command::new("sudo").args(["/usr/sbin/sysrc", &format!("ifconfig_{}=inet {}", name, addr)]).output().await;
                    msgs.push(format!("Set static IP {}", addr));
                }

                // Handle gateway — only modify the default route if this interface
                // currently owns it (or no default route exists).  Configuring a
                // LAN interface must never clobber the WAN's default gateway.
                if let Some(ref gw) = req.gateway {
                    if !gw.is_empty() {
                        let (_, cur_gw_iface) = get_default_gateway().await;
                        let owns_default = cur_gw_iface.as_deref() == Some(&name)
                            || cur_gw_iface.is_none();
                        if owns_default {
                            let _ = run_cmd("sudo route delete default 2>/dev/null || true").await;
                            let _ = run_cmd(&format!("sudo route add default {}", gw)).await;
                            let _ = Command::new("sudo").args(["/usr/sbin/sysrc", &format!("defaultrouter={}", gw)]).output().await;
                            msgs.push(format!("Gateway set to {}", gw));
                        } else {
                            msgs.push(format!("Gateway {} noted (default route stays on {})",
                                gw, cur_gw_iface.as_deref().unwrap_or("unknown")));
                        }
                    }
                    // Blank gateway on a non-default-route interface is a no-op.
                    // Only remove the default route if this interface currently owns it.
                    else {
                        let (_, cur_gw_iface) = get_default_gateway().await;
                        if cur_gw_iface.as_deref() == Some(&name) {
                            let _ = run_cmd("sudo route delete default 2>/dev/null || true").await;
                            let _ = Command::new("sudo").args(["/usr/sbin/sysrc", "-x", "defaultrouter"]).output().await;
                            msgs.push("Default gateway removed".to_string());
                        }
                    }
                }
            }
            "none" => {
                let _ = run_cmd(&format!("sudo pkill -f 'dhclient.*{}'", name)).await;
                let _ = run_cmd(&format!("sudo /sbin/ifconfig {} delete 2>/dev/null || true", name)).await;
                let _ = Command::new("sudo").args(["/usr/sbin/sysrc", "-x", &format!("ifconfig_{}", name)]).output().await;
                msgs.push("Removed IP configuration".to_string());
            }
            _ => {}
        }
    } else if let Some(ref gw) = req.gateway {
        // Gateway update without mode change — same guard: only touch
        // the default route if this interface currently owns it.
        let (_, cur_gw_iface) = get_default_gateway().await;
        if !gw.is_empty() {
            let owns_default = cur_gw_iface.as_deref() == Some(&name)
                || cur_gw_iface.is_none();
            if owns_default {
                let _ = run_cmd("sudo route delete default 2>/dev/null || true").await;
                let _ = run_cmd(&format!("sudo route add default {}", gw)).await;
                let _ = Command::new("sudo").args(["/usr/sbin/sysrc", &format!("defaultrouter={}", gw)]).output().await;
                msgs.push(format!("Gateway set to {}", gw));
            } else {
                msgs.push(format!("Gateway {} noted (default route stays on {})",
                    gw, cur_gw_iface.as_deref().unwrap_or("unknown")));
            }
        } else if cur_gw_iface.as_deref() == Some(&name) {
            let _ = run_cmd("sudo route delete default 2>/dev/null || true").await;
            let _ = Command::new("sudo").args(["/usr/sbin/sysrc", "-x", "defaultrouter"]).output().await;
            msgs.push("Default gateway removed".to_string());
        }
    }

    if let Some(ref ipv6) = req.ipv6_address {
        if !ipv6.is_empty() {
            let _ = run_cmd(&format!("sudo /sbin/ifconfig {} inet6 {}", name, ipv6)).await;
        }
    }

    if let Some(ref desc) = req.description {
        let _ = run_cmd(&format!("sudo /sbin/ifconfig {} description \"{}\"", name, desc)).await;
    }

    let summary = if msgs.is_empty() {
        format!("Interface {} configured", name)
    } else {
        format!("Interface {} configured: {}", name, msgs.join(", "))
    };

    Ok(Json(MessageResponse { message: summary }))
}

/// Validate an IPv4 address in CIDR notation (e.g. "192.168.1.1/24")
fn validate_cidr(addr: &str) -> Result<(), String> {
    let parts: Vec<&str> = addr.splitn(2, '/').collect();
    if parts.len() != 2 {
        return Err("Address must include a prefix length (e.g. 192.168.1.1/24).".to_string());
    }
    let ip_str = parts[0];
    let prefix_str = parts[1];

    // Validate IP part
    validate_ip(ip_str)?;

    // Validate prefix
    let prefix: u8 = prefix_str.parse().map_err(|_| "Invalid prefix length.".to_string())?;
    if prefix > 32 {
        return Err("Prefix length must be between 0 and 32.".to_string());
    }

    Ok(())
}

/// Validate a plain IPv4 address (no prefix)
fn validate_ip(ip: &str) -> Result<(), String> {
    let octets: Vec<&str> = ip.split('.').collect();
    if octets.len() != 4 {
        return Err("Must be a valid IPv4 address (e.g. 192.168.1.1).".to_string());
    }
    for (i, octet) in octets.iter().enumerate() {
        let val: u16 = octet.parse().map_err(|_| format!("Invalid octet '{}' in address.", octet))?;
        if val > 255 {
            return Err(format!("Octet {} ({}) is out of range (0-255).", i + 1, val));
        }
    }
    Ok(())
}

/// Get all current IPv4 addresses on an interface
async fn get_iface_ipv4s(name: &str) -> Vec<String> {
    let output = Command::new("/sbin/ifconfig").arg(name).output().await;
    let stdout = match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).to_string(),
        _ => return vec![],
    };
    stdout.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("inet ") {
                trimmed.split_whitespace().nth(1).map(String::from)
            } else {
                None
            }
        })
        .collect()
}

/// Run a shell command and return success/failure
async fn run_cmd(cmd: &str) -> bool {
    Command::new("sh").arg("-c").arg(cmd).output().await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

// --- VLANs ---

pub async fn list_vlans(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<VlanConfig>>>, StatusCode> {
    let rows = sqlx::query_as::<_, (String,i64,String,String,Option<String>,Option<String>,i64,bool,Option<String>,String)>(
        "SELECT id, vlan_id, parent, ipv4_mode, ipv4_address, ipv6_address, mtu, enabled, description, created_at FROM vlans ORDER BY vlan_id ASC"
    ).fetch_all(&state.pool).await.map_err(|_| internal())?;
    let vlans: Vec<VlanConfig> = rows.into_iter().map(|(id,vid,parent,mode,ip4,ip6,mtu,en,desc,ca)| VlanConfig {
        id, vlan_id: vid as u16, parent, ipv4_mode: mode, ipv4_address: ip4,
        ipv6_address: ip6, mtu: mtu as u32, enabled: en, description: desc, created_at: ca,
    }).collect();
    Ok(Json(ApiResponse { data: vlans }))
}

pub async fn create_vlan(
    State(state): State<AppState>,
    Json(req): Json<CreateVlanRequest>,
) -> Result<(StatusCode, Json<ApiResponse<VlanConfig>>), StatusCode> {
    if req.vlan_id < 1 || req.vlan_id > 4094 { return Err(bad_request()); }

    let id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let mode = req.ipv4_mode.unwrap_or_else(|| "none".to_string());
    let mtu = req.mtu.unwrap_or(1500);
    let enabled = req.enabled.unwrap_or(true);
    let vlan_name = format!("vlan{}", req.vlan_id);

    sqlx::query("INSERT INTO vlans (id, vlan_id, parent, ipv4_mode, ipv4_address, ipv6_address, mtu, enabled, description, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)")
        .bind(&id).bind(req.vlan_id as i64).bind(&req.parent).bind(&mode)
        .bind(req.ipv4_address.as_deref()).bind(req.ipv6_address.as_deref())
        .bind(mtu as i64).bind(enabled).bind(req.description.as_deref()).bind(&now)
        .execute(&state.pool).await.map_err(|_| bad_request())?;

    // Create the VLAN interface
    if enabled {
        let _ = Command::new("sudo").args(["/sbin/ifconfig", &vlan_name, "create"]).output().await;
        let _ = Command::new("sudo").args(["/sbin/ifconfig", &vlan_name, "vlan", &req.vlan_id.to_string(), "vlandev", &req.parent]).output().await;
        let _ = Command::new("sudo").args(["/sbin/ifconfig", &vlan_name, "mtu", &mtu.to_string()]).output().await;

        if mode == "static" {
            if let Some(ref addr) = req.ipv4_address {
                let _ = Command::new("sudo").args(["/sbin/ifconfig", &vlan_name, "inet", addr]).output().await;
            }
        } else if mode == "dhcp" {
            let _ = Command::new("sudo").args(["/sbin/dhclient", &vlan_name]).output().await;
        }
        let _ = Command::new("sudo").args(["/sbin/ifconfig", &vlan_name, "up"]).output().await;

        // Persist in rc.conf
        let _ = Command::new("sudo").args(["/usr/sbin/sysrc", &format!("vlans_{}={}", req.parent, req.vlan_id)]).output().await;
        let rc_val = match mode.as_str() {
            "dhcp" => "DHCP".to_string(),
            "static" => format!("inet {}", req.ipv4_address.as_deref().unwrap_or("")),
            _ => "up".to_string(),
        };
        let _ = Command::new("sudo").args(["/usr/sbin/sysrc", &format!("ifconfig_{}={}", vlan_name, rc_val)]).output().await;
    }

    let vlan = VlanConfig { id, vlan_id: req.vlan_id, parent: req.parent, ipv4_mode: mode,
        ipv4_address: req.ipv4_address, ipv6_address: req.ipv6_address, mtu, enabled,
        description: req.description, created_at: now };
    Ok((StatusCode::CREATED, Json(ApiResponse { data: vlan })))
}

pub async fn delete_vlan(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let row = sqlx::query_as::<_, (i64,)>("SELECT vlan_id FROM vlans WHERE id = ?1")
        .bind(&id).fetch_optional(&state.pool).await.map_err(|_| internal())?
        .ok_or(StatusCode::NOT_FOUND)?;
    let vlan_name = format!("vlan{}", row.0);

    let _ = Command::new("sudo").args(["/sbin/ifconfig", &vlan_name, "destroy"]).output().await;
    let _ = Command::new("sudo").args(["/usr/sbin/sysrc", "-x", &format!("ifconfig_{}", vlan_name)]).output().await;

    sqlx::query("DELETE FROM vlans WHERE id = ?1").bind(&id).execute(&state.pool).await.map_err(|_| internal())?;
    Ok(Json(MessageResponse { message: format!("VLAN {} deleted", vlan_name) }))
}

pub async fn update_vlan(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateVlanRequest>,
) -> Result<Json<ApiResponse<VlanConfig>>, StatusCode> {
    let mode = req.ipv4_mode.unwrap_or_else(|| "none".to_string());
    let mtu = req.mtu.unwrap_or(1500);
    let enabled = req.enabled.unwrap_or(true);

    let result = sqlx::query("UPDATE vlans SET vlan_id=?2, parent=?3, ipv4_mode=?4, ipv4_address=?5, ipv6_address=?6, mtu=?7, enabled=?8, description=?9 WHERE id=?1")
        .bind(&id).bind(req.vlan_id as i64).bind(&req.parent).bind(&mode)
        .bind(req.ipv4_address.as_deref()).bind(req.ipv6_address.as_deref())
        .bind(mtu as i64).bind(enabled).bind(req.description.as_deref())
        .execute(&state.pool).await.map_err(|_| internal())?;
    if result.rows_affected() == 0 { return Err(StatusCode::NOT_FOUND); }

    let vlan_name = format!("vlan{}", req.vlan_id);

    if enabled {
        let _ = Command::new("sudo").args(["/sbin/ifconfig", &vlan_name, "mtu", &mtu.to_string()]).output().await;
        if mode == "static" {
            if let Some(ref addr) = req.ipv4_address {
                let _ = Command::new("sudo").args(["/sbin/ifconfig", &vlan_name, "inet", addr]).output().await;
            }
        }
        let _ = Command::new("sudo").args(["/sbin/ifconfig", &vlan_name, "up"]).output().await;
    } else {
        let _ = Command::new("sudo").args(["/sbin/ifconfig", &vlan_name, "down"]).output().await;
    }

    let now = Utc::now().to_rfc3339();
    Ok(Json(ApiResponse { data: VlanConfig { id, vlan_id: req.vlan_id, parent: req.parent, ipv4_mode: mode,
        ipv4_address: req.ipv4_address, ipv6_address: req.ipv6_address, mtu, enabled,
        description: req.description, created_at: now } }))
}
