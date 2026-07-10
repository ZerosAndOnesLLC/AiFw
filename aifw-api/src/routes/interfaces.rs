//! Network interface enumeration, per-interface counters, and the
//! read-only system routing table (`netstat -rn`).

use super::*;

#[derive(Debug, Serialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub status: String,
    pub mac: Option<String>,
    pub role: Option<String>,
}

pub async fn get_system_routes(
    axum::extract::Query(q): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<ApiResponse<Vec<SystemRoute>>>, StatusCode> {
    // Optional ?fib=N filter — defaults to main FIB. `netstat -rn -F N` shows
    // only the given FIB; without -F you get FIB 0.
    let fib: u32 = q.get("fib").and_then(|v| v.parse().ok()).unwrap_or(0);
    let fib_s = fib.to_string();
    let mut args: Vec<&str> = vec!["-rn", "-f", "inet"];
    if fib > 0 {
        args.push("-F");
        args.push(&fib_s);
    }
    let output = tokio::process::Command::new("netstat")
        .args(&args)
        .output()
        .await
        .map_err(|_| internal())?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let routes: Vec<SystemRoute> = stdout
        .lines()
        .skip_while(|l| !l.contains("Destination"))
        .skip(1)
        .filter(|l| !l.is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                Some(SystemRoute {
                    destination: parts[0].to_string(),
                    gateway: parts[1].to_string(),
                    flags: parts[2].to_string(),
                    interface: parts.last().unwrap_or(&"").to_string(),
                })
            } else {
                None
            }
        })
        .collect();
    Ok(Json(ApiResponse { data: routes }))
}

// --- Network interfaces ---

pub async fn list_interfaces(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<InterfaceInfo>>>, StatusCode> {
    let output = tokio::process::Command::new("ifconfig")
        .output()
        .await
        .map_err(|_| internal())?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut interfaces = Vec::new();
    let mut current: Option<InterfaceInfo> = None;

    for line in stdout.lines() {
        if !line.starts_with('\t') && !line.starts_with(' ') && line.contains(':') {
            if let Some(iface) = current.take() {
                interfaces.push(iface);
            }
            let name = line.split(':').next().unwrap_or("").to_string();
            let status = if line.contains("UP") { "up" } else { "down" };
            current = Some(InterfaceInfo {
                name,
                ipv4: None,
                ipv6: None,
                status: status.to_string(),
                mac: None,
                role: None,
            });
        }
        if let Some(ref mut iface) = current {
            let trimmed = line.trim();
            if trimmed.starts_with("inet ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    iface.ipv4 = Some(parts[1].to_string());
                }
            }
            if trimmed.starts_with("inet6 ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    iface.ipv6 = Some(parts[1].to_string());
                }
            }
            if trimmed.starts_with("ether ") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    iface.mac = Some(parts[1].to_string());
                }
            }
        }
    }
    if let Some(iface) = current {
        interfaces.push(iface);
    }

    // Filter out pseudo-interfaces
    interfaces.retain(|i| {
        !i.name.starts_with("lo")
            && !i.name.starts_with("pflog")
            && !i.name.starts_with("enc")
            && !i.name.starts_with("pfsync")
    });

    // Add VLANs from DB that aren't already in the system interface list
    if let Ok(vlans) = sqlx::query_as::<_, (i64, String, bool)>(
        "SELECT vlan_id, parent, enabled FROM vlans WHERE enabled = 1",
    )
    .fetch_all(&state.pool)
    .await
    {
        for (vid, _parent, _enabled) in vlans {
            let vlan_name = format!("vlan{}", vid);
            if !interfaces.iter().any(|i| i.name == vlan_name) {
                interfaces.push(InterfaceInfo {
                    name: vlan_name,
                    ipv4: None,
                    ipv6: None,
                    status: "down".to_string(),
                    mac: None,
                    role: None,
                });
            }
        }
    }

    // Enrich with roles from DB
    let roles =
        sqlx::query_as::<_, (String, String)>("SELECT interface_name, role FROM interface_roles")
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default();
    let role_map: std::collections::HashMap<String, String> = roles.into_iter().collect();
    for iface in &mut interfaces {
        iface.role = role_map.get(&iface.name).cloned();
    }

    Ok(Json(ApiResponse { data: interfaces }))
}

// --- Per-interface stats ---

#[derive(Debug, Serialize)]
pub struct InterfaceStatsResponse {
    pub name: String,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub packets_in: u64,
    pub packets_out: u64,
    pub errors_in: u64,
    pub errors_out: u64,
}

pub async fn get_interface_stats(
    Path(name): Path<String>,
) -> Result<Json<ApiResponse<InterfaceStatsResponse>>, StatusCode> {
    // Use netstat -I <iface> -b to get byte counters
    let output = tokio::process::Command::new("netstat")
        .args(["-I", &name, "-b", "-n"])
        .output()
        .await
        .map_err(|_| internal())?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut stats = InterfaceStatsResponse {
        name: name.clone(),
        bytes_in: 0,
        bytes_out: 0,
        packets_in: 0,
        packets_out: 0,
        errors_in: 0,
        errors_out: 0,
    };

    // Parse netstat -I output: Name Mtu Network Address Ipkts Ierrs Ibytes Opkts Oerrs Obytes Coll
    for line in stdout.lines().skip(1) {
        let parts: Vec<&str> = line.split_whitespace().collect();
        // Format: Name Mtu Network Address Ipkts Ierrs Idrop Ibytes Opkts Oerrs Obytes Coll
        // Index:  0    1   2       3       4     5     6     7      8     9     10     11
        if parts.len() >= 11 && parts[0] == name {
            stats.packets_in = parts[4].parse().unwrap_or(0);
            stats.errors_in = parts[5].parse().unwrap_or(0);
            stats.bytes_in = parts[7].parse().unwrap_or(0);
            stats.packets_out = parts[8].parse().unwrap_or(0);
            stats.errors_out = parts[9].parse().unwrap_or(0);
            stats.bytes_out = parts[10].parse().unwrap_or(0);
            break;
        }
    }

    Ok(Json(ApiResponse { data: stats }))
}
