use axum::{extract::{Path, State}, http::StatusCode, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use uuid::Uuid;
use tokio::process::Command;

use crate::AppState;

// ============================================================
// Types
// ============================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DhcpGlobalConfig {
    pub enabled: bool,
    pub interfaces: Vec<String>,
    pub authoritative: bool,
    pub default_lease_time: u32,
    pub max_lease_time: u32,
    pub dns_servers: Vec<String>,
    pub domain_name: String,
    pub domain_search: Vec<String>,  // search domains for Windows/Linux
    pub ntp_servers: Vec<String>,
    pub wins_servers: Vec<String>,
    pub next_server: Option<String>,
    pub boot_filename: Option<String>,
}

impl Default for DhcpGlobalConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interfaces: vec![],
            authoritative: true,
            default_lease_time: 3600,
            max_lease_time: 86400,
            dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            domain_name: "local".to_string(),
            domain_search: vec![],
            ntp_servers: vec![],
            wins_servers: vec![],
            next_server: None,
            boot_filename: None,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DhcpSubnet {
    pub id: String,
    pub network: String,    // e.g. "192.168.1.0/24"
    pub pool_start: String, // e.g. "192.168.1.100"
    pub pool_end: String,   // e.g. "192.168.1.200"
    pub gateway: String,
    pub dns_servers: Option<String>,  // comma-separated override
    pub domain_name: Option<String>,
    pub lease_time: Option<u32>,
    pub enabled: bool,
    pub description: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateSubnetRequest {
    pub network: String,
    pub pool_start: String,
    pub pool_end: String,
    pub gateway: String,
    pub dns_servers: Option<String>,
    pub domain_name: Option<String>,
    pub lease_time: Option<u32>,
    pub enabled: Option<bool>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DhcpReservation {
    pub id: String,
    pub subnet_id: Option<String>,
    pub mac_address: String,
    pub ip_address: String,
    pub hostname: Option<String>,
    pub description: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateReservationRequest {
    pub subnet_id: Option<String>,
    pub mac_address: String,
    pub ip_address: String,
    pub hostname: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DhcpLease {
    pub ip_address: String,
    pub mac_address: String,
    pub hostname: Option<String>,
    pub state: String,
    pub starts: Option<String>,
    pub expires: Option<String>,
    pub subnet_id: Option<u32>,
}

#[derive(Debug, Serialize)]
pub struct DhcpStatus {
    pub running: bool,
    pub version: String,
    pub uptime: Option<String>,
    pub total_subnets: usize,
    pub total_reservations: usize,
    pub active_leases: usize,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> { pub data: T }
#[derive(Debug, Serialize)]
pub struct MessageResponse { pub message: String }

fn bad_request() -> StatusCode { StatusCode::BAD_REQUEST }
fn internal() -> StatusCode { StatusCode::INTERNAL_SERVER_ERROR }

// ============================================================
// DB Migration
// ============================================================

pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS dhcp_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    "#).execute(pool).await?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS dhcp_subnets (
            id TEXT PRIMARY KEY,
            network TEXT NOT NULL,
            pool_start TEXT NOT NULL,
            pool_end TEXT NOT NULL,
            gateway TEXT NOT NULL,
            dns_servers TEXT,
            domain_name TEXT,
            lease_time INTEGER,
            enabled INTEGER NOT NULL DEFAULT 1,
            description TEXT,
            created_at TEXT NOT NULL
        )
    "#).execute(pool).await?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS dhcp_reservations (
            id TEXT PRIMARY KEY,
            subnet_id TEXT,
            mac_address TEXT NOT NULL,
            ip_address TEXT NOT NULL UNIQUE,
            hostname TEXT,
            description TEXT,
            created_at TEXT NOT NULL
        )
    "#).execute(pool).await?;

    Ok(())
}

// ============================================================
// Config helpers
// ============================================================

async fn load_global_config(pool: &SqlitePool) -> DhcpGlobalConfig {
    let rows = sqlx::query_as::<_, (String, String)>("SELECT key, value FROM dhcp_config")
        .fetch_all(pool).await.unwrap_or_default();
    let mut config = DhcpGlobalConfig::default();
    for (key, value) in rows {
        match key.as_str() {
            "enabled" => config.enabled = value == "true",
            "interfaces" => config.interfaces = value.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            "authoritative" => config.authoritative = value == "true",
            "default_lease_time" => config.default_lease_time = value.parse().unwrap_or(3600),
            "max_lease_time" => config.max_lease_time = value.parse().unwrap_or(86400),
            "dns_servers" => config.dns_servers = value.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            "domain_name" => config.domain_name = value,
            "domain_search" => config.domain_search = value.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            "ntp_servers" => config.ntp_servers = value.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            "wins_servers" => config.wins_servers = value.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            "next_server" => config.next_server = if value.is_empty() { None } else { Some(value) },
            "boot_filename" => config.boot_filename = if value.is_empty() { None } else { Some(value) },
            _ => {}
        }
    }
    config
}

async fn save_config_key(pool: &SqlitePool, key: &str, value: &str) {
    let _ = sqlx::query("INSERT OR REPLACE INTO dhcp_config (key, value) VALUES (?1, ?2)")
        .bind(key).bind(value).execute(pool).await;
}

/// Generate Kea DHCPv4 JSON config
async fn generate_kea_config(pool: &SqlitePool) -> String {
    let config = load_global_config(pool).await;
    let subnets = list_subnets_db(pool).await;
    let reservations = list_reservations_db(pool).await;

    let interfaces_json: Vec<String> = config.interfaces.iter().map(|i| format!("\"{}\"", i)).collect();
    let dns_json: Vec<String> = config.dns_servers.iter().map(|d| format!("\"{}\"", d)).collect();

    let mut subnet_entries = Vec::new();
    for subnet in &subnets {
        if !subnet.enabled { continue; }

        let sub_dns = subnet.dns_servers.as_ref()
            .map(|d| d.split(',').map(|s| format!("\"{}\"", s.trim())).collect::<Vec<_>>().join(", "))
            .unwrap_or_else(|| dns_json.join(", "));

        let sub_domain = subnet.domain_name.as_deref().unwrap_or(&config.domain_name);
        let sub_lease = subnet.lease_time.unwrap_or(config.default_lease_time);

        // Host reservations for this subnet
        let subnet_network = &subnet.network;
        let sub_reservations: Vec<String> = reservations.iter()
            .filter(|r| r.subnet_id.as_deref() == Some(&subnet.id))
            .map(|r| {
                let hostname = r.hostname.as_deref().map(|h| format!(", \"hostname\": \"{}\"", h)).unwrap_or_default();
                format!("        {{ \"hw-address\": \"{}\", \"ip-address\": \"{}\"{} }}", r.mac_address, r.ip_address, hostname)
            })
            .collect();

        let reservations_block = if sub_reservations.is_empty() {
            String::new()
        } else {
            format!(",\n      \"reservations\": [\n{}\n      ]", sub_reservations.join(",\n"))
        };

        subnet_entries.push(format!(r#"    {{
      "subnet": "{}",
      "pools": [{{ "pool": "{} - {}" }}],
      "option-data": [
        {{ "name": "routers", "data": "{}" }},
        {{ "name": "domain-name-servers", "data": "{}" }},
        {{ "name": "domain-name", "data": "{}" }}
      ],
      "valid-lifetime": {}{}
    }}"#,
            subnet_network, subnet.pool_start, subnet.pool_end,
            subnet.gateway,
            sub_dns.replace('"', "").replace(", ", ","),
            sub_domain, sub_lease, reservations_block
        ));
    }

    format!(r#"{{
  "Dhcp4": {{
    "interfaces-config": {{
      "interfaces": [{}]
    }},
    "authoritative": {},
    "valid-lifetime": {},
    "max-valid-lifetime": {},
    "option-data": [
      {{ "name": "domain-name-servers", "data": "{}" }},
      {{ "name": "domain-name", "data": "{}" }}{}{}{}
    ],
    "subnet4": [
{}
    ],
    "loggers": [{{
      "name": "kea-dhcp4",
      "output_options": [{{ "output": "/var/log/kea/kea-dhcp4.log" }}],
      "severity": "INFO"
    }}]
  }}
}}"#,
        interfaces_json.join(", "),
        config.authoritative,
        config.default_lease_time,
        config.max_lease_time,
        dns_json.join(",").replace('"', ""),
        config.domain_name,
        // Domain search list
        if config.domain_search.is_empty() { String::new() } else {
            format!(",\n      {{ \"name\": \"domain-search\", \"data\": \"{}\" }}", config.domain_search.join(","))
        },
        // NTP servers
        if config.ntp_servers.is_empty() { String::new() } else {
            format!(",\n      {{ \"code\": 42, \"data\": \"{}\", \"space\": \"dhcp4\" }}", config.ntp_servers.join(","))
        },
        // WINS/NetBIOS name servers
        if config.wins_servers.is_empty() { String::new() } else {
            format!(",\n      {{ \"code\": 44, \"data\": \"{}\", \"space\": \"dhcp4\" }}", config.wins_servers.join(","))
        },
        subnet_entries.join(",\n"),
    )
}

async fn list_subnets_db(pool: &SqlitePool) -> Vec<DhcpSubnet> {
    sqlx::query_as::<_, (String,String,String,String,String,Option<String>,Option<String>,Option<i64>,bool,Option<String>,String)>(
        "SELECT id, network, pool_start, pool_end, gateway, dns_servers, domain_name, lease_time, enabled, description, created_at FROM dhcp_subnets ORDER BY created_at ASC"
    ).fetch_all(pool).await.unwrap_or_default()
    .into_iter().map(|(id,net,ps,pe,gw,dns,dn,lt,en,desc,ca)| DhcpSubnet {
        id, network: net, pool_start: ps, pool_end: pe, gateway: gw,
        dns_servers: dns, domain_name: dn, lease_time: lt.map(|v| v as u32),
        enabled: en, description: desc, created_at: ca,
    }).collect()
}

async fn list_reservations_db(pool: &SqlitePool) -> Vec<DhcpReservation> {
    sqlx::query_as::<_, (String,Option<String>,String,String,Option<String>,Option<String>,String)>(
        "SELECT id, subnet_id, mac_address, ip_address, hostname, description, created_at FROM dhcp_reservations ORDER BY ip_address ASC"
    ).fetch_all(pool).await.unwrap_or_default()
    .into_iter().map(|(id,sid,mac,ip,hn,desc,ca)| DhcpReservation {
        id, subnet_id: sid, mac_address: mac, ip_address: ip, hostname: hn, description: desc, created_at: ca,
    }).collect()
}

// ============================================================
// Handlers
// ============================================================

// --- Status ---

pub async fn dhcp_status(
    State(state): State<AppState>,
) -> Result<Json<DhcpStatus>, StatusCode> {
    let running = Command::new("sudo").args(["/usr/sbin/service", "kea", "status"]).output().await
        .map(|o| {
            let stdout = String::from_utf8_lossy(&o.stdout);
            // Kea status output: "DHCPv4 server: active" or "inactive"
            stdout.contains("active") && !stdout.contains("inactive")
        }).unwrap_or(false);

    let version = Command::new("pkg").args(["query", "%v", "kea"]).output().await
        .map(|o| {
            let v = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if v.is_empty() || !o.status.success() { "not installed".to_string() } else { format!("Kea {}", v) }
        }).unwrap_or_else(|_| "not installed".to_string());

    let subnets = list_subnets_db(&state.pool).await;
    let reservations = list_reservations_db(&state.pool).await;

    // Count leases from Kea lease file
    let lease_count = tokio::fs::read_to_string("/var/db/kea/kea-leases4.csv").await
        .map(|c| c.lines().filter(|l| !l.starts_with('#') && !l.is_empty()).count())
        .unwrap_or(0);

    Ok(Json(DhcpStatus {
        running, version, uptime: None,
        total_subnets: subnets.len(),
        total_reservations: reservations.len(),
        active_leases: lease_count,
    }))
}

// --- Service control ---

async fn run_kea_service(action: &str) -> Json<MessageResponse> {
    let output = Command::new("sudo").args(["/usr/sbin/service", "kea", action])
        .output().await;
    match output {
        Ok(o) => {
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let stderr = String::from_utf8_lossy(&o.stderr).to_string();
            let msg = if o.status.success() {
                format!("DHCP server {}: {}", action, stdout.trim())
            } else {
                format!("DHCP {} failed: {} {}", action, stdout.trim(), stderr.trim())
            };
            Json(MessageResponse { message: msg })
        }
        Err(e) => Json(MessageResponse { message: format!("Failed to {} DHCP: {}", action, e) }),
    }
}

pub async fn dhcp_start() -> Result<Json<MessageResponse>, StatusCode> {
    Ok(run_kea_service("start").await)
}

pub async fn dhcp_stop() -> Result<Json<MessageResponse>, StatusCode> {
    Ok(run_kea_service("stop").await)
}

pub async fn dhcp_restart() -> Result<Json<MessageResponse>, StatusCode> {
    Ok(run_kea_service("restart").await)
}

// --- Global config ---

pub async fn get_config(
    State(state): State<AppState>,
) -> Result<Json<DhcpGlobalConfig>, StatusCode> {
    Ok(Json(load_global_config(&state.pool).await))
}

pub async fn update_config(
    State(state): State<AppState>,
    Json(config): Json<DhcpGlobalConfig>,
) -> Result<Json<MessageResponse>, StatusCode> {
    save_config_key(&state.pool, "enabled", if config.enabled { "true" } else { "false" }).await;
    save_config_key(&state.pool, "interfaces", &config.interfaces.join(",")).await;
    save_config_key(&state.pool, "authoritative", if config.authoritative { "true" } else { "false" }).await;
    save_config_key(&state.pool, "default_lease_time", &config.default_lease_time.to_string()).await;
    save_config_key(&state.pool, "max_lease_time", &config.max_lease_time.to_string()).await;
    save_config_key(&state.pool, "dns_servers", &config.dns_servers.join(",")).await;
    save_config_key(&state.pool, "domain_name", &config.domain_name).await;
    save_config_key(&state.pool, "domain_search", &config.domain_search.join(",")).await;
    save_config_key(&state.pool, "ntp_servers", &config.ntp_servers.join(",")).await;
    save_config_key(&state.pool, "wins_servers", &config.wins_servers.join(",")).await;
    save_config_key(&state.pool, "next_server", config.next_server.as_deref().unwrap_or("")).await;
    save_config_key(&state.pool, "boot_filename", config.boot_filename.as_deref().unwrap_or("")).await;
    Ok(Json(MessageResponse { message: "DHCP config updated".to_string() }))
}

// --- Subnets ---

pub async fn list_subnets(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<DhcpSubnet>>>, StatusCode> {
    Ok(Json(ApiResponse { data: list_subnets_db(&state.pool).await }))
}

pub async fn create_subnet(
    State(state): State<AppState>,
    Json(req): Json<CreateSubnetRequest>,
) -> Result<(StatusCode, Json<ApiResponse<DhcpSubnet>>), StatusCode> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    let enabled = req.enabled.unwrap_or(true);
    sqlx::query("INSERT INTO dhcp_subnets (id, network, pool_start, pool_end, gateway, dns_servers, domain_name, lease_time, enabled, description, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)")
        .bind(&id).bind(&req.network).bind(&req.pool_start).bind(&req.pool_end).bind(&req.gateway)
        .bind(req.dns_servers.as_deref()).bind(req.domain_name.as_deref()).bind(req.lease_time.map(|v| v as i64))
        .bind(enabled).bind(req.description.as_deref()).bind(&now)
        .execute(&state.pool).await.map_err(|_| bad_request())?;
    let subnet = DhcpSubnet { id, network: req.network, pool_start: req.pool_start, pool_end: req.pool_end, gateway: req.gateway, dns_servers: req.dns_servers, domain_name: req.domain_name, lease_time: req.lease_time, enabled, description: req.description, created_at: now };
    Ok((StatusCode::CREATED, Json(ApiResponse { data: subnet })))
}

pub async fn update_subnet(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateSubnetRequest>,
) -> Result<Json<ApiResponse<DhcpSubnet>>, StatusCode> {
    let enabled = req.enabled.unwrap_or(true);
    let result = sqlx::query("UPDATE dhcp_subnets SET network=?2, pool_start=?3, pool_end=?4, gateway=?5, dns_servers=?6, domain_name=?7, lease_time=?8, enabled=?9, description=?10 WHERE id=?1")
        .bind(&id).bind(&req.network).bind(&req.pool_start).bind(&req.pool_end).bind(&req.gateway)
        .bind(req.dns_servers.as_deref()).bind(req.domain_name.as_deref()).bind(req.lease_time.map(|v| v as i64))
        .bind(enabled).bind(req.description.as_deref())
        .execute(&state.pool).await.map_err(|_| internal())?;
    if result.rows_affected() == 0 { return Err(StatusCode::NOT_FOUND); }
    let now = Utc::now().to_rfc3339();
    Ok(Json(ApiResponse { data: DhcpSubnet { id, network: req.network, pool_start: req.pool_start, pool_end: req.pool_end, gateway: req.gateway, dns_servers: req.dns_servers, domain_name: req.domain_name, lease_time: req.lease_time, enabled, description: req.description, created_at: now } }))
}

pub async fn delete_subnet(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query("DELETE FROM dhcp_subnets WHERE id=?1").bind(&id).execute(&state.pool).await.map_err(|_| internal())?;
    if result.rows_affected() == 0 { return Err(StatusCode::NOT_FOUND); }
    Ok(Json(MessageResponse { message: format!("Subnet {} deleted", id) }))
}

// --- Reservations ---

pub async fn list_reservations(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<DhcpReservation>>>, StatusCode> {
    Ok(Json(ApiResponse { data: list_reservations_db(&state.pool).await }))
}

pub async fn create_reservation(
    State(state): State<AppState>,
    Json(req): Json<CreateReservationRequest>,
) -> Result<(StatusCode, Json<ApiResponse<DhcpReservation>>), StatusCode> {
    let id = Uuid::new_v4().to_string();
    let now = Utc::now().to_rfc3339();
    sqlx::query("INSERT INTO dhcp_reservations (id, subnet_id, mac_address, ip_address, hostname, description, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7)")
        .bind(&id).bind(req.subnet_id.as_deref()).bind(&req.mac_address).bind(&req.ip_address)
        .bind(req.hostname.as_deref()).bind(req.description.as_deref()).bind(&now)
        .execute(&state.pool).await.map_err(|_| bad_request())?;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: DhcpReservation { id, subnet_id: req.subnet_id, mac_address: req.mac_address, ip_address: req.ip_address, hostname: req.hostname, description: req.description, created_at: now } })))
}

pub async fn update_reservation(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateReservationRequest>,
) -> Result<Json<ApiResponse<DhcpReservation>>, StatusCode> {
    let result = sqlx::query("UPDATE dhcp_reservations SET subnet_id=?2, mac_address=?3, ip_address=?4, hostname=?5, description=?6 WHERE id=?1")
        .bind(&id).bind(req.subnet_id.as_deref()).bind(&req.mac_address).bind(&req.ip_address)
        .bind(req.hostname.as_deref()).bind(req.description.as_deref())
        .execute(&state.pool).await.map_err(|_| internal())?;
    if result.rows_affected() == 0 { return Err(StatusCode::NOT_FOUND); }
    let now = Utc::now().to_rfc3339();
    Ok(Json(ApiResponse { data: DhcpReservation { id, subnet_id: req.subnet_id, mac_address: req.mac_address, ip_address: req.ip_address, hostname: req.hostname, description: req.description, created_at: now } }))
}

pub async fn delete_reservation(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query("DELETE FROM dhcp_reservations WHERE id=?1").bind(&id).execute(&state.pool).await.map_err(|_| internal())?;
    if result.rows_affected() == 0 { return Err(StatusCode::NOT_FOUND); }
    Ok(Json(MessageResponse { message: format!("Reservation {} deleted", id) }))
}

// --- Leases ---

pub async fn list_leases() -> Result<Json<ApiResponse<Vec<DhcpLease>>>, StatusCode> {
    let content = tokio::fs::read_to_string("/var/db/kea/kea-leases4.csv").await.unwrap_or_default();
    let mut leases = Vec::new();
    for line in content.lines() {
        if line.starts_with('#') || line.is_empty() { continue; }
        let parts: Vec<&str> = line.split(',').collect();
        // Kea CSV: address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context
        if parts.len() >= 9 {
            leases.push(DhcpLease {
                ip_address: parts[0].to_string(),
                mac_address: parts[1].to_string(),
                hostname: if parts[8].is_empty() { None } else { Some(parts[8].to_string()) },
                state: match parts.get(9).unwrap_or(&"0") { &"0" => "active", &"1" => "declined", &"2" => "expired", _ => "unknown" }.to_string(),
                starts: None,
                expires: Some(parts[4].to_string()),
                subnet_id: parts[5].parse().ok(),
            });
        }
    }
    // Filter to only active/unexpired
    leases.retain(|l| l.state == "active");
    Ok(Json(ApiResponse { data: leases }))
}

pub async fn release_lease(
    Path(ip): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    // Remove from Kea lease file (simplified — in production use Kea CA API)
    let _ = Command::new("sudo").args(["/usr/local/sbin/kea-admin", "lease-del", "4", &ip]).output().await;
    Ok(Json(MessageResponse { message: format!("Lease {} released", ip) }))
}

// --- Logs ---

pub async fn dhcp_logs(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<ApiResponse<Vec<String>>>, StatusCode> {
    let lines_param = params.get("lines").and_then(|v| v.parse::<usize>().ok()).unwrap_or(200);
    let search = params.get("search").cloned().unwrap_or_default();

    // Read Kea log file (try multiple locations)
    let log_paths = ["/var/log/kea/kea-dhcp4.log", "/var/log/kea-dhcp4.log", "/usr/local/var/log/kea/kea-dhcp4.log"];
    let mut content = String::new();
    for path in &log_paths {
        // Use sudo cat since log may be owned by root
        if let Ok(output) = Command::new("sudo").args(["/bin/cat", path]).output().await {
            if output.status.success() {
                content = String::from_utf8_lossy(&output.stdout).to_string();
                break;
            }
        }
    }

    let mut log_lines: Vec<String> = content.lines()
        .filter(|l| !l.is_empty())
        .filter(|l| search.is_empty() || l.to_lowercase().contains(&search.to_lowercase()))
        .map(String::from)
        .collect();

    // Return last N lines (newest first)
    log_lines.reverse();
    log_lines.truncate(lines_param);

    Ok(Json(ApiResponse { data: log_lines }))
}

// --- Apply (write config + restart) ---

pub async fn apply_config(
    State(state): State<AppState>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let config = load_global_config(&state.pool).await;
    let kea_json = generate_kea_config(&state.pool).await;

    // Write config
    let config_path = "/usr/local/etc/kea/kea-dhcp4.conf";
    let _ = tokio::fs::create_dir_all("/usr/local/etc/kea").await;
    let _ = tokio::fs::create_dir_all("/var/db/kea").await;
    let _ = tokio::fs::create_dir_all("/etc/kea").await;
    tokio::fs::write(config_path, &kea_json).await.map_err(|_| internal())?;

    // Ensure keactrl only runs dhcp4 (not ctrl-agent which needs a password file)
    let keactrl_conf = "dhcp4=yes\ndhcp6=no\ndhcp_ddns=no\nctrl_agent=no\nkea_verbose=no\n";
    let _ = tokio::fs::write("/usr/local/etc/kea/keactrl.conf", keactrl_conf).await;

    if config.enabled {
        let _ = Command::new("sudo").args(["/usr/sbin/sysrc", "kea_enable=YES"]).output().await;
        let _ = Command::new("sudo").args(["/usr/sbin/service", "kea", "restart"]).output().await;
        Ok(Json(MessageResponse { message: "DHCP config applied and service restarted".to_string() }))
    } else {
        let _ = Command::new("sudo").args(["/usr/sbin/service", "kea", "stop"]).output().await;
        let _ = Command::new("sudo").args(["/usr/sbin/sysrc", "kea_enable=NO"]).output().await;
        Ok(Json(MessageResponse { message: "DHCP config saved, service stopped".to_string() }))
    }
}
