use axum::{extract::{Path, State}, http::StatusCode, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use uuid::Uuid;
use tokio::process::Command;

use crate::AppState;

const RDHCP_CONFIG_PATH: &str = "/usr/local/etc/rdhcpd/config.toml";

/// Reload all aifw anchor rules — user firewall rules + service pass rules.
/// This is the safe way for services to update pf without clobbering other rules.
async fn reload_aifw_anchor(state: &AppState) {
    let _ = state.rule_engine.apply_rules().await;
    let _ = state.nat_engine.apply_rules().await;
}
const RDHCP_LEASE_DB: &str = "/var/db/rdhcpd/leases";
const RDHCP_LOG_PATH: &str = "/var/log/rdhcpd/rdhcpd.log";

// ============================================================
// Types — Global Config
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
    pub domain_search: Vec<String>,
    pub ntp_servers: Vec<String>,
    pub wins_servers: Vec<String>,
    pub next_server: Option<String>,
    pub boot_filename: Option<String>,
    pub log_level: String,
    pub log_format: String,
    pub api_port: u16,
    pub workers: u32,
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
            log_level: "info".to_string(),
            log_format: "text".to_string(),
            api_port: 9967,
            workers: 1,
        }
    }
}

// ============================================================
// Types — Subnets (v4 + v6)
// ============================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DhcpSubnet {
    pub id: String,
    pub network: String,
    pub pool_start: String,
    pub pool_end: String,
    pub gateway: String,
    pub dns_servers: Option<String>,
    pub domain_name: Option<String>,
    pub lease_time: Option<u32>,
    pub max_lease_time: Option<u32>,
    pub renewal_time: Option<u32>,
    pub rebinding_time: Option<u32>,
    pub preferred_time: Option<u32>,
    pub subnet_type: String, // "address" or "prefix-delegation"
    pub delegated_length: Option<u8>,
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
    pub dns_servers: Option<Vec<String>>,
    pub domain_name: Option<String>,
    pub lease_time: Option<u32>,
    pub max_lease_time: Option<u32>,
    pub renewal_time: Option<u32>,
    pub rebinding_time: Option<u32>,
    pub preferred_time: Option<u32>,
    pub subnet_type: Option<String>,
    pub delegated_length: Option<u8>,
    pub enabled: Option<bool>,
    pub description: Option<String>,
}

// ============================================================
// Types — Reservations
// ============================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DhcpReservation {
    pub id: String,
    pub subnet_id: Option<String>,
    pub mac_address: String,
    pub ip_address: String,
    pub hostname: Option<String>,
    pub client_id: Option<String>,
    pub description: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateReservationRequest {
    pub subnet_id: Option<String>,
    pub mac_address: String,
    pub ip_address: String,
    pub hostname: Option<String>,
    pub client_id: Option<String>,
    pub description: Option<String>,
}

// ============================================================
// Types — DDNS
// ============================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DdnsConfig {
    pub enabled: bool,
    pub forward_zone: String,
    pub reverse_zone_v4: String,
    pub reverse_zone_v6: String,
    pub dns_server: String,
    pub tsig_key: String,
    pub tsig_algorithm: String,
    pub tsig_secret: String,
    pub ttl: u32,
}

impl Default for DdnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            forward_zone: String::new(),
            reverse_zone_v4: String::new(),
            reverse_zone_v6: String::new(),
            dns_server: String::new(),
            tsig_key: String::new(),
            tsig_algorithm: "hmac-sha256".to_string(),
            tsig_secret: String::new(),
            ttl: 300,
        }
    }
}

// ============================================================
// Types — HA
// ============================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HaConfig {
    pub mode: String, // "standalone", "active-active", "raft"
    // active-active fields
    pub peer: Option<String>,
    pub listen: Option<String>,
    pub scope_split: Option<f64>,
    pub mclt: Option<u32>,
    pub partner_down_delay: Option<u32>,
    // raft fields
    pub node_id: Option<u64>,
    pub peers: Option<Vec<String>>,
    // shared TLS
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    pub tls_ca: Option<String>,
}

impl Default for HaConfig {
    fn default() -> Self {
        Self {
            mode: "standalone".to_string(),
            peer: None,
            listen: None,
            scope_split: None,
            mclt: None,
            partner_down_delay: None,
            node_id: None,
            peers: None,
            tls_cert: None,
            tls_key: None,
            tls_ca: None,
        }
    }
}

// ============================================================
// Types — Leases (from rDHCP API)
// ============================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct DhcpLease {
    pub ip_address: String,
    pub mac_address: String,
    pub hostname: Option<String>,
    pub client_id: Option<String>,
    pub state: String,
    pub lease_time: u32,
    pub starts: Option<String>,
    pub expires: Option<String>,
    pub subnet: Option<String>,
}

// rDHCP API lease response format
#[derive(Debug, Deserialize)]
struct RdhcpLeaseResponse {
    ip: String,
    mac: Option<String>,
    client_id: Option<String>,
    hostname: Option<String>,
    lease_time: u32,
    state: String,
    start_time: u64,
    expire_time: u64,
    subnet: String,
}

// ============================================================
// Types — Pool Stats (from rDHCP API)
// ============================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct PoolStats {
    pub subnet: String,
    pub total: u64,
    pub allocated: u64,
    pub available: u64,
    pub utilization: f64,
}

// ============================================================
// Types — HA Status (from rDHCP API)
// ============================================================

#[derive(Debug, Serialize, Deserialize)]
pub struct HaStatus {
    pub mode: String,
    pub role: String,
    pub peer_state: Option<String>,
    pub healthy: bool,
}

// ============================================================
// Types — Status
// ============================================================

#[derive(Debug, Serialize)]
pub struct DhcpStatus {
    pub running: bool,
    pub version: String,
    pub uptime: Option<String>,
    pub total_subnets: usize,
    pub total_reservations: usize,
    pub active_leases: usize,
    pub ha: Option<HaStatus>,
    pub pool_stats: Vec<PoolStats>,
}

// ============================================================
// Types — Responses
// ============================================================

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
            preferred_time INTEGER,
            subnet_type TEXT NOT NULL DEFAULT 'address',
            delegated_length INTEGER,
            enabled INTEGER NOT NULL DEFAULT 1,
            description TEXT,
            created_at TEXT NOT NULL
        )
    "#).execute(pool).await?;

    // Add new columns if they don't exist (migration from old schema)
    for col in ["preferred_time INTEGER", "subnet_type TEXT DEFAULT 'address'", "delegated_length INTEGER", "max_lease_time INTEGER", "renewal_time INTEGER", "rebinding_time INTEGER"] {
        let col_name = col.split_whitespace().next().unwrap_or("");
        let check = sqlx::query_scalar::<_, i32>(
            &format!("SELECT COUNT(*) FROM pragma_table_info('dhcp_subnets') WHERE name='{}'", col_name)
        ).fetch_one(pool).await.unwrap_or(0);
        if check == 0 {
            let _ = sqlx::query(&format!("ALTER TABLE dhcp_subnets ADD COLUMN {}", col)).execute(pool).await;
        }
    }

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS dhcp_reservations (
            id TEXT PRIMARY KEY,
            subnet_id TEXT,
            mac_address TEXT NOT NULL,
            ip_address TEXT NOT NULL UNIQUE,
            hostname TEXT,
            client_id TEXT,
            description TEXT,
            created_at TEXT NOT NULL
        )
    "#).execute(pool).await?;

    // Add client_id column if missing
    let check = sqlx::query_scalar::<_, i32>(
        "SELECT COUNT(*) FROM pragma_table_info('dhcp_reservations') WHERE name='client_id'"
    ).fetch_one(pool).await.unwrap_or(0);
    if check == 0 {
        let _ = sqlx::query("ALTER TABLE dhcp_reservations ADD COLUMN client_id TEXT").execute(pool).await;
    }

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS dhcp_ddns_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    "#).execute(pool).await?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS dhcp_ha_config (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
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
            "log_level" => config.log_level = value,
            "log_format" => config.log_format = value,
            "api_port" => config.api_port = value.parse().unwrap_or(9967),
            "workers" => config.workers = value.parse().unwrap_or(1),
            _ => {}
        }
    }
    config
}

async fn save_config_key(pool: &SqlitePool, key: &str, value: &str) {
    let _ = sqlx::query("INSERT OR REPLACE INTO dhcp_config (key, value) VALUES (?1, ?2)")
        .bind(key).bind(value).execute(pool).await;
}

async fn load_ddns_config(pool: &SqlitePool) -> DdnsConfig {
    let rows = sqlx::query_as::<_, (String, String)>("SELECT key, value FROM dhcp_ddns_config")
        .fetch_all(pool).await.unwrap_or_default();
    let mut config = DdnsConfig::default();
    for (key, value) in rows {
        match key.as_str() {
            "enabled" => config.enabled = value == "true",
            "forward_zone" => config.forward_zone = value,
            "reverse_zone_v4" => config.reverse_zone_v4 = value,
            "reverse_zone_v6" => config.reverse_zone_v6 = value,
            "dns_server" => config.dns_server = value,
            "tsig_key" => config.tsig_key = value,
            "tsig_algorithm" => config.tsig_algorithm = value,
            "tsig_secret" => config.tsig_secret = value,
            "ttl" => config.ttl = value.parse().unwrap_or(300),
            _ => {}
        }
    }
    config
}

async fn save_ddns_key(pool: &SqlitePool, key: &str, value: &str) {
    let _ = sqlx::query("INSERT OR REPLACE INTO dhcp_ddns_config (key, value) VALUES (?1, ?2)")
        .bind(key).bind(value).execute(pool).await;
}

async fn load_ha_config(pool: &SqlitePool) -> HaConfig {
    let rows = sqlx::query_as::<_, (String, String)>("SELECT key, value FROM dhcp_ha_config")
        .fetch_all(pool).await.unwrap_or_default();
    let mut config = HaConfig::default();
    for (key, value) in rows {
        match key.as_str() {
            "mode" => config.mode = value,
            "peer" => config.peer = if value.is_empty() { None } else { Some(value) },
            "listen" => config.listen = if value.is_empty() { None } else { Some(value) },
            "scope_split" => config.scope_split = value.parse().ok(),
            "mclt" => config.mclt = value.parse().ok(),
            "partner_down_delay" => config.partner_down_delay = value.parse().ok(),
            "node_id" => config.node_id = value.parse().ok(),
            "peers" => config.peers = if value.is_empty() { None } else { Some(value.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()) },
            "tls_cert" => config.tls_cert = if value.is_empty() { None } else { Some(value) },
            "tls_key" => config.tls_key = if value.is_empty() { None } else { Some(value) },
            "tls_ca" => config.tls_ca = if value.is_empty() { None } else { Some(value) },
            _ => {}
        }
    }
    config
}

async fn save_ha_key(pool: &SqlitePool, key: &str, value: &str) {
    let _ = sqlx::query("INSERT OR REPLACE INTO dhcp_ha_config (key, value) VALUES (?1, ?2)")
        .bind(key).bind(value).execute(pool).await;
}

async fn list_subnets_db(pool: &SqlitePool) -> Vec<DhcpSubnet> {
    let rows = sqlx::query(
        "SELECT id, network, pool_start, pool_end, gateway, dns_servers, domain_name, lease_time, max_lease_time, renewal_time, rebinding_time, preferred_time, subnet_type, delegated_length, enabled, description, created_at FROM dhcp_subnets ORDER BY created_at ASC"
    ).fetch_all(pool).await.unwrap_or_default();

    use sqlx::Row;
    rows.into_iter().map(|r| DhcpSubnet {
        id: r.get("id"),
        network: r.get("network"),
        pool_start: r.get("pool_start"),
        pool_end: r.get("pool_end"),
        gateway: r.get("gateway"),
        dns_servers: r.get("dns_servers"),
        domain_name: r.get("domain_name"),
        lease_time: r.get::<Option<i64>, _>("lease_time").map(|v| v as u32),
        max_lease_time: r.get::<Option<i64>, _>("max_lease_time").map(|v| v as u32),
        renewal_time: r.get::<Option<i64>, _>("renewal_time").map(|v| v as u32),
        rebinding_time: r.get::<Option<i64>, _>("rebinding_time").map(|v| v as u32),
        preferred_time: r.get::<Option<i64>, _>("preferred_time").map(|v| v as u32),
        subnet_type: r.get::<Option<String>, _>("subnet_type").unwrap_or_else(|| "address".to_string()),
        delegated_length: r.get::<Option<i64>, _>("delegated_length").map(|v| v as u8),
        enabled: r.get("enabled"),
        description: r.get("description"),
        created_at: r.get("created_at"),
    }).collect()
}

async fn list_reservations_db(pool: &SqlitePool) -> Vec<DhcpReservation> {
    sqlx::query_as::<_, (String,Option<String>,String,String,Option<String>,Option<String>,Option<String>,String)>(
        "SELECT id, subnet_id, mac_address, ip_address, hostname, client_id, description, created_at FROM dhcp_reservations ORDER BY ip_address ASC"
    ).fetch_all(pool).await.unwrap_or_default()
    .into_iter().map(|(id,sid,mac,ip,hn,cid,desc,ca)| DhcpReservation {
        id, subnet_id: sid, mac_address: mac, ip_address: ip, hostname: hn, client_id: cid, description: desc, created_at: ca,
    }).collect()
}

// ============================================================
// rDHCP TOML Config Generation
// ============================================================

/// Generate rDHCP TOML configuration from AiFw DB state
async fn generate_rdhcp_config(pool: &SqlitePool) -> String {
    let config = load_global_config(pool).await;
    let ddns = load_ddns_config(pool).await;
    let ha = load_ha_config(pool).await;
    let subnets = list_subnets_db(pool).await;
    let reservations = list_reservations_db(pool).await;

    let mut toml = String::with_capacity(4096);

    // Header
    toml.push_str("# rDHCP configuration — generated by AiFw\n");
    toml.push_str("# Do not edit manually; changes will be overwritten on next apply.\n\n");

    // [global]
    toml.push_str("[global]\n");
    toml.push_str(&format!("log_level = \"{}\"\n", config.log_level));
    toml.push_str(&format!("log_format = \"{}\"\n", config.log_format));
    toml.push_str(&format!("lease_db = \"{}\"\n", RDHCP_LEASE_DB));
    toml.push_str(&format!("workers = {}\n", config.workers));
    toml.push('\n');

    // [api]
    toml.push_str("[api]\n");
    toml.push_str(&format!("listen = \"127.0.0.1:{}\"\n", config.api_port));
    toml.push('\n');

    // [ha]
    match ha.mode.as_str() {
        "active-active" => {
            toml.push_str("[ha]\n");
            toml.push_str("mode = \"active-active\"\n");
            if let Some(ref peer) = ha.peer {
                toml.push_str(&format!("peer = \"{}\"\n", peer));
            }
            if let Some(ref listen) = ha.listen {
                toml.push_str(&format!("listen = \"{}\"\n", listen));
            }
            if let Some(split) = ha.scope_split {
                toml.push_str(&format!("scope_split = {}\n", split));
            }
            if let Some(mclt) = ha.mclt {
                toml.push_str(&format!("mclt = {}\n", mclt));
            }
            if let Some(delay) = ha.partner_down_delay {
                toml.push_str(&format!("partner_down_delay = {}\n", delay));
            }
            if let Some(ref cert) = ha.tls_cert { toml.push_str(&format!("tls_cert = \"{}\"\n", cert)); }
            if let Some(ref key) = ha.tls_key { toml.push_str(&format!("tls_key = \"{}\"\n", key)); }
            if let Some(ref ca) = ha.tls_ca { toml.push_str(&format!("tls_ca = \"{}\"\n", ca)); }
        }
        "raft" => {
            toml.push_str("[ha]\n");
            toml.push_str("mode = \"raft\"\n");
            if let Some(id) = ha.node_id {
                toml.push_str(&format!("node_id = {}\n", id));
            }
            if let Some(ref peers) = ha.peers {
                let peers_str: Vec<String> = peers.iter().map(|p| format!("\"{}\"", p)).collect();
                toml.push_str(&format!("peers = [{}]\n", peers_str.join(", ")));
            }
            if let Some(ref cert) = ha.tls_cert { toml.push_str(&format!("tls_cert = \"{}\"\n", cert)); }
            if let Some(ref key) = ha.tls_key { toml.push_str(&format!("tls_key = \"{}\"\n", key)); }
            if let Some(ref ca) = ha.tls_ca { toml.push_str(&format!("tls_ca = \"{}\"\n", ca)); }
        }
        _ => {
            toml.push_str("[ha]\n");
            toml.push_str("mode = \"standalone\"\n");
        }
    }
    toml.push('\n');

    // [[subnet]] entries
    for subnet in &subnets {
        if !subnet.enabled { continue; }

        toml.push_str("[[subnet]]\n");
        toml.push_str(&format!("network = \"{}\"\n", subnet.network));

        // Pool start/end (optional for PD subnets)
        if subnet.subnet_type != "prefix-delegation" {
            toml.push_str(&format!("pool_start = \"{}\"\n", subnet.pool_start));
            toml.push_str(&format!("pool_end = \"{}\"\n", subnet.pool_end));
        }

        let lease_time = subnet.lease_time.unwrap_or(config.default_lease_time);
        toml.push_str(&format!("lease_time = {}\n", lease_time));

        if let Some(mlt) = subnet.max_lease_time {
            toml.push_str(&format!("max_lease_time = {}\n", mlt));
        }
        if let Some(rt) = subnet.renewal_time {
            toml.push_str(&format!("renewal_time = {}\n", rt));
        }
        if let Some(rbt) = subnet.rebinding_time {
            toml.push_str(&format!("rebinding_time = {}\n", rbt));
        }

        if let Some(pt) = subnet.preferred_time {
            toml.push_str(&format!("preferred_time = {}\n", pt));
        }

        if subnet.subnet_type == "prefix-delegation" {
            toml.push_str("type = \"prefix-delegation\"\n");
            if let Some(dl) = subnet.delegated_length {
                toml.push_str(&format!("delegated_length = {}\n", dl));
            }
        }

        // Gateway (router)
        if !subnet.gateway.is_empty() {
            toml.push_str(&format!("router = \"{}\"\n", subnet.gateway));
        }

        // DNS servers — per-subnet override or global
        let dns_list: Vec<String> = subnet.dns_servers.as_ref()
            .map(|d| d.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
            .unwrap_or_else(|| config.dns_servers.clone());
        if !dns_list.is_empty() {
            let dns_str: Vec<String> = dns_list.iter().map(|d| format!("\"{}\"", d)).collect();
            toml.push_str(&format!("dns = [{}]\n", dns_str.join(", ")));
        }

        // Domain
        let domain = subnet.domain_name.as_deref().unwrap_or(&config.domain_name);
        if !domain.is_empty() {
            toml.push_str(&format!("domain = \"{}\"\n", domain));
        }

        // Reservations for this subnet
        let sub_reservations: Vec<&DhcpReservation> = reservations.iter()
            .filter(|r| r.subnet_id.as_deref() == Some(&subnet.id))
            .collect();

        for res in sub_reservations {
            toml.push('\n');
            toml.push_str("[[subnet.reservation]]\n");
            if !res.mac_address.is_empty() {
                toml.push_str(&format!("mac = \"{}\"\n", res.mac_address));
            }
            if let Some(ref cid) = res.client_id {
                if !cid.is_empty() {
                    toml.push_str(&format!("client_id = \"{}\"\n", cid));
                }
            }
            toml.push_str(&format!("ip = \"{}\"\n", res.ip_address));
            if let Some(ref hn) = res.hostname {
                if !hn.is_empty() {
                    toml.push_str(&format!("hostname = \"{}\"\n", hn));
                }
            }
        }

        toml.push('\n');
    }

    // [ddns]
    toml.push_str("[ddns]\n");
    toml.push_str(&format!("enabled = {}\n", ddns.enabled));
    if ddns.enabled {
        if !ddns.forward_zone.is_empty() {
            toml.push_str(&format!("forward_zone = \"{}\"\n", ddns.forward_zone));
        }
        if !ddns.reverse_zone_v4.is_empty() {
            toml.push_str(&format!("reverse_zone_v4 = \"{}\"\n", ddns.reverse_zone_v4));
        }
        if !ddns.reverse_zone_v6.is_empty() {
            toml.push_str(&format!("reverse_zone_v6 = \"{}\"\n", ddns.reverse_zone_v6));
        }
        if !ddns.dns_server.is_empty() {
            toml.push_str(&format!("dns_server = \"{}\"\n", ddns.dns_server));
        }
        if !ddns.tsig_key.is_empty() {
            toml.push_str(&format!("tsig_key = \"{}\"\n", ddns.tsig_key));
        }
        if !ddns.tsig_algorithm.is_empty() {
            toml.push_str(&format!("tsig_algorithm = \"{}\"\n", ddns.tsig_algorithm));
        }
        if !ddns.tsig_secret.is_empty() {
            toml.push_str(&format!("tsig_secret = \"{}\"\n", ddns.tsig_secret));
        }
        toml.push_str(&format!("ttl = {}\n", ddns.ttl));
    }

    toml
}

// ============================================================
// rDHCP API client helpers
// ============================================================

async fn rdhcp_api_get(path: &str, api_port: u16) -> Result<String, String> {
    let url = format!("http://127.0.0.1:{}{}", api_port, path);
    let output = Command::new("curl")
        .args(["-sf", "--max-time", "3", &url])
        .output()
        .await
        .map_err(|e| format!("curl failed: {}", e))?;

    if !output.status.success() {
        return Err("rDHCP API unreachable".to_string());
    }
    String::from_utf8(output.stdout).map_err(|e| format!("invalid UTF-8: {}", e))
}

async fn rdhcp_api_delete(path: &str, api_port: u16) -> Result<(), String> {
    let url = format!("http://127.0.0.1:{}{}", api_port, path);
    let output = Command::new("curl")
        .args(["-sf", "--max-time", "3", "-X", "DELETE", &url])
        .output()
        .await
        .map_err(|e| format!("curl failed: {}", e))?;

    if !output.status.success() {
        return Err("rDHCP API delete failed".to_string());
    }
    Ok(())
}

// ============================================================
// Handlers
// ============================================================

// --- Status ---

pub async fn dhcp_status(
    State(state): State<AppState>,
) -> Result<Json<DhcpStatus>, StatusCode> {
    let config = load_global_config(&state.pool).await;

    let running = Command::new("/usr/local/bin/sudo").args(["/usr/sbin/service", "rdhcpd", "status"]).output().await
        .map(|o| o.status.success())
        .unwrap_or(false);

    let version = if running {
        // Check rDHCP health endpoint for version info
        match rdhcp_api_get("/health", config.api_port).await {
            Ok(body) => {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&body) {
                    format!("rDHCP ({})", v["ha_mode"].as_str().unwrap_or("standalone"))
                } else {
                    "rDHCP".to_string()
                }
            }
            Err(_) => "rDHCP (API unreachable)".to_string(),
        }
    } else {
        "rDHCP (stopped)".to_string()
    };

    let subnets = list_subnets_db(&state.pool).await;
    let reservations = list_reservations_db(&state.pool).await;

    // Query rDHCP API for live data
    let mut active_leases = 0usize;
    let mut ha_status = None;
    let mut pool_stats = Vec::new();

    if running {
        // Lease stats
        if let Ok(body) = rdhcp_api_get("/api/v1/leases/stats", config.api_port).await {
            if let Ok(stats) = serde_json::from_str::<Vec<PoolStats>>(&body) {
                active_leases = stats.iter().map(|s| s.allocated as usize).sum();
                pool_stats = stats;
            }
        }

        // HA status
        if let Ok(body) = rdhcp_api_get("/api/v1/ha/status", config.api_port).await {
            ha_status = serde_json::from_str(&body).ok();
        }
    }

    Ok(Json(DhcpStatus {
        running, version, uptime: None,
        total_subnets: subnets.len(),
        total_reservations: reservations.len(),
        active_leases,
        ha: ha_status,
        pool_stats,
    }))
}

// --- Service control ---

async fn run_rdhcp_service(action: &str) -> Json<MessageResponse> {
    // Ensure rdhcpd is enabled in rc.conf before start/restart
    if action == "start" || action == "restart" {
        let _ = Command::new("/usr/local/bin/sudo").args(["/usr/sbin/sysrc", "rdhcpd_enable=YES"]).output().await;
    }
    let output = Command::new("/usr/local/bin/sudo").args(["/usr/sbin/service", "rdhcpd", action])
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

pub async fn dhcp_start(
    State(state): State<AppState>,
) -> Result<Json<MessageResponse>, StatusCode> {
    // Generate config if it doesn't exist
    ensure_config(&state.pool).await;
    Ok(run_rdhcp_service("start").await)
}

pub async fn dhcp_stop() -> Result<Json<MessageResponse>, StatusCode> {
    Ok(run_rdhcp_service("stop").await)
}

pub async fn dhcp_restart(
    State(state): State<AppState>,
) -> Result<Json<MessageResponse>, StatusCode> {
    ensure_config(&state.pool).await;
    Ok(run_rdhcp_service("restart").await)
}

/// Write rDHCP config if it doesn't already exist on disk
async fn ensure_config(pool: &SqlitePool) {
    let config_exists = tokio::fs::metadata(RDHCP_CONFIG_PATH).await.is_ok();
    if !config_exists {
        let toml_config = generate_rdhcp_config(pool).await;
        let _ = tokio::fs::create_dir_all("/usr/local/etc/rdhcpd").await;
        let _ = tokio::fs::create_dir_all(RDHCP_LEASE_DB).await;
        let _ = tokio::fs::create_dir_all("/var/log/rdhcpd").await;
        let _ = tokio::fs::write(RDHCP_CONFIG_PATH, &toml_config).await;
    }
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
    save_config_key(&state.pool, "log_level", &config.log_level).await;
    save_config_key(&state.pool, "log_format", &config.log_format).await;
    save_config_key(&state.pool, "api_port", &config.api_port.to_string()).await;
    save_config_key(&state.pool, "workers", &config.workers.to_string()).await;
    auto_apply(&state).await;
    Ok(Json(MessageResponse { message: "DHCP config updated and applied".to_string() }))
}

// --- DDNS config ---

pub async fn get_ddns_config(
    State(state): State<AppState>,
) -> Result<Json<DdnsConfig>, StatusCode> {
    Ok(Json(load_ddns_config(&state.pool).await))
}

pub async fn update_ddns_config(
    State(state): State<AppState>,
    Json(config): Json<DdnsConfig>,
) -> Result<Json<MessageResponse>, StatusCode> {
    save_ddns_key(&state.pool, "enabled", if config.enabled { "true" } else { "false" }).await;
    save_ddns_key(&state.pool, "forward_zone", &config.forward_zone).await;
    save_ddns_key(&state.pool, "reverse_zone_v4", &config.reverse_zone_v4).await;
    save_ddns_key(&state.pool, "reverse_zone_v6", &config.reverse_zone_v6).await;
    save_ddns_key(&state.pool, "dns_server", &config.dns_server).await;
    save_ddns_key(&state.pool, "tsig_key", &config.tsig_key).await;
    save_ddns_key(&state.pool, "tsig_algorithm", &config.tsig_algorithm).await;
    save_ddns_key(&state.pool, "tsig_secret", &config.tsig_secret).await;
    save_ddns_key(&state.pool, "ttl", &config.ttl.to_string()).await;
    Ok(Json(MessageResponse { message: "DDNS config updated".to_string() }))
}

// --- HA config ---

pub async fn get_ha_config(
    State(state): State<AppState>,
) -> Result<Json<HaConfig>, StatusCode> {
    Ok(Json(load_ha_config(&state.pool).await))
}

pub async fn update_ha_config(
    State(state): State<AppState>,
    Json(config): Json<HaConfig>,
) -> Result<Json<MessageResponse>, StatusCode> {
    save_ha_key(&state.pool, "mode", &config.mode).await;
    save_ha_key(&state.pool, "peer", config.peer.as_deref().unwrap_or("")).await;
    save_ha_key(&state.pool, "listen", config.listen.as_deref().unwrap_or("")).await;
    save_ha_key(&state.pool, "scope_split", &config.scope_split.map(|v| v.to_string()).unwrap_or_default()).await;
    save_ha_key(&state.pool, "mclt", &config.mclt.map(|v| v.to_string()).unwrap_or_default()).await;
    save_ha_key(&state.pool, "partner_down_delay", &config.partner_down_delay.map(|v| v.to_string()).unwrap_or_default()).await;
    save_ha_key(&state.pool, "node_id", &config.node_id.map(|v| v.to_string()).unwrap_or_default()).await;
    save_ha_key(&state.pool, "peers", &config.peers.as_ref().map(|v| v.join(",")).unwrap_or_default()).await;
    save_ha_key(&state.pool, "tls_cert", config.tls_cert.as_deref().unwrap_or("")).await;
    save_ha_key(&state.pool, "tls_key", config.tls_key.as_deref().unwrap_or("")).await;
    save_ha_key(&state.pool, "tls_ca", config.tls_ca.as_deref().unwrap_or("")).await;
    Ok(Json(MessageResponse { message: "HA config updated".to_string() }))
}

// --- HA live status (from rDHCP API) ---

pub async fn get_ha_status(
    State(state): State<AppState>,
) -> Result<Json<HaStatus>, StatusCode> {
    let config = load_global_config(&state.pool).await;
    let body = rdhcp_api_get("/api/v1/ha/status", config.api_port).await.map_err(|_| internal())?;
    serde_json::from_str(&body).map(Json).map_err(|_| internal())
}

// --- Pool stats (from rDHCP API) ---

pub async fn get_pool_stats(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<PoolStats>>>, StatusCode> {
    let config = load_global_config(&state.pool).await;
    let body = rdhcp_api_get("/api/v1/leases/stats", config.api_port).await.map_err(|_| internal())?;
    let stats: Vec<PoolStats> = serde_json::from_str(&body).map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: stats }))
}

// --- Metrics (proxy rDHCP Prometheus metrics) ---

pub async fn get_metrics(
    State(state): State<AppState>,
) -> Result<String, StatusCode> {
    let config = load_global_config(&state.pool).await;
    rdhcp_api_get("/metrics", config.api_port).await.map_err(|_| internal())
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
    let subnet_type = req.subnet_type.as_deref().unwrap_or("address");
    let dns_str = req.dns_servers.as_ref().map(|v| v.join(","));
    sqlx::query("INSERT INTO dhcp_subnets (id, network, pool_start, pool_end, gateway, dns_servers, domain_name, lease_time, max_lease_time, renewal_time, rebinding_time, preferred_time, subnet_type, delegated_length, enabled, description, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17)")
        .bind(&id).bind(&req.network).bind(&req.pool_start).bind(&req.pool_end).bind(&req.gateway)
        .bind(dns_str.as_deref()).bind(req.domain_name.as_deref()).bind(req.lease_time.map(|v| v as i64))
        .bind(req.max_lease_time.map(|v| v as i64)).bind(req.renewal_time.map(|v| v as i64))
        .bind(req.rebinding_time.map(|v| v as i64)).bind(req.preferred_time.map(|v| v as i64))
        .bind(subnet_type).bind(req.delegated_length.map(|v| v as i64))
        .bind(enabled).bind(req.description.as_deref()).bind(&now)
        .execute(&state.pool).await.map_err(|_| bad_request())?;
    let dns_display = req.dns_servers.as_ref().map(|v| v.join(","));
    let subnet = DhcpSubnet {
        id, network: req.network, pool_start: req.pool_start, pool_end: req.pool_end,
        gateway: req.gateway, dns_servers: dns_display, domain_name: req.domain_name,
        lease_time: req.lease_time, max_lease_time: req.max_lease_time,
        renewal_time: req.renewal_time, rebinding_time: req.rebinding_time,
        preferred_time: req.preferred_time,
        subnet_type: subnet_type.to_string(), delegated_length: req.delegated_length,
        enabled, description: req.description, created_at: now,
    };
    auto_apply(&state).await;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: subnet })))
}

pub async fn update_subnet(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateSubnetRequest>,
) -> Result<Json<ApiResponse<DhcpSubnet>>, StatusCode> {
    let enabled = req.enabled.unwrap_or(true);
    let subnet_type = req.subnet_type.as_deref().unwrap_or("address");
    let dns_str = req.dns_servers.as_ref().map(|v| v.join(","));
    let result = sqlx::query("UPDATE dhcp_subnets SET network=?2, pool_start=?3, pool_end=?4, gateway=?5, dns_servers=?6, domain_name=?7, lease_time=?8, max_lease_time=?9, renewal_time=?10, rebinding_time=?11, preferred_time=?12, subnet_type=?13, delegated_length=?14, enabled=?15, description=?16 WHERE id=?1")
        .bind(&id).bind(&req.network).bind(&req.pool_start).bind(&req.pool_end).bind(&req.gateway)
        .bind(dns_str.as_deref()).bind(req.domain_name.as_deref()).bind(req.lease_time.map(|v| v as i64))
        .bind(req.max_lease_time.map(|v| v as i64)).bind(req.renewal_time.map(|v| v as i64))
        .bind(req.rebinding_time.map(|v| v as i64)).bind(req.preferred_time.map(|v| v as i64))
        .bind(subnet_type).bind(req.delegated_length.map(|v| v as i64))
        .bind(enabled).bind(req.description.as_deref())
        .execute(&state.pool).await.map_err(|_| internal())?;
    if result.rows_affected() == 0 { return Err(StatusCode::NOT_FOUND); }
    let now = Utc::now().to_rfc3339();
    auto_apply(&state).await;
    let dns_display = req.dns_servers.as_ref().map(|v| v.join(","));
    Ok(Json(ApiResponse { data: DhcpSubnet {
        id, network: req.network, pool_start: req.pool_start, pool_end: req.pool_end,
        gateway: req.gateway, dns_servers: dns_display, domain_name: req.domain_name,
        lease_time: req.lease_time, max_lease_time: req.max_lease_time,
        renewal_time: req.renewal_time, rebinding_time: req.rebinding_time,
        preferred_time: req.preferred_time,
        subnet_type: subnet_type.to_string(), delegated_length: req.delegated_length,
        enabled, description: req.description, created_at: now,
    }}))
}

pub async fn delete_subnet(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query("DELETE FROM dhcp_subnets WHERE id=?1").bind(&id).execute(&state.pool).await.map_err(|_| internal())?;
    if result.rows_affected() == 0 { return Err(StatusCode::NOT_FOUND); }
    auto_apply(&state).await;
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
    sqlx::query("INSERT INTO dhcp_reservations (id, subnet_id, mac_address, ip_address, hostname, client_id, description, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8)")
        .bind(&id).bind(req.subnet_id.as_deref()).bind(&req.mac_address).bind(&req.ip_address)
        .bind(req.hostname.as_deref()).bind(req.client_id.as_deref()).bind(req.description.as_deref()).bind(&now)
        .execute(&state.pool).await.map_err(|_| bad_request())?;
    auto_apply(&state).await;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: DhcpReservation { id, subnet_id: req.subnet_id, mac_address: req.mac_address, ip_address: req.ip_address, hostname: req.hostname, client_id: req.client_id, description: req.description, created_at: now } })))
}

pub async fn update_reservation(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<CreateReservationRequest>,
) -> Result<Json<ApiResponse<DhcpReservation>>, StatusCode> {
    let result = sqlx::query("UPDATE dhcp_reservations SET subnet_id=?2, mac_address=?3, ip_address=?4, hostname=?5, client_id=?6, description=?7 WHERE id=?1")
        .bind(&id).bind(req.subnet_id.as_deref()).bind(&req.mac_address).bind(&req.ip_address)
        .bind(req.hostname.as_deref()).bind(req.client_id.as_deref()).bind(req.description.as_deref())
        .execute(&state.pool).await.map_err(|_| internal())?;
    if result.rows_affected() == 0 { return Err(StatusCode::NOT_FOUND); }
    let now = Utc::now().to_rfc3339();
    auto_apply(&state).await;
    Ok(Json(ApiResponse { data: DhcpReservation { id, subnet_id: req.subnet_id, mac_address: req.mac_address, ip_address: req.ip_address, hostname: req.hostname, client_id: req.client_id, description: req.description, created_at: now } }))
}

pub async fn delete_reservation(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let result = sqlx::query("DELETE FROM dhcp_reservations WHERE id=?1").bind(&id).execute(&state.pool).await.map_err(|_| internal())?;
    if result.rows_affected() == 0 { return Err(StatusCode::NOT_FOUND); }
    auto_apply(&state).await;
    Ok(Json(MessageResponse { message: format!("Reservation {} deleted", id) }))
}

// --- Leases (from rDHCP API) ---

pub async fn list_leases(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<DhcpLease>>>, StatusCode> {
    let config = load_global_config(&state.pool).await;

    let body = rdhcp_api_get("/api/v1/leases?state=bound&limit=10000", config.api_port).await
        .unwrap_or_else(|_| "[]".to_string());

    let rdhcp_leases: Vec<RdhcpLeaseResponse> = serde_json::from_str(&body).unwrap_or_default();

    let leases: Vec<DhcpLease> = rdhcp_leases.into_iter().map(|l| {
        DhcpLease {
            ip_address: l.ip,
            mac_address: l.mac.unwrap_or_default(),
            hostname: l.hostname,
            client_id: l.client_id,
            state: l.state,
            lease_time: l.lease_time,
            starts: Some(format_unix_ts(l.start_time)),
            expires: Some(format_unix_ts(l.expire_time)),
            subnet: Some(l.subnet),
        }
    }).collect();

    Ok(Json(ApiResponse { data: leases }))
}

pub async fn release_lease(
    State(state): State<AppState>,
    Path(ip): Path<String>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let config = load_global_config(&state.pool).await;
    let path = format!("/api/v1/leases/{}", ip);
    match rdhcp_api_delete(&path, config.api_port).await {
        Ok(()) => Ok(Json(MessageResponse { message: format!("Lease {} released", ip) })),
        Err(e) => Ok(Json(MessageResponse { message: format!("Failed to release {}: {}", ip, e) })),
    }
}

// --- Logs ---

pub async fn dhcp_logs(
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<ApiResponse<Vec<String>>>, StatusCode> {
    let lines_param = params.get("lines").and_then(|v| v.parse::<usize>().ok()).unwrap_or(200);
    let search = params.get("search").cloned().unwrap_or_default();

    // Read rDHCP log file
    let log_paths = [RDHCP_LOG_PATH, "/var/log/rdhcpd.log"];
    let mut content = String::new();
    for path in &log_paths {
        // Try direct read first (aifw user may have read access)
        if let Ok(c) = tokio::fs::read_to_string(path).await {
            content = c;
            break;
        }
        // Fallback to sudo
        if let Ok(output) = Command::new("/usr/local/bin/sudo").args(["/bin/cat", path]).output().await {
            if output.status.success() {
                content = String::from_utf8_lossy(&output.stdout).to_string();
                break;
            }
        }
    }

    // Also try journalctl if no log file found
    if content.is_empty() {
        if let Ok(output) = Command::new("/usr/local/bin/sudo").args(["journalctl", "-u", "rdhcpd", "--no-pager", "-n", &lines_param.to_string()]).output().await {
            if output.status.success() {
                content = String::from_utf8_lossy(&output.stdout).to_string();
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
    let toml_config = generate_rdhcp_config(&state.pool).await;

    // Create directories
    let _ = tokio::fs::create_dir_all("/usr/local/etc/rdhcpd").await;
    let _ = tokio::fs::create_dir_all(RDHCP_LEASE_DB).await;
    let _ = tokio::fs::create_dir_all("/var/log/rdhcpd").await;

    // Write TOML config
    tokio::fs::write(RDHCP_CONFIG_PATH, &toml_config).await.map_err(|_| internal())?;

    // Fix ownership
    let _ = Command::new("/usr/local/bin/sudo").args(["chown", "-R", "aifw:aifw", "/usr/local/etc/rdhcpd"]).output().await;
    let _ = Command::new("/usr/local/bin/sudo").args(["chown", "-R", "aifw:aifw", RDHCP_LEASE_DB]).output().await;
    let _ = Command::new("/usr/local/bin/sudo").args(["chown", "-R", "aifw:aifw", "/var/log/rdhcpd"]).output().await;

    if config.enabled {
        let _ = Command::new("/usr/local/bin/sudo").args(["/usr/sbin/sysrc", "rdhcpd_enable=YES"]).output().await;
        let _ = Command::new("/usr/local/bin/sudo").args(["/usr/sbin/service", "rdhcpd", "restart"]).output().await;

        // Reload all aifw anchor rules (includes user rules + service rules)
        // This preserves existing firewall rules while adding DHCP pass rules
        reload_aifw_anchor(&state).await;

        Ok(Json(MessageResponse { message: "DHCP config applied and rDHCP restarted".to_string() }))
    } else {
        let _ = Command::new("/usr/local/bin/sudo").args(["/usr/sbin/service", "rdhcpd", "stop"]).output().await;
        let _ = Command::new("/usr/local/bin/sudo").args(["/usr/sbin/sysrc", "rdhcpd_enable=NO"]).output().await;
        // Reload anchor to remove DHCP rules
        reload_aifw_anchor(&state).await;
        Ok(Json(MessageResponse { message: "DHCP config saved, rDHCP stopped".to_string() }))
    }
}

/// Auto-apply DHCP config after any change (subnet/reservation CRUD).
/// Regenerates the rDHCP config file, restarts the service, and ensures
/// pf allows DHCP broadcast traffic.
async fn auto_apply(state: &AppState) {
    let config = load_global_config(&state.pool).await;
    if !config.enabled { return; }

    let toml_config = generate_rdhcp_config(&state.pool).await;
    let _ = tokio::fs::create_dir_all("/usr/local/etc/rdhcpd").await;
    if tokio::fs::write(RDHCP_CONFIG_PATH, &toml_config).await.is_ok() {
        let _ = Command::new("/usr/local/bin/sudo").args(["chown", "-R", "aifw:aifw", "/usr/local/etc/rdhcpd"]).output().await;
        let _ = Command::new("/usr/local/bin/sudo").args(["/usr/sbin/service", "rdhcpd", "restart"]).output().await;
        tracing::info!("DHCP config auto-applied");
    }

    // Ensure pf allows DHCP broadcast traffic on configured interfaces.
    // DHCP discovers come from 0.0.0.0:68 → 255.255.255.255:67 which
    // doesn't match LAN subnet rules and gets dropped by "block in log all".
    ensure_dhcp_pf_rules(&config).await;
}

/// Add DHCP pass rules to the main pf.conf if not already present.
async fn ensure_dhcp_pf_rules(config: &DhcpGlobalConfig) {
    let pf_path = "/usr/local/etc/aifw/pf.conf.aifw";
    let content = match tokio::fs::read_to_string(pf_path).await {
        Ok(c) => c,
        Err(_) => return,
    };

    // Check if DHCP rules already exist
    if content.contains("port 67") {
        return;
    }

    // Insert DHCP pass rules before "block in log all"
    let dhcp_rules = format!(
        "# DHCP server — allow broadcast requests and replies\n\
         pass in quick on {{ {} }} proto udp from 0.0.0.0 port 68 to 255.255.255.255 port 67 label \"dhcp-discover\"\n\
         pass out quick on {{ {} }} proto udp from any port 67 to any port 68 label \"dhcp-reply\"\n\n",
        config.interfaces.join(" "),
        config.interfaces.join(" "),
    );

    let new_content = content.replace(
        "block in log all",
        &format!("{dhcp_rules}block in log all"),
    );

    if let Ok(()) = tokio::fs::write(pf_path, &new_content).await {
        // Reload pf with the updated config
        let _ = Command::new("/usr/local/bin/sudo")
            .args(["/sbin/pfctl", "-f", pf_path])
            .output()
            .await;
        tracing::info!("DHCP pf rules added");
    }
}

// ============================================================
// Utility
// ============================================================

fn format_unix_ts(ts: u64) -> String {
    chrono::DateTime::from_timestamp(ts as i64, 0)
        .map(|dt| dt.to_rfc3339())
        .unwrap_or_else(|| ts.to_string())
}
