use axum::{extract::{Path, State}, http::StatusCode, Json};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sqlx::sqlite::SqlitePool;
use tokio::process::Command;
use uuid::Uuid;

use crate::AppState;

/// Run a command with a 15-second timeout to prevent API hangs.
async fn run_cmd_timeout(program: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
    tokio::time::timeout(
        std::time::Duration::from_secs(15),
        Command::new(program).args(args).output()
    ).await.unwrap_or_else(|_| Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "command timed out")))
}

/// Run a service command with timeout (no shell interpolation).
async fn service_cmd(service: &str, action: &str) {
    let _ = run_cmd_timeout("/usr/local/bin/sudo", &["/usr/sbin/service", service, action]).await;
}

/// Run sysrc safely without shell interpolation.
async fn sysrc(setting: &str) {
    let _ = run_cmd_timeout("/usr/local/bin/sudo", &["/usr/sbin/sysrc", setting]).await;
}

/// Copy a file to a destination using sudo tee — no shell interpolation.
async fn sudo_copy(src: &str, dest: &str) {
    let _ = Command::new("/usr/local/bin/sudo")
        .args(["/usr/bin/install", "-m", "0644", src, dest])
        .output()
        .await;
}

/// Validate a domain name — alphanumeric, hyphens, dots only.
fn validate_domain(domain: &str) -> bool {
    !domain.is_empty()
        && domain.len() <= 253
        && domain.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !domain.contains("..")
        && !domain.starts_with('-')
        && !domain.starts_with('.')
}

/// Sanitize a filename derived from a domain — strip anything that's not alphanumeric/hyphen/dot.
fn sanitize_zone_filename(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '.')
        .collect()
}

// ============================================================
// Types
// ============================================================

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ResolverConfig {
    pub backend: String,  // "unbound" or "rdns"
    pub enabled: bool,
    pub listen_interfaces: Vec<String>,
    pub port: u16,
    pub dnssec: bool,
    pub dns64: bool,
    pub register_dhcp: bool,
    pub dhcp_domain: String,  // domain for DHCP lease DNS registration (e.g. "local")
    pub local_zone_type: String,  // transparent, static, redirect, etc.
    pub outgoing_interface: Option<String>,
    // Advanced
    pub num_threads: u32,
    pub msg_cache_size: String,
    pub rrset_cache_size: String,
    pub cache_max_ttl: u32,
    pub cache_min_ttl: u32,
    pub prefetch: bool,
    pub prefetch_key: bool,
    pub infra_host_ttl: u32,
    pub unwanted_reply_threshold: u32,
    pub log_queries: bool,
    pub log_replies: bool,
    pub log_verbosity: u32,
    pub hide_identity: bool,
    pub hide_version: bool,
    pub rebind_protection: bool,
    pub private_addresses: Vec<String>,
    // Forwarding
    pub forwarding_enabled: bool,
    pub forwarding_servers: Vec<String>,   // plain upstream DNS IPs (e.g. "8.8.8.8", "1.1.1.1")
    pub use_system_nameservers: bool,      // also forward to /etc/resolv.conf nameservers
    // DoT
    pub dot_enabled: bool,
    pub dot_upstream: Vec<String>,  // "1.1.1.1@853#cloudflare-dns.com"
    // Blocklists
    pub blocklists_enabled: bool,
    pub blocklist_urls: Vec<String>,
    pub whitelist: Vec<String>,
    pub blocklist_action: String,  // "nxdomain" | "redirect"
    pub blocklist_redirect_ip: Option<String>,
    // Custom
    pub custom_options: String,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            backend: "rdns".to_string(),
            enabled: false,
            listen_interfaces: vec!["0.0.0.0".to_string()],
            port: 53,
            dnssec: true,
            dns64: false,
            register_dhcp: true,
            dhcp_domain: "local".to_string(),
            local_zone_type: "transparent".to_string(),
            outgoing_interface: None,
            num_threads: 2,
            msg_cache_size: "8m".to_string(),
            rrset_cache_size: "16m".to_string(),
            cache_max_ttl: 86400,
            cache_min_ttl: 0,
            prefetch: true,
            prefetch_key: true,
            infra_host_ttl: 900,
            unwanted_reply_threshold: 10000,
            log_queries: false,
            log_replies: false,
            log_verbosity: 1,
            hide_identity: true,
            hide_version: true,
            rebind_protection: true,
            private_addresses: vec![
                "10.0.0.0/8".into(), "172.16.0.0/12".into(), "192.168.0.0/16".into(),
                "169.254.0.0/16".into(), "fd00::/8".into(), "fe80::/10".into(),
            ],
            forwarding_enabled: false,
            forwarding_servers: vec![],
            use_system_nameservers: false,
            dot_enabled: false,
            dot_upstream: vec![
                "1.1.1.1@853#cloudflare-dns.com".into(),
                "1.0.0.1@853#cloudflare-dns.com".into(),
            ],
            blocklists_enabled: false,
            blocklist_urls: vec![],
            whitelist: vec![],
            blocklist_action: "nxdomain".to_string(),
            blocklist_redirect_ip: None,
            custom_options: String::new(),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct HostOverride {
    pub id: String,
    pub hostname: String,
    pub domain: String,
    pub record_type: String,  // A, AAAA, MX, CNAME
    pub value: String,        // IP address or target
    pub mx_priority: Option<u16>,
    pub description: Option<String>,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateHostOverride {
    pub hostname: String,
    pub domain: String,
    pub record_type: Option<String>,
    pub value: String,
    pub mx_priority: Option<u16>,
    pub description: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DomainOverride {
    pub id: String,
    pub domain: String,
    pub server: String,       // IP:port of upstream DNS
    pub description: Option<String>,
    pub enabled: bool,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateDomainOverride {
    pub domain: String,
    pub server: String,
    pub description: Option<String>,
    pub enabled: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccessListEntry {
    pub id: String,
    pub network: String,      // CIDR
    pub action: String,       // allow, deny, refuse, allow_snoop
    pub description: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize)]
pub struct CreateAccessListEntry {
    pub network: String,
    pub action: String,
    pub description: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ResolverStatus {
    pub running: bool,
    pub version: String,
    pub total_hosts: usize,
    pub total_domains: usize,
    pub total_acls: usize,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub queries_total: u64,
}

#[derive(Debug, Serialize)]
pub struct ApiResponse<T: Serialize> { pub data: T }
#[derive(Debug, Serialize)]
pub struct MessageResponse { pub message: String }

fn internal() -> StatusCode { StatusCode::INTERNAL_SERVER_ERROR }
fn bad_request() -> StatusCode { StatusCode::BAD_REQUEST }

// ============================================================
// DB Migration
// ============================================================

pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query(r#"CREATE TABLE IF NOT EXISTS dns_resolver_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)"#)
        .execute(pool).await?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS dns_host_overrides (
            id TEXT PRIMARY KEY, hostname TEXT NOT NULL, domain TEXT NOT NULL,
            record_type TEXT NOT NULL DEFAULT 'A', value TEXT NOT NULL,
            mx_priority INTEGER, description TEXT,
            enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
        )
    "#).execute(pool).await?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS dns_domain_overrides (
            id TEXT PRIMARY KEY, domain TEXT NOT NULL, server TEXT NOT NULL,
            description TEXT, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL
        )
    "#).execute(pool).await?;

    sqlx::query(r#"
        CREATE TABLE IF NOT EXISTS dns_access_lists (
            id TEXT PRIMARY KEY, network TEXT NOT NULL, action TEXT NOT NULL,
            description TEXT, created_at TEXT NOT NULL
        )
    "#).execute(pool).await?;

    Ok(())
}

// ============================================================
// Config helpers
// ============================================================

async fn load_config(pool: &SqlitePool) -> ResolverConfig {
    let rows = sqlx::query_as::<_, (String, String)>("SELECT key, value FROM dns_resolver_config")
        .fetch_all(pool).await.unwrap_or_default();
    let mut c = ResolverConfig::default();
    for (k, v) in rows {
        match k.as_str() {
            "backend" => c.backend = v,
            "enabled" => c.enabled = v == "true",
            "dhcp_domain" => c.dhcp_domain = v,
            "listen_interfaces" => c.listen_interfaces = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            "port" => c.port = v.parse().unwrap_or(53),
            "dnssec" => c.dnssec = v == "true",
            "dns64" => c.dns64 = v == "true",
            "register_dhcp" => c.register_dhcp = v == "true",
            "local_zone_type" => c.local_zone_type = v,
            "outgoing_interface" => c.outgoing_interface = if v.is_empty() { None } else { Some(v) },
            "num_threads" => c.num_threads = v.parse().unwrap_or(2),
            "msg_cache_size" => c.msg_cache_size = v,
            "rrset_cache_size" => c.rrset_cache_size = v,
            "cache_max_ttl" => c.cache_max_ttl = v.parse().unwrap_or(86400),
            "cache_min_ttl" => c.cache_min_ttl = v.parse().unwrap_or(0),
            "prefetch" => c.prefetch = v == "true",
            "prefetch_key" => c.prefetch_key = v == "true",
            "infra_host_ttl" => c.infra_host_ttl = v.parse().unwrap_or(900),
            "unwanted_reply_threshold" => c.unwanted_reply_threshold = v.parse().unwrap_or(10000),
            "log_queries" => c.log_queries = v == "true",
            "log_replies" => c.log_replies = v == "true",
            "log_verbosity" => c.log_verbosity = v.parse().unwrap_or(1),
            "hide_identity" => c.hide_identity = v == "true",
            "hide_version" => c.hide_version = v == "true",
            "rebind_protection" => c.rebind_protection = v == "true",
            "private_addresses" => c.private_addresses = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            "forwarding_enabled" => c.forwarding_enabled = v == "true",
            "forwarding_servers" => c.forwarding_servers = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            "use_system_nameservers" => c.use_system_nameservers = v == "true",
            "dot_enabled" => c.dot_enabled = v == "true",
            "dot_upstream" => c.dot_upstream = v.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            "blocklists_enabled" => c.blocklists_enabled = v == "true",
            "blocklist_urls" => c.blocklist_urls = v.split('\n').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            "whitelist" => c.whitelist = v.split('\n').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            "blocklist_action" => c.blocklist_action = v,
            "blocklist_redirect_ip" => c.blocklist_redirect_ip = if v.is_empty() { None } else { Some(v) },
            "custom_options" => c.custom_options = v,
            _ => {}
        }
    }
    c
}

async fn save_key(pool: &SqlitePool, key: &str, value: &str) {
    let _ = sqlx::query("INSERT OR REPLACE INTO dns_resolver_config (key, value) VALUES (?1, ?2)")
        .bind(key).bind(value).execute(pool).await;
}

fn bool_str(b: bool) -> &'static str { if b { "true" } else { "false" } }

/// Generate unbound.conf from config + DB data
async fn generate_unbound_conf(pool: &SqlitePool) -> String {
    let c = load_config(pool).await;

    let interfaces: String = c.listen_interfaces.iter()
        .map(|i| format!("    interface: {}", i)).collect::<Vec<_>>().join("\n");

    let mut server_lines = vec![
        format!("    username: unbound"),
        format!("    directory: /var/unbound"),
        format!("    chroot: /var/unbound"),
        format!("    pidfile: /var/run/local_unbound.pid"),
        format!("    auto-trust-anchor-file: /var/unbound/root.key"),
        format!("    port: {}", c.port),
        format!("    do-daemonize: no"),
        interfaces,
        format!("    access-control: 0.0.0.0/0 allow"),
        format!("    access-control: ::0/0 allow"),
        format!("    do-ip4: yes"),
        format!("    do-ip6: yes"),
        format!("    do-udp: yes"),
        format!("    do-tcp: yes"),
        format!("    hide-identity: {}", if c.hide_identity { "yes" } else { "no" }),
        format!("    hide-version: {}", if c.hide_version { "yes" } else { "no" }),
        format!("    prefetch: {}", if c.prefetch { "yes" } else { "no" }),
        format!("    prefetch-key: {}", if c.prefetch_key { "yes" } else { "no" }),
        format!("    num-threads: {}", c.num_threads),
        format!("    msg-cache-size: {}", c.msg_cache_size),
        format!("    rrset-cache-size: {}", c.rrset_cache_size),
        format!("    cache-max-ttl: {}", c.cache_max_ttl),
        format!("    cache-min-ttl: {}", c.cache_min_ttl),
        format!("    infra-host-ttl: {}", c.infra_host_ttl),
        format!("    unwanted-reply-threshold: {}", c.unwanted_reply_threshold),
        format!("    verbosity: {}", c.log_verbosity),
    ];

    if c.dnssec {
        server_lines.push("    auto-trust-anchor-file: /usr/local/etc/unbound/root.key".to_string());
    }

    if c.log_queries { server_lines.push("    log-queries: yes".to_string()); }
    if c.log_replies { server_lines.push("    log-replies: yes".to_string()); }

    if c.rebind_protection {
        for addr in &c.private_addresses {
            server_lines.push(format!("    private-address: {}", addr));
        }
    }

    if let Some(ref out_iface) = c.outgoing_interface {
        server_lines.push(format!("    outgoing-interface: {}", out_iface));
    }

    // Access lists from DB
    let acls = sqlx::query_as::<_, (String, String)>(
        "SELECT network, action FROM dns_access_lists ORDER BY rowid ASC"
    ).fetch_all(pool).await.unwrap_or_default();
    for (network, action) in &acls {
        server_lines.push(format!("    access-control: {} {}", network, action));
    }

    // Host overrides from DB
    let hosts = sqlx::query_as::<_, (String, String, String, String, Option<i64>)>(
        "SELECT hostname, domain, record_type, value, mx_priority FROM dns_host_overrides WHERE enabled = 1"
    ).fetch_all(pool).await.unwrap_or_default();

    let mut local_data_lines = Vec::new();
    for (hostname, domain, rtype, value, mx_pri) in &hosts {
        let fqdn = if domain.is_empty() { hostname.clone() } else { format!("{}.{}", hostname, domain) };
        match rtype.as_str() {
            "A" | "AAAA" => local_data_lines.push(format!("    local-data: \"{} IN {} {}\"", fqdn, rtype, value)),
            "MX" => local_data_lines.push(format!("    local-data: \"{} IN MX {} {}\"", fqdn, mx_pri.unwrap_or(10), value)),
            "CNAME" => local_data_lines.push(format!("    local-data: \"{} IN CNAME {}\"", fqdn, value)),
            "TXT" => local_data_lines.push(format!("    local-data: '{} IN TXT \"{}\"'", fqdn, value)),
            _ => {}
        }
        // Also add PTR for A records
        if rtype == "A" {
            let octets: Vec<&str> = value.split('.').collect();
            if octets.len() == 4 {
                let ptr = format!("{}.{}.{}.{}.in-addr.arpa", octets[3], octets[2], octets[1], octets[0]);
                local_data_lines.push(format!("    local-data-ptr: \"{} {}\"", value, fqdn));
                let _ = ptr;
            }
        }
    }

    // DHCP lease registration (query rDHCP API for active leases)
    if c.register_dhcp {
        if let Ok(output) = tokio::process::Command::new("curl")
            .args(["-sf", "--max-time", "3", "http://127.0.0.1:9967/api/v1/leases?state=bound&limit=10000"])
            .output().await
        {
            if output.status.success() {
                let body = String::from_utf8_lossy(&output.stdout);
                if let Ok(leases) = serde_json::from_str::<Vec<serde_json::Value>>(&body) {
                    for lease in &leases {
                        let ip = lease["ip"].as_str().unwrap_or("");
                        let hostname = lease["hostname"].as_str().unwrap_or("");
                        if !ip.is_empty() && !hostname.is_empty() {
                            local_data_lines.push(format!("    local-data: \"{} IN A {}\"", hostname, ip));
                            local_data_lines.push(format!("    local-data-ptr: \"{} {}\"", ip, hostname));
                        }
                    }
                }
            }
        }
    }

    // Domain overrides (forward zones)
    let domains = sqlx::query_as::<_, (String, String)>(
        "SELECT domain, server FROM dns_domain_overrides WHERE enabled = 1"
    ).fetch_all(pool).await.unwrap_or_default();

    let mut forward_zones = Vec::new();
    if c.dot_enabled && !c.dot_upstream.is_empty() {
        // Forward all queries via DoT
        let mut zone = String::from("forward-zone:\n    name: \".\"\n    forward-tls-upstream: yes\n");
        for upstream in &c.dot_upstream {
            zone.push_str(&format!("    forward-addr: {}\n", upstream));
        }
        forward_zones.push(zone);
    } else if c.forwarding_enabled {
        // Plain DNS forwarding
        let mut addrs: Vec<String> = c.forwarding_servers.iter()
            .filter(|s| !s.is_empty())
            .cloned()
            .collect();
        if c.use_system_nameservers {
            if let Ok(resolv) = std::fs::read_to_string("/etc/resolv.conf") {
                for line in resolv.lines() {
                    let line = line.trim();
                    if let Some(ns) = line.strip_prefix("nameserver") {
                        let ns = ns.trim();
                        if ns != "127.0.0.1" && ns != "::1" && !addrs.contains(&ns.to_string()) {
                            addrs.push(ns.to_string());
                        }
                    }
                }
            }
        }
        if !addrs.is_empty() {
            let mut zone = String::from("forward-zone:\n    name: \".\"\n    forward-first: yes\n");
            for addr in &addrs {
                zone.push_str(&format!("    forward-addr: {}\n", addr));
            }
            forward_zones.push(zone);
        }
    }

    for (domain, server) in &domains {
        forward_zones.push(format!("forward-zone:\n    name: \"{}\"\n    forward-addr: {}\n", domain, server));
    }

    // Custom options
    let custom = if c.custom_options.is_empty() { String::new() } else { format!("\n    # Custom options\n{}", c.custom_options.lines().map(|l| format!("    {}", l)).collect::<Vec<_>>().join("\n")) };

    format!("# AiFw Unbound Configuration — Auto-generated\n# Do not edit manually\n\nserver:\n{}\n{}{}\n\n{}\n",
        server_lines.join("\n"),
        local_data_lines.join("\n"),
        custom,
        forward_zones.join("\n"),
    )
}

// ============================================================
// rDNS TOML + Zone Generation
// ============================================================

/// Generate rDNS TOML configuration from the shared DB config.
async fn generate_rdns_conf(pool: &SqlitePool) -> String {
    let c = load_config(pool).await;

    let hosts_count = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM dns_host_overrides WHERE enabled=1")
        .fetch_one(pool).await.map(|r| r.0).unwrap_or(0);
    let need_auth = hosts_count > 0 || c.register_dhcp;

    let listen_udp: Vec<String> = c.listen_interfaces.iter().map(|i| format!("\"{}:{}\"", i, c.port)).collect();
    let listen_tcp = listen_udp.clone();

    let mode = if need_auth { "both" } else { "resolver" };

    let mut toml = String::from("# AiFw rDNS Configuration — Auto-generated\n\n");

    // [server]
    // PID file managed by daemon(8) wrapper — rDNS internal pidfile disabled
    toml.push_str(&format!("[server]\nmode = \"{}\"\nuser = \"rdns\"\ngroup = \"rdns\"\npidfile = \"/dev/null\"\n\n", mode));

    // [listeners]
    toml.push_str(&format!("[listeners]\nudp = [{}]\ntcp = [{}]\n\n", listen_udp.join(", "), listen_tcp.join(", ")));

    // [cache]
    toml.push_str(&format!("[cache]\nmax_entries = 1000000\nmax_ttl = {}\nmin_ttl = {}\nnegative_ttl = 300\n\n", c.cache_max_ttl, c.cache_min_ttl));

    // [resolver]
    toml.push_str("[resolver]\n");
    if c.forwarding_enabled && !c.forwarding_servers.is_empty() {
        let fwd: Vec<String> = c.forwarding_servers.iter().map(|s| format!("\"{}\"", s)).collect();
        toml.push_str(&format!("forwarders = [{}]\n", fwd.join(", ")));
    } else {
        toml.push_str("forwarders = []\n");
    }
    toml.push_str(&format!("dnssec = {}\nqname_minimization = true\n", c.dnssec));

    // Per-domain forward zones
    let domains = sqlx::query_as::<_, (String, String)>(
        "SELECT domain, server FROM dns_domain_overrides WHERE enabled = 1"
    ).fetch_all(pool).await.unwrap_or_default();
    if !domains.is_empty() {
        toml.push('\n');
        for (domain, server) in &domains {
            // Extract IP from "IP:port" or just "IP"
            let ip = if server.contains(':') { server.split(':').next().unwrap_or(server) } else { server.as_str() };
            toml.push_str(&format!("[[resolver.forward_zones]]\nname = \"{}\"\nforwarders = [\"{}\"]\n\n", domain, ip));
        }
    }
    toml.push('\n');

    // [authoritative]
    if need_auth {
        toml.push_str("[authoritative]\nsource = \"zone-files\"\ndirectory = \"/usr/local/etc/rdns/zones\"\n\n");
    } else {
        toml.push_str("[authoritative]\nsource = \"none\"\n\n");
    }

    // [control]
    toml.push_str("[control]\nsocket = \"/var/run/rdns/control.sock\"\n\n");

    // [metrics]
    toml.push_str("[metrics]\nenabled = true\naddress = \"127.0.0.1:9153\"\n\n");

    // [logging]
    let level = if c.log_queries || c.log_verbosity >= 3 { "debug" } else if c.log_verbosity >= 2 { "debug" } else { "info" };
    toml.push_str(&format!("[logging]\nlevel = \"{}\"\nformat = \"text\"\n\n", level));

    // [security]
    toml.push_str("[security]\nsandbox = false\nrate_limit = 1000\n\n");

    // [rpz] — blocklists
    if c.blocklists_enabled && !c.blocklist_urls.is_empty() {
        toml.push_str("[[rpz.zones]]\nname = \"rpz.blocklist\"\nfile = \"/usr/local/etc/rdns/rpz/blocklist.rpz\"\n\n");
    }

    toml
}

/// Generate RFC 1035 zone files for rDNS from host overrides + DHCP leases.
/// Returns Vec<(filename, content)>.
async fn generate_rdns_zones(pool: &SqlitePool) -> Vec<(String, String)> {
    let c = load_config(pool).await;
    let mut zones = Vec::new();
    let serial = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();

    // Collect host overrides grouped by domain
    let hosts = sqlx::query_as::<_, (String, String, String, String, Option<i64>)>(
        "SELECT hostname, domain, record_type, value, mx_priority FROM dns_host_overrides WHERE enabled = 1"
    ).fetch_all(pool).await.unwrap_or_default();

    let mut domain_records: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    let mut ptr_records: Vec<String> = Vec::new();

    for (hostname, domain, rtype, value, mx_pri) in &hosts {
        let domain_key = if domain.is_empty() { "local".to_string() } else { domain.clone() };
        let entry = domain_records.entry(domain_key.clone()).or_default();
        let name = if domain.is_empty() { hostname.clone() } else { hostname.clone() };
        match rtype.as_str() {
            "A" => {
                entry.push(format!("{:<24} IN A       {}", name, value));
                // PTR record
                let octets: Vec<&str> = value.split('.').collect();
                if octets.len() == 4 {
                    let fqdn = if domain.is_empty() { hostname.clone() } else { format!("{}.{}", hostname, domain) };
                    ptr_records.push(format!("{}.{}.{}.{}.in-addr.arpa. IN PTR {}.{}.", octets[3], octets[2], octets[1], octets[0], fqdn, if fqdn.ends_with('.') { "" } else { "." }));
                }
            }
            "AAAA" => entry.push(format!("{:<24} IN AAAA    {}", name, value)),
            "CNAME" => entry.push(format!("{:<24} IN CNAME   {}", name, value)),
            "MX" => entry.push(format!("{:<24} IN MX      {} {}", name, mx_pri.unwrap_or(10), value)),
            "TXT" => entry.push(format!("{:<24} IN TXT     \"{}\"", name, value)),
            _ => {}
        }
    }

    // Write a zone file per domain
    for (domain, records) in &domain_records {
        let mut zone = format!(
            "$TTL 300\n$ORIGIN {}.\n@ IN SOA ns1.{domain}. admin.{domain}. {serial} 3600 900 604800 300\n  IN NS  ns1.{domain}.\n",
            domain, domain = domain, serial = serial
        );
        for record in records {
            zone.push_str(record);
            zone.push('\n');
        }
        zones.push((format!("{}.zone", domain), zone));
    }

    // DHCP lease zone
    if c.register_dhcp {
        let dhcp_domain = if c.dhcp_domain.is_empty() { "local".to_string() } else { c.dhcp_domain.clone() };
        if let Ok(output) = tokio::process::Command::new("curl")
            .args(["-sf", "--max-time", "3", "http://127.0.0.1:9967/api/v1/leases?state=bound&limit=10000"])
            .output().await
        {
            if output.status.success() {
                let body = String::from_utf8_lossy(&output.stdout);
                if let Ok(leases) = serde_json::from_str::<Vec<serde_json::Value>>(&body) {
                    let mut zone = format!(
                        "$TTL 60\n$ORIGIN {}.\n@ IN SOA ns1.{d}. admin.{d}. {s} 3600 900 604800 60\n  IN NS  ns1.{d}.\n",
                        dhcp_domain, d = dhcp_domain, s = serial
                    );
                    for lease in &leases {
                        let ip = lease["ip"].as_str().unwrap_or("");
                        let hostname = lease["hostname"].as_str().unwrap_or("");
                        if !ip.is_empty() && !hostname.is_empty() {
                            // Sanitize hostname (no dots, lowercase)
                            let safe_host = hostname.split('.').next().unwrap_or(hostname).to_lowercase();
                            zone.push_str(&format!("{:<24} IN A       {}\n", safe_host, ip));
                            // PTR
                            let octets: Vec<&str> = ip.split('.').collect();
                            if octets.len() == 4 {
                                ptr_records.push(format!("{}.{}.{}.{}.in-addr.arpa. IN PTR {}.{}.", octets[3], octets[2], octets[1], octets[0], safe_host, dhcp_domain));
                            }
                        }
                    }
                    zones.push((format!("dhcp.{}.zone", dhcp_domain), zone));
                }
            }
        }
    }

    // Reverse (PTR) zone — group by /24 subnet
    if !ptr_records.is_empty() {
        let mut reverse_zones: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
        for ptr in &ptr_records {
            // ptr looks like "X.C.B.A.in-addr.arpa. IN PTR host.domain."
            let parts: Vec<&str> = ptr.split('.').collect();
            if parts.len() >= 6 {
                let zone_key = format!("{}.{}.{}.in-addr.arpa", parts[1], parts[2], parts[3]);
                reverse_zones.entry(zone_key).or_default().push(ptr.clone());
            }
        }
        for (zone_name, records) in &reverse_zones {
            let mut zone = format!(
                "$TTL 300\n$ORIGIN {}.\n@ IN SOA ns1.aifw.local. admin.aifw.local. {} 3600 900 604800 300\n  IN NS  ns1.aifw.local.\n",
                zone_name, serial
            );
            for record in records {
                // Extract just the host part relative to the zone
                let parts: Vec<&str> = record.splitn(2, ".in-addr.arpa").collect();
                if let Some(host_part) = parts.first() {
                    let zone_origin = format!(".{}", zone_name);
                    let relative = host_part.strip_suffix(&zone_origin.replace(".in-addr.arpa", "")).unwrap_or(host_part);
                    // Just write the full record
                    zone.push_str(record);
                    zone.push('\n');
                    let _ = relative;
                }
            }
            zones.push((format!("{}.zone", zone_name), zone));
        }
    }

    zones
}

/// Download blocklists and generate an RPZ zone file for rDNS.
async fn generate_rdns_rpz(pool: &SqlitePool) -> Option<String> {
    let c = load_config(pool).await;
    if !c.blocklists_enabled || c.blocklist_urls.is_empty() {
        return None;
    }

    let serial = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    let mut zone = format!(
        "$TTL 300\n@ IN SOA localhost. admin.localhost. {} 3600 900 604800 300\n  IN NS  localhost.\n",
        serial
    );

    // Whitelist entries (passthru)
    for domain in &c.whitelist {
        let d = domain.trim().trim_end_matches('.');
        if !d.is_empty() {
            zone.push_str(&format!("{} CNAME rpz-passthru.\n", d));
        }
    }

    // Download and parse blocklists
    for url in &c.blocklist_urls {
        if url.trim().is_empty() { continue; }
        let output = tokio::process::Command::new("curl")
            .args(["-sf", "--max-time", "30", url.trim()])
            .output().await;
        if let Ok(o) = output {
            if o.status.success() {
                let body = String::from_utf8_lossy(&o.stdout);
                for line in body.lines() {
                    let line = line.trim();
                    if line.is_empty() || line.starts_with('#') || line.starts_with('!') { continue; }
                    // hosts file format: "0.0.0.0 domain" or "127.0.0.1 domain" or just "domain"
                    let domain = if line.starts_with("0.0.0.0") || line.starts_with("127.0.0.1") {
                        line.split_whitespace().nth(1).unwrap_or("")
                    } else {
                        line.split_whitespace().next().unwrap_or("")
                    };
                    let domain = domain.trim().trim_end_matches('.');
                    if domain.is_empty() || domain == "localhost" || domain == "local" { continue; }
                    match c.blocklist_action.as_str() {
                        "redirect" => {
                            let ip = c.blocklist_redirect_ip.as_deref().unwrap_or("0.0.0.0");
                            zone.push_str(&format!("{} A {}\n", domain, ip));
                        }
                        _ => zone.push_str(&format!("{} CNAME .\n", domain)),
                    }
                }
            }
        }
    }

    Some(zone)
}

// ============================================================
// Handlers
// ============================================================

pub async fn resolver_status(
    State(state): State<AppState>,
) -> Result<Json<ResolverStatus>, StatusCode> {
    let config = load_config(&state.pool).await;
    let is_rdns = config.backend == "rdns";

    let service_name = if is_rdns { "rdns" } else { "local_unbound" };
    let running = Command::new("sudo").args(["/usr/sbin/service", service_name, "status"]).output().await
        .map(|o| o.status.success()).unwrap_or(false);

    let version = if is_rdns {
        let v = Command::new("/usr/local/sbin/rdns").arg("--version").output().await
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        if v.is_empty() { "rDNS".to_string() } else { v }
    } else {
        let v = Command::new("unbound").arg("-V").output().await
            .map(|o| String::from_utf8_lossy(&o.stdout).lines().next().unwrap_or("").to_string())
            .unwrap_or_default();
        if v.is_empty() { "Unbound".to_string() } else { v }
    };

    let hosts = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM dns_host_overrides")
        .fetch_one(&state.pool).await.map(|r| r.0 as usize).unwrap_or(0);
    let domains = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM dns_domain_overrides")
        .fetch_one(&state.pool).await.map(|r| r.0 as usize).unwrap_or(0);
    let acls = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM dns_access_lists")
        .fetch_one(&state.pool).await.map(|r| r.0 as usize).unwrap_or(0);

    let (cache_hits, cache_misses, queries_total) = if is_rdns {
        // rDNS stats via control socket
        Command::new("/usr/local/sbin/rdns-control")
            .args(["--socket", "/var/run/rdns/control.sock", "stats"]).output().await
            .map(|o| {
                let s = String::from_utf8_lossy(&o.stdout);
                let mut hits = 0u64; let mut misses = 0u64;
                for line in s.lines() {
                    let parts: Vec<&str> = line.split('=').collect();
                    if parts.len() == 2 {
                        let val: u64 = parts[1].trim().parse().unwrap_or(0);
                        match parts[0].trim() {
                            "cache.hits" => hits = val,
                            "cache.misses" => misses = val,
                            _ => {}
                        }
                    }
                }
                (hits, misses, hits + misses)
            }).unwrap_or((0, 0, 0))
    } else {
        Command::new("sudo")
            .args(["/usr/local/sbin/unbound-control", "stats_noreset"]).output().await
            .map(|o| {
                let s = String::from_utf8_lossy(&o.stdout);
                let mut hits = 0u64; let mut misses = 0u64; let mut total = 0u64;
                for line in s.lines() {
                    if line.starts_with("total.num.cachehits=") { hits = line.split('=').nth(1).and_then(|v| v.parse().ok()).unwrap_or(0); }
                    if line.starts_with("total.num.cachemiss=") { misses = line.split('=').nth(1).and_then(|v| v.parse().ok()).unwrap_or(0); }
                    if line.starts_with("total.num.queries=") { total = line.split('=').nth(1).and_then(|v| v.parse().ok()).unwrap_or(0); }
                }
                (hits, misses, total)
            }).unwrap_or((0, 0, 0))
    };

    Ok(Json(ResolverStatus {
        running, version, total_hosts: hosts, total_domains: domains, total_acls: acls,
        cache_hits, cache_misses, queries_total,
    }))
}

pub async fn get_config_handler(
    State(state): State<AppState>,
) -> Result<Json<ResolverConfig>, StatusCode> {
    Ok(Json(load_config(&state.pool).await))
}

pub async fn update_config_handler(
    State(state): State<AppState>,
    Json(c): Json<ResolverConfig>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let pool = &state.pool;
    save_key(pool, "backend", &c.backend).await;
    save_key(pool, "enabled", bool_str(c.enabled)).await;
    save_key(pool, "dhcp_domain", &c.dhcp_domain).await;
    save_key(pool, "listen_interfaces", &c.listen_interfaces.join(",")).await;
    save_key(pool, "port", &c.port.to_string()).await;
    save_key(pool, "dnssec", bool_str(c.dnssec)).await;
    save_key(pool, "dns64", bool_str(c.dns64)).await;
    save_key(pool, "register_dhcp", bool_str(c.register_dhcp)).await;
    save_key(pool, "local_zone_type", &c.local_zone_type).await;
    save_key(pool, "outgoing_interface", c.outgoing_interface.as_deref().unwrap_or("")).await;
    save_key(pool, "num_threads", &c.num_threads.to_string()).await;
    save_key(pool, "msg_cache_size", &c.msg_cache_size).await;
    save_key(pool, "rrset_cache_size", &c.rrset_cache_size).await;
    save_key(pool, "cache_max_ttl", &c.cache_max_ttl.to_string()).await;
    save_key(pool, "cache_min_ttl", &c.cache_min_ttl.to_string()).await;
    save_key(pool, "prefetch", bool_str(c.prefetch)).await;
    save_key(pool, "prefetch_key", bool_str(c.prefetch_key)).await;
    save_key(pool, "infra_host_ttl", &c.infra_host_ttl.to_string()).await;
    save_key(pool, "unwanted_reply_threshold", &c.unwanted_reply_threshold.to_string()).await;
    save_key(pool, "log_queries", bool_str(c.log_queries)).await;
    save_key(pool, "log_replies", bool_str(c.log_replies)).await;
    save_key(pool, "log_verbosity", &c.log_verbosity.to_string()).await;
    save_key(pool, "hide_identity", bool_str(c.hide_identity)).await;
    save_key(pool, "hide_version", bool_str(c.hide_version)).await;
    save_key(pool, "rebind_protection", bool_str(c.rebind_protection)).await;
    save_key(pool, "private_addresses", &c.private_addresses.join(",")).await;
    save_key(pool, "forwarding_enabled", bool_str(c.forwarding_enabled)).await;
    save_key(pool, "forwarding_servers", &c.forwarding_servers.join(",")).await;
    save_key(pool, "use_system_nameservers", bool_str(c.use_system_nameservers)).await;
    save_key(pool, "dot_enabled", bool_str(c.dot_enabled)).await;
    save_key(pool, "dot_upstream", &c.dot_upstream.join(",")).await;
    save_key(pool, "blocklists_enabled", bool_str(c.blocklists_enabled)).await;
    save_key(pool, "blocklist_urls", &c.blocklist_urls.join("\n")).await;
    save_key(pool, "whitelist", &c.whitelist.join("\n")).await;
    save_key(pool, "blocklist_action", &c.blocklist_action).await;
    save_key(pool, "blocklist_redirect_ip", c.blocklist_redirect_ip.as_deref().unwrap_or("")).await;
    save_key(pool, "custom_options", &c.custom_options).await;
    state.set_pending(|p| p.dns = true).await;
    Ok(Json(MessageResponse { message: "DNS resolver config saved".to_string() }))
}

pub async fn apply_resolver(
    State(state): State<AppState>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let config = load_config(&state.pool).await;

    match config.backend.as_str() {
        "rdns" => apply_rdns(&state, &config).await,
        _ => apply_unbound(&state, &config).await,
    }
}

async fn apply_unbound(state: &AppState, config: &ResolverConfig) -> Result<Json<MessageResponse>, StatusCode> {
    // Stop rDNS if running (with timeout to prevent hang)
    service_cmd("rdns", "stop").await;
    sysrc("rdns_enable=NO").await;

    let conf = generate_unbound_conf(&state.pool).await;
    let tmp_path = "/tmp/aifw_unbound.conf";
    tokio::fs::write(tmp_path, &conf).await.map_err(|_| internal())?;
    sudo_copy(tmp_path, "/var/unbound/unbound.conf").await;
    let _ = tokio::fs::remove_file(tmp_path).await;
    let _ = Command::new("sudo").args(["/usr/sbin/chown", "-R", "unbound:unbound", "/var/unbound"]).output().await;

    if config.enabled {
        sysrc("local_unbound_enable=YES").await;
        let output = run_cmd_timeout("/usr/local/bin/sudo", &["/usr/sbin/service", "local_unbound", "restart"]).await;
        match output {
            Ok(o) => {
                let msg = String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr);
                if o.status.success() {
                    state.set_pending(|p| p.dns = false).await;
                    Ok(Json(MessageResponse { message: "Unbound config applied and restarted".to_string() }))
                } else {
                    state.set_pending(|p| p.dns = false).await;
                    Ok(Json(MessageResponse { message: format!("Unbound restart issue: {}", msg.trim()) }))
                }
            }
            Err(e) => Ok(Json(MessageResponse { message: format!("Failed: {}", e) })),
        }
    } else {
        service_cmd("local_unbound", "stop").await;
        sysrc("local_unbound_enable=NO").await;
        state.set_pending(|p| p.dns = false).await;
        Ok(Json(MessageResponse { message: "DNS resolver stopped".to_string() }))
    }
}

async fn apply_rdns(state: &AppState, config: &ResolverConfig) -> Result<Json<MessageResponse>, StatusCode> {
    // Stop Unbound if running (with timeout)
    service_cmd("local_unbound", "stop").await;
    sysrc("local_unbound_enable=NO").await;

    // Create directories
    let _ = Command::new("sudo").args(["mkdir", "-p", "/usr/local/etc/rdns/zones", "/usr/local/etc/rdns/rpz", "/var/run/rdns", "/var/log/rdns"]).output().await;

    // Generate and write rDNS config
    let conf = generate_rdns_conf(&state.pool).await;
    let tmp = "/tmp/aifw_rdns.toml";
    tokio::fs::write(tmp, &conf).await.map_err(|_| internal())?;
    sudo_copy(tmp, "/usr/local/etc/rdns/rdns.toml").await;
    let _ = tokio::fs::remove_file(tmp).await;

    // Generate and write zone files
    let zones = generate_rdns_zones(&state.pool).await;
    // Clear old auto-generated zones
    let _ = Command::new("/usr/local/bin/sudo")
        .args(["/usr/bin/find", "/usr/local/etc/rdns/zones", "-name", "*.zone", "-delete"])
        .output().await;
    for (filename, content) in &zones {
        let safe_name = sanitize_zone_filename(filename);
        if safe_name.is_empty() { continue; }
        let tmp_zone = format!("/tmp/aifw_zone_{}", safe_name);
        let dest_zone = format!("/usr/local/etc/rdns/zones/{}", safe_name);
        tokio::fs::write(&tmp_zone, content).await.map_err(|_| internal())?;
        sudo_copy(&tmp_zone, &dest_zone).await;
        let _ = tokio::fs::remove_file(&tmp_zone).await;
    }

    // Generate and write RPZ blocklist
    if let Some(rpz_content) = generate_rdns_rpz(&state.pool).await {
        let tmp_rpz = "/tmp/aifw_rpz_blocklist.rpz";
        tokio::fs::write(tmp_rpz, &rpz_content).await.map_err(|_| internal())?;
        sudo_copy(tmp_rpz, "/usr/local/etc/rdns/rpz/blocklist.rpz").await;
        let _ = tokio::fs::remove_file(tmp_rpz).await;
    }

    if config.enabled {
        sysrc("rdns_enable=YES").await;
        let output = run_cmd_timeout("/usr/local/bin/sudo", &["/usr/sbin/service", "rdns", "restart"]).await;
        match output {
            Ok(o) => {
                let msg = String::from_utf8_lossy(&o.stdout).to_string() + &String::from_utf8_lossy(&o.stderr);
                if o.status.success() {
                    state.set_pending(|p| p.dns = false).await;
                    Ok(Json(MessageResponse { message: format!("rDNS config applied — {} zone file(s)", zones.len()) }))
                } else {
                    Ok(Json(MessageResponse { message: format!("rDNS restart issue: {}", msg.trim()) }))
                }
            }
            Err(e) => Ok(Json(MessageResponse { message: format!("Failed: {}", e) })),
        }
    } else {
        service_cmd("rdns", "stop").await;
        sysrc("rdns_enable=NO").await;
        state.set_pending(|p| p.dns = false).await;
        Ok(Json(MessageResponse { message: "DNS resolver stopped".to_string() }))
    }
}

// Service control — backend-aware
pub async fn resolver_start(State(state): State<AppState>) -> Result<Json<MessageResponse>, StatusCode> {
    let config = load_config(&state.pool).await;
    let (svc, enable_key, other_svc, other_key) = if config.backend == "rdns" {
        ("rdns", "rdns_enable=YES", "local_unbound", "local_unbound_enable=NO")
    } else {
        ("local_unbound", "local_unbound_enable=YES", "rdns", "rdns_enable=NO")
    };
    service_cmd(other_svc, "stop").await;
    sysrc(other_key).await;
    sysrc(enable_key).await;
    service_cmd(svc, "start").await;
    Ok(Json(MessageResponse { message: format!("{} started", if config.backend == "rdns" { "rDNS" } else { "Unbound" }) }))
}
pub async fn resolver_stop(State(state): State<AppState>) -> Result<Json<MessageResponse>, StatusCode> {
    let config = load_config(&state.pool).await;
    let (svc, disable_key) = if config.backend == "rdns" { ("rdns", "rdns_enable=NO") } else { ("local_unbound", "local_unbound_enable=NO") };
    service_cmd(svc, "stop").await;
    sysrc(disable_key).await;
    Ok(Json(MessageResponse { message: "DNS resolver stopped".to_string() }))
}
pub async fn resolver_restart(State(state): State<AppState>) -> Result<Json<MessageResponse>, StatusCode> {
    let config = load_config(&state.pool).await;
    let (svc, enable_key, other_svc, other_key) = if config.backend == "rdns" {
        ("rdns", "rdns_enable=YES", "local_unbound", "local_unbound_enable=NO")
    } else {
        ("local_unbound", "local_unbound_enable=YES", "rdns", "rdns_enable=NO")
    };
    service_cmd(other_svc, "stop").await;
    sysrc(other_key).await;
    sysrc(enable_key).await;
    service_cmd(svc, "restart").await;
    Ok(Json(MessageResponse { message: format!("{} restarted", if config.backend == "rdns" { "rDNS" } else { "Unbound" }) }))
}

// Host overrides CRUD
pub async fn list_hosts(State(state): State<AppState>) -> Result<Json<ApiResponse<Vec<HostOverride>>>, StatusCode> {
    let rows = sqlx::query_as::<_, (String,String,String,String,String,Option<i64>,Option<String>,bool,String)>(
        "SELECT id, hostname, domain, record_type, value, mx_priority, description, enabled, created_at FROM dns_host_overrides ORDER BY hostname ASC"
    ).fetch_all(&state.pool).await.map_err(|_| internal())?;
    let hosts: Vec<HostOverride> = rows.into_iter().map(|(id,h,d,rt,v,mx,desc,en,ca)| HostOverride {
        id, hostname: h, domain: d, record_type: rt, value: v, mx_priority: mx.map(|v| v as u16),
        description: desc, enabled: en, created_at: ca,
    }).collect();
    Ok(Json(ApiResponse { data: hosts }))
}

pub async fn create_host(State(state): State<AppState>, Json(req): Json<CreateHostOverride>) -> Result<(StatusCode, Json<ApiResponse<HostOverride>>), StatusCode> {
    if !validate_domain(&req.hostname) || !validate_domain(&req.domain) {
        return Err(bad_request());
    }
    let id = Uuid::new_v4().to_string(); let now = Utc::now().to_rfc3339();
    let rt = req.record_type.unwrap_or_else(|| "A".to_string());
    let enabled = req.enabled.unwrap_or(true);
    sqlx::query("INSERT INTO dns_host_overrides (id, hostname, domain, record_type, value, mx_priority, description, enabled, created_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)")
        .bind(&id).bind(&req.hostname).bind(&req.domain).bind(&rt).bind(&req.value)
        .bind(req.mx_priority.map(|v| v as i64)).bind(req.description.as_deref()).bind(enabled).bind(&now)
        .execute(&state.pool).await.map_err(|_| bad_request())?;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: HostOverride { id, hostname: req.hostname, domain: req.domain, record_type: rt, value: req.value, mx_priority: req.mx_priority, description: req.description, enabled, created_at: now } })))
}

pub async fn update_host(State(state): State<AppState>, Path(id): Path<String>, Json(req): Json<CreateHostOverride>) -> Result<Json<ApiResponse<HostOverride>>, StatusCode> {
    if !validate_domain(&req.hostname) || !validate_domain(&req.domain) {
        return Err(bad_request());
    }
    let rt = req.record_type.unwrap_or_else(|| "A".to_string());
    let enabled = req.enabled.unwrap_or(true);
    let r = sqlx::query("UPDATE dns_host_overrides SET hostname=?2, domain=?3, record_type=?4, value=?5, mx_priority=?6, description=?7, enabled=?8 WHERE id=?1")
        .bind(&id).bind(&req.hostname).bind(&req.domain).bind(&rt).bind(&req.value)
        .bind(req.mx_priority.map(|v| v as i64)).bind(req.description.as_deref()).bind(enabled)
        .execute(&state.pool).await.map_err(|_| internal())?;
    if r.rows_affected() == 0 { return Err(StatusCode::NOT_FOUND); }
    Ok(Json(ApiResponse { data: HostOverride { id, hostname: req.hostname, domain: req.domain, record_type: rt, value: req.value, mx_priority: req.mx_priority, description: req.description, enabled, created_at: Utc::now().to_rfc3339() } }))
}

pub async fn delete_host(State(state): State<AppState>, Path(id): Path<String>) -> Result<Json<MessageResponse>, StatusCode> {
    let r = sqlx::query("DELETE FROM dns_host_overrides WHERE id=?1").bind(&id).execute(&state.pool).await.map_err(|_| internal())?;
    if r.rows_affected() == 0 { return Err(StatusCode::NOT_FOUND); }
    Ok(Json(MessageResponse { message: "Host override deleted".to_string() }))
}

// Domain overrides CRUD
pub async fn list_domains(State(state): State<AppState>) -> Result<Json<ApiResponse<Vec<DomainOverride>>>, StatusCode> {
    let rows = sqlx::query_as::<_, (String,String,String,Option<String>,bool,String)>(
        "SELECT id, domain, server, description, enabled, created_at FROM dns_domain_overrides ORDER BY domain ASC"
    ).fetch_all(&state.pool).await.map_err(|_| internal())?;
    let domains: Vec<DomainOverride> = rows.into_iter().map(|(id,d,s,desc,en,ca)| DomainOverride { id, domain: d, server: s, description: desc, enabled: en, created_at: ca }).collect();
    Ok(Json(ApiResponse { data: domains }))
}

pub async fn create_domain(State(state): State<AppState>, Json(req): Json<CreateDomainOverride>) -> Result<(StatusCode, Json<ApiResponse<DomainOverride>>), StatusCode> {
    if !validate_domain(&req.domain) {
        return Err(bad_request());
    }
    let id = Uuid::new_v4().to_string(); let now = Utc::now().to_rfc3339();
    let enabled = req.enabled.unwrap_or(true);
    sqlx::query("INSERT INTO dns_domain_overrides (id, domain, server, description, enabled, created_at) VALUES (?1,?2,?3,?4,?5,?6)")
        .bind(&id).bind(&req.domain).bind(&req.server).bind(req.description.as_deref()).bind(enabled).bind(&now)
        .execute(&state.pool).await.map_err(|_| bad_request())?;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: DomainOverride { id, domain: req.domain, server: req.server, description: req.description, enabled, created_at: now } })))
}

pub async fn update_domain(State(state): State<AppState>, Path(id): Path<String>, Json(req): Json<CreateDomainOverride>) -> Result<Json<ApiResponse<DomainOverride>>, StatusCode> {
    let enabled = req.enabled.unwrap_or(true);
    let r = sqlx::query("UPDATE dns_domain_overrides SET domain=?2, server=?3, description=?4, enabled=?5 WHERE id=?1")
        .bind(&id).bind(&req.domain).bind(&req.server).bind(req.description.as_deref()).bind(enabled)
        .execute(&state.pool).await.map_err(|_| internal())?;
    if r.rows_affected() == 0 { return Err(StatusCode::NOT_FOUND); }
    Ok(Json(ApiResponse { data: DomainOverride { id, domain: req.domain, server: req.server, description: req.description, enabled, created_at: Utc::now().to_rfc3339() } }))
}

pub async fn delete_domain(State(state): State<AppState>, Path(id): Path<String>) -> Result<Json<MessageResponse>, StatusCode> {
    let r = sqlx::query("DELETE FROM dns_domain_overrides WHERE id=?1").bind(&id).execute(&state.pool).await.map_err(|_| internal())?;
    if r.rows_affected() == 0 { return Err(StatusCode::NOT_FOUND); }
    Ok(Json(MessageResponse { message: "Domain override deleted".to_string() }))
}

// Access lists CRUD
pub async fn list_acls(State(state): State<AppState>) -> Result<Json<ApiResponse<Vec<AccessListEntry>>>, StatusCode> {
    let rows = sqlx::query_as::<_, (String,String,String,Option<String>,String)>(
        "SELECT id, network, action, description, created_at FROM dns_access_lists ORDER BY rowid ASC"
    ).fetch_all(&state.pool).await.map_err(|_| internal())?;
    let acls: Vec<AccessListEntry> = rows.into_iter().map(|(id,n,a,d,c)| AccessListEntry { id, network: n, action: a, description: d, created_at: c }).collect();
    Ok(Json(ApiResponse { data: acls }))
}

pub async fn create_acl(State(state): State<AppState>, Json(req): Json<CreateAccessListEntry>) -> Result<(StatusCode, Json<ApiResponse<AccessListEntry>>), StatusCode> {
    let id = Uuid::new_v4().to_string(); let now = Utc::now().to_rfc3339();
    sqlx::query("INSERT INTO dns_access_lists (id, network, action, description, created_at) VALUES (?1,?2,?3,?4,?5)")
        .bind(&id).bind(&req.network).bind(&req.action).bind(req.description.as_deref()).bind(&now)
        .execute(&state.pool).await.map_err(|_| bad_request())?;
    Ok((StatusCode::CREATED, Json(ApiResponse { data: AccessListEntry { id, network: req.network, action: req.action, description: req.description, created_at: now } })))
}

pub async fn delete_acl(State(state): State<AppState>, Path(id): Path<String>) -> Result<Json<MessageResponse>, StatusCode> {
    let r = sqlx::query("DELETE FROM dns_access_lists WHERE id=?1").bind(&id).execute(&state.pool).await.map_err(|_| internal())?;
    if r.rows_affected() == 0 { return Err(StatusCode::NOT_FOUND); }
    Ok(Json(MessageResponse { message: "ACL entry deleted".to_string() }))
}

// Query log — backend-aware
pub async fn resolver_logs(State(state): State<AppState>) -> Result<Json<ApiResponse<Vec<String>>>, StatusCode> {
    let config = load_config(&state.pool).await;
    let is_rdns = config.backend == "rdns";

    let content = if is_rdns {
        // rDNS logs to stderr (captured by daemon) — check syslog
        let primary = Command::new("sudo").args(["/bin/cat", "/var/log/rdns.log"]).output().await;
        match primary {
            Ok(o) if o.status.success() && !o.stdout.is_empty() => String::from_utf8_lossy(&o.stdout).to_string(),
            _ => Command::new("sudo").args(["/bin/cat", "/var/log/messages"]).output().await
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default(),
        }
    } else {
        let primary = Command::new("sudo").args(["/bin/cat", "/var/log/unbound.log"]).output().await;
        match primary {
            Ok(o) if o.status.success() && !o.stdout.is_empty() => String::from_utf8_lossy(&o.stdout).to_string(),
            _ => Command::new("sudo").args(["/bin/cat", "/var/log/messages"]).output().await
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string()).unwrap_or_default(),
        }
    };

    let filter_term = if is_rdns { "rdns" } else { "unbound" };
    let lines: Vec<String> = content.lines()
        .filter(|l| l.to_lowercase().contains(filter_term))
        .map(String::from)
        .collect::<Vec<_>>()
        .into_iter().rev().take(200).collect();

    Ok(Json(ApiResponse { data: lines }))
}
