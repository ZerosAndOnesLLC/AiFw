//! Initial database: schema, admin user, seeded rules and DHCP config.

use crate::config::SetupConfig;
use crate::console;
use aifw_common::{CarpVip, ClusterNode, ClusterRole, Interface, PfsyncConfig};

// `run_best_effort`/`run_sysrc` are only referenced from the
// `#[cfg(target_os = "freebsd")]` blocks below (sysrc/chown on a real box).
use super::system::warn_on_err;
#[cfg(target_os = "freebsd")]
use super::system::{run_best_effort, run_sysrc};

/// Initialize the SQLite database and create the admin user
pub(super) async fn init_database(config: &SetupConfig) -> Result<(), String> {
    let db = aifw_core::Database::new(std::path::Path::new(&config.db_path))
        .await
        .map_err(|e| format!("db init error: {e}"))?;

    let pool = db.pool().clone();

    // Run auth migrations — schemas are sourced from aifw_common::schemas
    // (QUAL-C5) so the wizard and aifw-api's startup migration share one
    // definition that can't drift.
    for sql in [
        aifw_common::schemas::USERS_CREATE,
        aifw_common::schemas::RECOVERY_CODES_CREATE,
        aifw_common::schemas::AUTH_CONFIG_CREATE,
    ] {
        sqlx::query(sql)
            .execute(&pool)
            .await
            .map_err(|e| format!("migration error: {e}"))?;
    }

    // Create admin user
    let user_id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    sqlx::query(
        "INSERT OR REPLACE INTO users (id, username, password_hash, totp_enabled, totp_secret, auth_provider, created_at) VALUES (?1, ?2, ?3, ?4, ?5, 'local', ?6)",
    )
    .bind(&user_id)
    .bind(&config.admin_username)
    .bind(&config.admin_password_hash)
    .bind(config.totp_enabled)
    .bind(if config.totp_enabled { Some(&config.totp_secret) } else { None })
    .bind(&now)
    .execute(&pool)
    .await
    .map_err(|e| format!("user creation error: {e}"))?;

    // Save recovery codes (hashed)
    for code in &config.recovery_codes {
        let code_hash = hash_for_db(code).map_err(|e| format!("recovery code hash: {e}"))?;
        sqlx::query(
            "INSERT INTO recovery_codes (id, user_id, code_hash, used) VALUES (?1, ?2, ?3, 0)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(&user_id)
        .bind(&code_hash)
        .execute(&pool)
        .await
        .map_err(|e| format!("recovery code error: {e}"))?;
    }

    // Save auth config
    sqlx::query("INSERT OR REPLACE INTO auth_config (key, value) VALUES ('require_totp', ?1)")
        .bind(if config.totp_enabled { "true" } else { "false" })
        .execute(&pool)
        .await
        .map_err(|e| format!("config error: {e}"))?;

    // Auto-size memory caches based on detected RAM
    let ram = config.ram_mb;
    let (ids_alert_mb, dashboard_history_secs) = match ram {
        0..=1024 => (16, 900),       // 1 GB:  16 MB alerts, 15 min history
        1025..=2048 => (32, 1800),   // 2 GB:  32 MB alerts, 30 min history
        2049..=4096 => (48, 1800),   // 4 GB:  48 MB alerts, 30 min history
        4097..=8192 => (64, 3600),   // 8 GB:  64 MB alerts, 60 min history
        8193..=16384 => (128, 3600), // 16 GB: 128 MB alerts, 60 min history
        _ => (256, 7200),            // 32+ GB: 256 MB alerts, 2 hr history
    };
    console::info(&format!(
        "RAM: {} MB — IDS alert buffer: {} MB, dashboard history: {}s",
        ram, ids_alert_mb, dashboard_history_secs
    ));
    let cache_settings = [
        ("ids_alert_max_mb", ids_alert_mb.to_string()),
        ("ids_alert_max_age_secs", "86400".to_string()),
        (
            "dashboard_history_seconds",
            dashboard_history_secs.to_string(),
        ),
    ];
    for (key, value) in &cache_settings {
        sqlx::query("INSERT OR REPLACE INTO auth_config (key, value) VALUES (?1, ?2)")
            .bind(key)
            .bind(value)
            .execute(&pool)
            .await
            .map_err(|e| format!("cache config error: {e}"))?;
    }

    // Seed firewall rules based on chosen policy
    seed_default_rules(&pool, config).await?;

    // Seed interface roles (WAN/LAN descriptions)
    sqlx::query(aifw_common::schemas::INTERFACE_ROLES_CREATE)
        .execute(&pool)
        .await
        .map_err(|e| format!("interface_roles table: {e}"))?;

    let now = chrono::Utc::now().to_rfc3339();
    warn_on_err(
        "seed WAN interface role",
        sqlx::query("INSERT OR REPLACE INTO interface_roles (interface_name, role, updated_at) VALUES (?1, 'WAN', ?2)")
            .bind(&config.wan_interface).bind(&now).execute(&pool).await,
    );
    if let Some(ref lan) = config.lan_interface {
        warn_on_err(
            "seed LAN interface role",
            sqlx::query("INSERT OR REPLACE INTO interface_roles (interface_name, role, updated_at) VALUES (?1, 'LAN', ?2)")
                .bind(lan).bind(&now).execute(&pool).await,
        );
    }

    // Seed DNS resolver config — rDNS enabled by default with forwarding to user's DNS servers
    sqlx::query(aifw_common::schemas::DNS_RESOLVER_CONFIG_CREATE)
        .execute(&pool)
        .await
        .map_err(|e| format!("dns config table: {e}"))?;

    let dns_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM dns_resolver_config")
        .fetch_one(&pool)
        .await
        .map_err(|e| format!("dns count: {e}"))?;
    if dns_count.0 == 0 {
        let dns_defaults = [
            ("backend", "rdns"),
            ("enabled", "true"),
            ("port", "53"),
            ("dnssec", "false"),
            ("forwarding_enabled", "true"),
            ("use_system_nameservers", "true"),
            ("log_queries", "false"),
            ("prefetch", "true"),
            ("hide_identity", "true"),
            ("hide_version", "true"),
            ("rebind_protection", "true"),
        ];
        for (k, v) in &dns_defaults {
            warn_on_err(
                &format!("seed dns config {k}"),
                sqlx::query(
                    "INSERT OR IGNORE INTO dns_resolver_config (key, value) VALUES (?1, ?2)",
                )
                .bind(k)
                .bind(v)
                .execute(&pool)
                .await,
            );
        }
        // Forward to user's configured DNS servers
        if !config.dns_servers.is_empty() {
            warn_on_err(
                "seed dns forwarding servers",
                sqlx::query("INSERT OR IGNORE INTO dns_resolver_config (key, value) VALUES ('forwarding_servers', ?1)")
                    .bind(config.dns_servers.join(",")).execute(&pool).await,
            );
        }
    }

    // Write default rDNS config file and enable service
    let fwd_servers = config
        .dns_servers
        .iter()
        .map(|s| format!("\"{s}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let rdns_conf = format!(
        r#"# AiFw rDNS Configuration — Generated by setup wizard

[server]
mode = "resolver"
user = "rdns"
group = "rdns"
pidfile = "/dev/null"

[listeners]
udp = ["0.0.0.0:53"]
tcp = ["0.0.0.0:53"]

[cache]
max_entries = 1000000
max_ttl = 86400
min_ttl = 60
negative_ttl = 300

[resolver]
forwarders = [{fwd}]
dnssec = false
qname_minimization = true

[authoritative]
source = "none"

[control]
socket = "/var/run/rdns/control.sock"

[metrics]
enabled = true
address = "127.0.0.1:9153"

[logging]
level = "info"
format = "text"

[security]
sandbox = false
rate_limit = 1000
"#,
        fwd = fwd_servers
    );

    warn_on_err(
        "mkdir /usr/local/etc/rdns",
        std::fs::create_dir_all("/usr/local/etc/rdns"),
    );
    warn_on_err(
        "write rdns.toml",
        std::fs::write("/usr/local/etc/rdns/rdns.toml", &rdns_conf),
    );

    // Enable rDNS at boot
    #[cfg(target_os = "freebsd")]
    {
        run_best_effort("sysrc", &["rdns_enable=YES"]);
        // Disable unbound to avoid port conflict
        run_best_effort("sysrc", &["local_unbound_enable=NO"]);
    }

    // Seed DNS ACL entries — allow LAN subnet and localhost
    sqlx::query(aifw_common::schemas::DNS_ACCESS_LISTS_CREATE)
        .execute(&pool)
        .await
        .map_err(|e| format!("dns acl table: {e}"))?;

    let acl_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM dns_access_lists")
        .fetch_one(&pool)
        .await
        .map_err(|e| format!("acl count: {e}"))?;
    if acl_count.0 == 0 {
        let now = chrono::Utc::now().to_rfc3339();
        // Allow localhost
        warn_on_err(
            "seed localhost dns acl",
            sqlx::query("INSERT INTO dns_access_lists (id, network, action, description, created_at) VALUES (?1, '127.0.0.0/8', 'allow', 'Localhost', ?2)")
                .bind(uuid::Uuid::new_v4().to_string()).bind(&now).execute(&pool).await,
        );
        // Allow LAN subnet if configured
        if let Some(ref lip) = config.lan_ip {
            let octets: Vec<&str> = lip
                .split('/')
                .next()
                .unwrap_or("192.168.1.1")
                .split('.')
                .collect();
            if octets.len() == 4 {
                let subnet = format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
                warn_on_err(
                    "seed lan dns acl",
                    sqlx::query("INSERT INTO dns_access_lists (id, network, action, description, created_at) VALUES (?1, ?2, 'allow', 'LAN subnet', ?3)")
                        .bind(uuid::Uuid::new_v4().to_string()).bind(&subnet).bind(&now).execute(&pool).await,
                );
            }
        }
    }

    // Seed DHCP server config if enabled
    if config.dhcp_enabled
        && let Some(ref lan_cidr) = config.lan_ip
    {
        seed_dhcp_config(&pool, config, lan_cidr).await?;
    }

    // Bootstrap HA cluster DB rows and push pf anchor rules
    if let Some(c) = &config.cluster {
        // Generate a loopback API key so the daemon background tasks
        // (RoleWatcher, HealthProber, ClusterReplicator) can authenticate to
        // the local API. The key is stored in `api_keys` and the plaintext is
        // written to rc.conf via aifw_daemon_env so the rc.d start script
        // passes AIFW_LOOPBACK_API_KEY to the daemon process.
        //
        // Schema is sourced from aifw_common::schemas (QUAL-C5) so the
        // wizard and aifw-api's migrate can't drift.
        sqlx::query(aifw_common::schemas::API_KEYS_CREATE)
            .execute(&pool)
            .await
            .map_err(|e| format!("api_keys table: {e}"))?;

        // Two simple-format UUIDs = 64 hex chars of entropy.
        let loopback_key = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        // prefix: first 12 chars — matches the fast-lookup path in verify_api_key.
        let loopback_prefix = loopback_key[..12].to_string();
        // Hash with Argon2id (same algorithm as hash_password in aifw-api/src/auth/password.rs).
        let loopback_key_hash =
            hash_for_db(&loopback_key).map_err(|e| format!("loopback key hash: {e}"))?;

        // Delete any pre-existing loopback key so re-running setup always yields
        // a fresh credential. The daemon must be restarted after re-running setup
        // to pick up the new key from rc.conf.
        warn_on_err(
            "clear stale loopback api key",
            sqlx::query("DELETE FROM api_keys WHERE name = 'aifw-daemon-loopback'")
                .execute(&pool)
                .await,
        );

        sqlx::query(
            "INSERT INTO api_keys (id, name, key_hash, prefix, user_id, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind("aifw-daemon-loopback")
        .bind(&loopback_key_hash)
        .bind(&loopback_prefix)
        .bind(&user_id)
        .bind(chrono::Utc::now().to_rfc3339())
        .execute(&pool)
        .await
        .map_err(|e| format!("loopback api_key insert: {e}"))?;

        // Write the loopback key to a 640 file owned root:aifw rather than
        // embedding it in /etc/rc.conf (which is mode 644, world-readable on
        // FreeBSD). The rc.d aifw_daemon precmd reads this file and exports
        // AIFW_LOOPBACK_API_KEY into the daemon's environment.
        let key_path = std::path::Path::new("/usr/local/etc/aifw/daemon.key");
        if let Some(parent) = key_path.parent() {
            warn_on_err(
                &format!("mkdir {}", parent.display()),
                std::fs::create_dir_all(parent),
            );
        }
        if let Err(e) = std::fs::write(key_path, &loopback_key) {
            tracing::warn!(error = %e, "could not write daemon.key (non-FreeBSD dev env — skipped)");
        } else {
            // chmod 640
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Ok(meta) = std::fs::metadata(key_path) {
                    let mut perms = meta.permissions();
                    perms.set_mode(0o640);
                    warn_on_err(
                        "chmod daemon api key to 0600",
                        std::fs::set_permissions(key_path, perms),
                    );
                }
            }
            // chown root:aifw — only meaningful on FreeBSD where the aifw user exists.
            #[cfg(target_os = "freebsd")]
            {
                run_best_effort("chown", &["root:aifw", "/usr/local/etc/aifw/daemon.key"]);
            }
        }
        // Clear any previously set aifw_daemon_env from rc.conf — the key is
        // now read from daemon.key by the precmd; rc.conf no longer carries it.
        #[cfg(target_os = "freebsd")]
        warn_on_err("", run_sysrc("aifw_daemon_env", ""));

        let pf: std::sync::Arc<dyn aifw_pf::PfBackend> =
            std::sync::Arc::from(aifw_pf::create_backend());
        let cluster_engine = aifw_core::ClusterEngine::new(pool.clone(), pf);
        cluster_engine
            .migrate()
            .await
            .map_err(|e| format!("ha migrate: {e}"))?;

        // pfsync singleton row
        let pfsync = PfsyncConfig::new(Interface(c.pfsync_iface.clone()));
        cluster_engine
            .set_pfsync(pfsync)
            .await
            .map_err(|e| format!("ha set_pfsync: {e}"))?;

        // CARP VIPs
        for v in &c.vips {
            let vip = CarpVip::new(
                v.vhid,
                v.virtual_ip,
                v.prefix,
                Interface(v.interface.clone()),
                c.password.clone(),
            );
            cluster_engine
                .add_carp_vip(vip)
                .await
                .map_err(|e| format!("ha add_carp_vip: {e}"))?;
        }

        // Self node row
        let self_role = c.role;
        let peer_role = match self_role {
            ClusterRole::Primary => ClusterRole::Secondary,
            ClusterRole::Secondary => ClusterRole::Primary,
            ClusterRole::Standalone => {
                return Err("standalone role cannot be configured with a cluster peer".to_string());
            }
        };
        // LAN IP is required when configuring a cluster — 127.0.0.1 would be
        // silently wrong and mislead the peer reachability check.
        let self_addr = config
            .lan_ip
            .as_ref()
            .and_then(|ip| ip.split('/').next())
            .and_then(|s| s.parse::<std::net::IpAddr>().ok())
            .ok_or_else(|| "HA cluster setup requires a configured LAN IP".to_string())?;
        // Resolve hostname via `hostname` command (avoids needing the nix
        // "hostname" feature; works on both FreeBSD and Linux dev environments)
        let self_name = std::process::Command::new("hostname")
            .output()
            .ok()
            .and_then(|o| {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if s.is_empty() { None } else { Some(s) }
            })
            .unwrap_or_else(|| config.hostname.clone());
        cluster_engine
            .add_node(ClusterNode::new(self_name, self_addr, self_role))
            .await
            .map_err(|e| format!("ha add_node self: {e}"))?;
        cluster_engine
            .add_node(ClusterNode::new(
                format!("peer-{}", c.peer_address),
                c.peer_address,
                peer_role,
            ))
            .await
            .map_err(|e| format!("ha add_node peer: {e}"))?;

        // Render HA rules into the pf anchor
        cluster_engine
            .apply_ha_rules()
            .await
            .map_err(|e| format!("ha apply_ha_rules: {e}"))?;

        // Apply runtime kernel state too — recover_kernel_state_for_role
        // owns the carp.preempt sysctl now that apply_ha_rules is pure-pf.
        cluster_engine
            .recover_kernel_state_for_role(c.role)
            .await
            .map_err(|e| format!("ha recover_kernel_state_for_role: {e}"))?;

        // Seed minimal default health checks so the HealthProber daemon task
        // has something to probe out of the box.  Failures are warn-only so a
        // duplicate-name conflict (re-running setup) never blocks setup completion.
        for h in [
            aifw_common::HealthCheck::new(
                "aifw_api".into(),
                aifw_common::HealthCheckType::TcpPort,
                "127.0.0.1:8080".into(),
            ),
            aifw_common::HealthCheck::new(
                "pf".into(),
                aifw_common::HealthCheckType::PfStatus,
                String::new(),
            ),
            aifw_common::HealthCheck::new(
                "aifw_daemon".into(),
                aifw_common::HealthCheckType::ProcessRunning,
                "aifw-daemon".into(),
            ),
            aifw_common::HealthCheck::new(
                "aifw_ids".into(),
                aifw_common::HealthCheckType::ProcessRunning,
                "aifw-ids".into(),
            ),
        ] {
            if let Err(e) = cluster_engine.add_health_check(h.clone()).await {
                tracing::warn!(
                    ?e,
                    name = %h.name,
                    "ha: failed to seed default health check (continuing)"
                );
            }
        }
    }

    Ok(())
}

pub(super) async fn seed_dhcp_config(
    pool: &sqlx::SqlitePool,
    config: &SetupConfig,
    lan_cidr: &str,
) -> Result<(), String> {
    // Parse LAN IP: "192.168.1.1/24" -> ip=192.168.1.1, prefix=24
    let parts: Vec<&str> = lan_cidr.split('/').collect();
    let lan_ip = parts[0];
    let octets: Vec<&str> = lan_ip.split('.').collect();
    if octets.len() != 4 {
        return Ok(());
    }
    let base = format!("{}.{}.{}", octets[0], octets[1], octets[2]);
    let network = format!("{}.0/24", base);
    let pool_start = format!("{}.20", base);
    let pool_end = format!("{}.219", base);
    let gateway = lan_ip.to_string();

    // Create DHCP config table — schema shared via aifw_common::schemas
    sqlx::query(aifw_common::schemas::DHCP_CONFIG_CREATE)
        .execute(pool)
        .await
        .map_err(|e| format!("dhcp config table: {e}"))?;

    let dhcp_defaults = [
        ("enabled", "true"),
        ("authoritative", "true"),
        ("default_lease_time", "3600"),
        ("max_lease_time", "86400"),
        ("log_level", "info"),
        ("log_format", "text"),
        ("api_port", "9967"),
        ("workers", "1"),
        ("domain_name", "local"),
    ];
    for (k, v) in &dhcp_defaults {
        warn_on_err(
            &format!("seed dhcp config {k}"),
            sqlx::query("INSERT OR IGNORE INTO dhcp_config (key, value) VALUES (?1, ?2)")
                .bind(k)
                .bind(v)
                .execute(pool)
                .await,
        );
    }
    // Bind to LAN interface
    if let Some(ref li) = config.lan_interface {
        warn_on_err(
            "seed dhcp interfaces",
            sqlx::query("INSERT OR IGNORE INTO dhcp_config (key, value) VALUES ('interfaces', ?1)")
                .bind(li)
                .execute(pool)
                .await,
        );
    }
    // DNS for scope = LAN IP (rDNS is on the firewall)
    warn_on_err(
        "seed dhcp dns_servers",
        sqlx::query("INSERT OR IGNORE INTO dhcp_config (key, value) VALUES ('dns_servers', ?1)")
            .bind(lan_ip)
            .execute(pool)
            .await,
    );

    // Create subnets table and default pool
    sqlx::query(r#"CREATE TABLE IF NOT EXISTS dhcp_subnets (
        id TEXT PRIMARY KEY, network TEXT NOT NULL, pool_start TEXT NOT NULL, pool_end TEXT NOT NULL,
        gateway TEXT NOT NULL, dns_servers TEXT, domain_name TEXT,
        lease_time INTEGER, max_lease_time INTEGER, renewal_time INTEGER, rebinding_time INTEGER,
        preferred_time INTEGER, subnet_type TEXT NOT NULL DEFAULT 'address',
        delegated_length INTEGER, enabled INTEGER NOT NULL DEFAULT 1,
        description TEXT, created_at TEXT NOT NULL
    )"#).execute(pool).await.map_err(|e| format!("dhcp subnets table: {e}"))?;

    let now = chrono::Utc::now().to_rfc3339();
    let id = uuid::Uuid::new_v4().to_string();
    sqlx::query(
        "INSERT INTO dhcp_subnets (id, network, pool_start, pool_end, gateway, dns_servers, domain_name, \
         lease_time, subnet_type, enabled, description, created_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'local', 3600, 'address', 1, 'Default LAN pool', ?7)"
    )
    .bind(&id).bind(&network).bind(&pool_start).bind(&pool_end)
    .bind(&gateway).bind(lan_ip).bind(&now)
    .execute(pool).await.map_err(|e| format!("seed dhcp subnet: {e}"))?;

    // Write rDHCP config file
    let iface_name = config.lan_interface.as_deref().unwrap_or("em1");
    let rdhcp_conf = format!(
        r#"# rDHCP configuration — generated by AiFw setup wizard

[global]
log_level = "info"
log_format = "text"
lease_db = "/var/db/rdhcpd/leases"
workers = 1
interfaces = ["{iface}"]

[api]
listen = "127.0.0.1:9967"

[ha]
mode = "standalone"

[[subnet]]
network = "{network}"
pool_start = "{pool_start}"
pool_end = "{pool_end}"
lease_time = 3600
router = "{gw}"
dns = ["{dns}"]
domain = "local"

[ddns]
enabled = false
"#,
        iface = iface_name,
        network = network,
        pool_start = pool_start,
        pool_end = pool_end,
        gw = gateway,
        dns = lan_ip
    );

    warn_on_err(
        "mkdir /usr/local/etc/rdhcpd",
        std::fs::create_dir_all("/usr/local/etc/rdhcpd"),
    );
    warn_on_err(
        "mkdir /var/db/rdhcpd/leases",
        std::fs::create_dir_all("/var/db/rdhcpd/leases"),
    );
    warn_on_err(
        "mkdir /var/log/rdhcpd",
        std::fs::create_dir_all("/var/log/rdhcpd"),
    );
    warn_on_err(
        "write rdhcpd config.toml",
        std::fs::write("/usr/local/etc/rdhcpd/config.toml", &rdhcp_conf),
    );

    // Enable rDHCP at boot
    #[cfg(target_os = "freebsd")]
    {
        run_best_effort("sysrc", &["rdhcpd_enable=YES"]);
    }

    Ok(())
}

pub(super) async fn seed_default_rules(
    pool: &sqlx::SqlitePool,
    config: &SetupConfig,
) -> Result<(), String> {
    use crate::config::DefaultPolicy;

    // Create rules table if not exists (same schema as aifw-core)
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS rules (
            id TEXT PRIMARY KEY, priority INTEGER NOT NULL DEFAULT 100,
            action TEXT NOT NULL, direction TEXT NOT NULL, interface TEXT,
            protocol TEXT NOT NULL, src_addr TEXT NOT NULL,
            src_port_start INTEGER, src_port_end INTEGER,
            dst_addr TEXT NOT NULL, dst_port_start INTEGER, dst_port_end INTEGER,
            log INTEGER NOT NULL DEFAULT 0, quick INTEGER NOT NULL DEFAULT 1,
            label TEXT, state_tracking TEXT NOT NULL DEFAULT 'keep_state',
            state_policy TEXT, adaptive_start INTEGER, adaptive_end INTEGER,
            timeout_tcp INTEGER, timeout_udp INTEGER, timeout_icmp INTEGER,
            status TEXT NOT NULL DEFAULT 'active',
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL, schedule_id TEXT
        )"#,
    )
    .execute(pool)
    .await
    .map_err(|e| format!("rules table: {e}"))?;

    // Skip if rules already exist
    let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM rules")
        .fetch_one(pool)
        .await
        .map_err(|e| format!("count: {e}"))?;
    if count.0 > 0 {
        return Ok(());
    }

    let now = chrono::Utc::now().to_rfc3339();
    let wan = &config.wan_interface;
    let lan = config.lan_interface.as_deref();

    // Derive LAN subnet from LAN IP (e.g. 192.168.1.1/24 -> 192.168.1.0/24)
    let lan_subnet = config.lan_ip.as_ref().map(|ip| {
        let host = ip.split('/').next().unwrap_or("192.168.1.1");
        let prefix = ip.split('/').nth(1).unwrap_or("24");
        let octets: Vec<&str> = host.split('.').collect();
        if octets.len() == 4 {
            format!("{}.{}.{}.0/{}", octets[0], octets[1], octets[2], prefix)
        } else {
            ip.clone()
        }
    });

    // Helper to insert a rule
    async fn ins(
        pool: &sqlx::SqlitePool,
        pri: i32,
        action: &str,
        dir: &str,
        iface: Option<&str>,
        proto: &str,
        src: &str,
        dst_port: Option<u16>,
        log: bool,
        label: &str,
        now: &str,
    ) -> Result<(), String> {
        let id = uuid::Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO rules (id, priority, action, direction, interface, protocol, src_addr, \
             src_port_start, src_port_end, dst_addr, dst_port_start, dst_port_end, \
             log, quick, label, state_tracking, status, created_at, updated_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,NULL,NULL,'any',?8,?9,?10,1,?11,'keep_state','active',?12,?13)"
        )
        .bind(&id).bind(pri).bind(action).bind(dir).bind(iface)
        .bind(proto).bind(src)
        .bind(dst_port.map(|p| p as i64)).bind(dst_port.map(|p| p as i64))
        .bind(log).bind(label).bind(now).bind(now)
        .execute(pool).await.map_err(|e| format!("seed rule: {e}"))?;
        Ok(())
    }

    match config.default_policy {
        DefaultPolicy::Standard => {
            // Outbound: allow all out on both interfaces
            ins(
                pool,
                1,
                "pass",
                "out",
                Some(wan),
                "any",
                "any",
                None,
                false,
                "Allow outbound (WAN)",
                &now,
            )
            .await?;
            if let Some(li) = lan {
                ins(
                    pool,
                    2,
                    "pass",
                    "out",
                    Some(li),
                    "any",
                    "any",
                    None,
                    false,
                    "Allow outbound (LAN)",
                    &now,
                )
                .await?;
            }
            // LAN inbound: only from configured LAN subnet
            if let Some(ref subnet) = lan_subnet {
                ins(
                    pool,
                    3,
                    "pass",
                    "in",
                    lan,
                    "any",
                    subnet,
                    None,
                    false,
                    "Allow LAN subnet",
                    &now,
                )
                .await?;
            }
            // DHCP on LAN (src is 0.0.0.0 for discovery, must allow from any)
            if config.dhcp_enabled
                && let Some(li) = lan
            {
                ins(
                    pool,
                    4,
                    "pass",
                    "in",
                    Some(li),
                    "udp",
                    "any",
                    Some(67),
                    false,
                    "Allow DHCP server (LAN)",
                    &now,
                )
                .await?;
                ins(
                    pool,
                    5,
                    "pass",
                    "in",
                    Some(li),
                    "udp",
                    "any",
                    Some(68),
                    false,
                    "Allow DHCP client (LAN)",
                    &now,
                )
                .await?;
            }
            // Management: SSH + Web UI from LAN subnet only
            let mgmt_src = lan_subnet.as_deref().unwrap_or("any");
            ins(
                pool,
                20,
                "pass",
                "in",
                None,
                "tcp",
                mgmt_src,
                Some(22),
                false,
                "Allow SSH (LAN)",
                &now,
            )
            .await?;
            ins(
                pool,
                21,
                "pass",
                "in",
                None,
                "tcp",
                mgmt_src,
                Some(config.api_port),
                false,
                "Allow AiFw Web UI (LAN)",
                &now,
            )
            .await?;
            // ICMP from LAN subnet
            ins(
                pool,
                10,
                "pass",
                "in",
                None,
                "icmp",
                mgmt_src,
                None,
                false,
                "Allow ICMP (LAN)",
                &now,
            )
            .await?;
            // Block all inbound (WAN + anything else)
            ins(
                pool,
                1000,
                "block",
                "in",
                None,
                "any",
                "any",
                None,
                true,
                "Default block inbound",
                &now,
            )
            .await?;
        }
        DefaultPolicy::Strict => {
            // Only SSH + Web UI on WAN, block everything else
            ins(
                pool,
                20,
                "pass",
                "in",
                Some(wan),
                "tcp",
                "any",
                Some(22),
                false,
                "Allow SSH (WAN)",
                &now,
            )
            .await?;
            ins(
                pool,
                21,
                "pass",
                "in",
                Some(wan),
                "tcp",
                "any",
                Some(config.api_port),
                false,
                "Allow AiFw Web UI (WAN)",
                &now,
            )
            .await?;
            ins(
                pool,
                1000,
                "block",
                "any",
                None,
                "any",
                "any",
                None,
                true,
                "Default block all",
                &now,
            )
            .await?;
        }
        DefaultPolicy::Permissive => {
            ins(
                pool,
                1,
                "pass",
                "any",
                None,
                "any",
                "any",
                None,
                false,
                "Allow all (permissive)",
                &now,
            )
            .await?;
        }
    }

    // Seed NAT rules if NAT is enabled (LAN behind WAN)
    if config.nat_enabled {
        sqlx::query(
            r#"CREATE TABLE IF NOT EXISTS nat_rules (
                id TEXT PRIMARY KEY, nat_type TEXT NOT NULL, interface TEXT NOT NULL,
                protocol TEXT NOT NULL, src_addr TEXT NOT NULL,
                src_port_start INTEGER, src_port_end INTEGER,
                dst_addr TEXT NOT NULL, dst_port_start INTEGER, dst_port_end INTEGER,
                redirect_addr TEXT NOT NULL, redirect_port_start INTEGER, redirect_port_end INTEGER,
                label TEXT, status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL, updated_at TEXT NOT NULL
            )"#,
        )
        .execute(pool)
        .await
        .map_err(|e| format!("nat table: {e}"))?;

        let nat_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM nat_rules")
            .fetch_one(pool)
            .await
            .map_err(|e| format!("nat count: {e}"))?;
        if nat_count.0 == 0 {
            let id = uuid::Uuid::new_v4().to_string();
            let src = if let Some(ref _li) = config.lan_interface {
                // Use LAN subnet if we have a LAN IP (e.g. 192.168.1.1 -> 192.168.1.0/24)
                if let Some(ref lip) = config.lan_ip {
                    let parts: Vec<&str> = lip.split('.').collect();
                    if parts.len() == 4 {
                        format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2])
                    } else {
                        "any".to_string()
                    }
                } else {
                    "any".to_string()
                }
            } else {
                "any".to_string()
            };

            sqlx::query(
                "INSERT INTO nat_rules (id, nat_type, interface, protocol, src_addr, \
                 src_port_start, src_port_end, dst_addr, dst_port_start, dst_port_end, \
                 redirect_addr, redirect_port_start, redirect_port_end, \
                 label, status, created_at, updated_at) \
                 VALUES (?1,'masquerade',?2,'any',?3,NULL,NULL,'any',NULL,NULL,'any',NULL,NULL,?4,'active',?5,?6)"
            )
            .bind(&id).bind(wan).bind(&src).bind("Default Outbound NAT").bind(&now).bind(&now)
            .execute(pool).await.map_err(|e| format!("seed nat: {e}"))?;
        }
    }

    Ok(())
}

/// Hash a secret for storage in `aifw.db` using the workspace-pinned
/// Argon2id parameters (SEC-M4 #301). Errors surface to the caller instead
/// of silently storing an empty hash that can never verify.
pub(super) fn hash_for_db(secret: &str) -> Result<String, String> {
    aifw_common::password::hash_password(secret).map_err(|e| e.to_string())
}
