use crate::config::{DefaultPolicy, SetupConfig};
use crate::console;
use crate::tuning::{self, TuningItem};

/// Apply the setup configuration: write files, init DB, start services
pub async fn apply(config: &SetupConfig, tuning_items: &[TuningItem]) -> Result<(), String> {
    console::header("Applying Configuration");

    // 1. Create directories
    console::info("Creating directories...");
    create_dirs(config)?;
    console::success("Directories created");

    // 2. Write config file
    console::info("Writing configuration file...");
    write_config_file(config)?;
    console::success(&format!("Config written to {}/aifw.conf", config.config_dir));

    // 3. Initialize database
    console::info("Initializing database...");
    init_database(config).await?;
    console::success(&format!("Database initialized at {}", config.db_path));

    // 4. Generate pf rules
    console::info("Generating pf ruleset...");
    let pf_rules = generate_pf_conf(config);
    write_file(&format!("{}/pf.conf.aifw", config.config_dir), &pf_rules)?;
    console::success("pf ruleset generated");

    // 5. Write rc.d scripts
    console::info("Installing service scripts...");
    write_rcd_scripts(config)?;
    console::success("Service scripts installed");

    // 6. Write tuning files
    let enabled_tunings = tuning_items.iter().filter(|t| t.enabled).count();
    if enabled_tunings > 0 {
        console::info("Writing kernel tuning files...");

        let sysctl_conf = tuning::generate_sysctl_conf(tuning_items);
        if !sysctl_conf.lines().filter(|l| l.contains('=')).count() == 0 {
            write_file("/etc/sysctl.conf.aifw", &sysctl_conf)?;
            console::success("sysctl.conf.aifw written");
        }

        let loader_conf = tuning::generate_loader_conf(tuning_items);
        if !loader_conf.lines().filter(|l| l.contains('=')).count() == 0 {
            write_file("/boot/loader.conf.aifw", &loader_conf)?;
            console::success("loader.conf.aifw written");
        }

        let nic_cmds = tuning::generate_nic_commands(tuning_items);
        if !nic_cmds.is_empty() {
            let script = nic_cmds.join("\n");
            write_file(&format!("{}/nic_tuning.sh", config.config_dir), &script)?;
            console::success(&format!("{} NIC tuning commands written", nic_cmds.len()));
        }

        let modules = tuning::kernel_modules_to_load(tuning_items);
        if !modules.is_empty() {
            console::success(&format!("Kernel modules to load: {}", modules.join(", ")));
        }

        console::success(&format!("{enabled_tunings} kernel/network tunings applied"));
    }

    // 7. Write resolv.conf
    if !config.dns_servers.is_empty() {
        console::info("Configuring DNS...");
        let resolv: Vec<String> = config.dns_servers.iter().map(|s| format!("nameserver {s}")).collect();
        write_file("/etc/resolv.conf.aifw", &resolv.join("\n"))?;
        console::success("DNS configured");
    }

    console::header("Setup Complete");
    console::success(&format!("AiFw is configured on {}", config.hostname));
    console::info("");
    console::info(&format!("  API:      http://{}:{}/api/v1/", config.api_listen, config.api_port));
    if config.ui_enabled {
        console::info(&format!("  Web UI:   http://{}:3000/", config.api_listen));
    }
    console::info(&format!("  Admin:    {}", config.admin_username));
    console::info(&format!("  MFA:      {}", if config.totp_enabled { "enabled" } else { "disabled" }));
    console::info("");
    console::info("To start services:");
    console::info("  service aifw_daemon start");
    console::info("  service aifw_api start");
    console::info("");
    console::info("To apply pf rules:");
    console::info(&format!("  pfctl -f {}/pf.conf.aifw", config.config_dir));
    console::info("");

    Ok(())
}

fn create_dirs(config: &SetupConfig) -> Result<(), String> {
    for dir in [&config.config_dir, "/var/db/aifw", "/var/log/aifw"] {
        std::fs::create_dir_all(dir).map_err(|e| format!("failed to create {dir}: {e}"))?;
    }
    Ok(())
}

fn write_file(path: &str, content: &str) -> Result<(), String> {
    std::fs::write(path, content).map_err(|e| format!("failed to write {path}: {e}"))
}

fn write_config_file(config: &SetupConfig) -> Result<(), String> {
    let json = serde_json::to_string_pretty(config)
        .map_err(|e| format!("serialize error: {e}"))?;
    write_file(&format!("{}/aifw.conf", config.config_dir), &json)
}

/// Initialize the SQLite database and create the admin user
async fn init_database(config: &SetupConfig) -> Result<(), String> {
    let db = aifw_core::Database::new(std::path::Path::new(&config.db_path))
        .await
        .map_err(|e| format!("db init error: {e}"))?;

    let pool = db.pool().clone();

    // Run auth migrations
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
            totp_enabled INTEGER NOT NULL DEFAULT 0, totp_secret TEXT,
            auth_provider TEXT NOT NULL DEFAULT 'local', created_at TEXT NOT NULL
        )"#,
    )
    .execute(&pool)
    .await
    .map_err(|e| format!("migration error: {e}"))?;

    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS recovery_codes (
            id TEXT PRIMARY KEY, user_id TEXT NOT NULL, code_hash TEXT NOT NULL,
            used INTEGER NOT NULL DEFAULT 0
        )"#,
    )
    .execute(&pool)
    .await
    .map_err(|e| format!("migration error: {e}"))?;

    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS auth_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)"#,
    )
    .execute(&pool)
    .await
    .map_err(|e| format!("migration error: {e}"))?;

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
        let code_hash = hash_for_db(code);
        sqlx::query("INSERT INTO recovery_codes (id, user_id, code_hash, used) VALUES (?1, ?2, ?3, 0)")
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

    Ok(())
}

fn hash_for_db(password: &str) -> String {
    use argon2::{Argon2, PasswordHasher, password_hash::SaltString, password_hash::rand_core::OsRng};
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default().hash_password(password.as_bytes(), &salt).map(|h| h.to_string()).unwrap_or_default()
}

/// Generate a pf.conf based on the setup configuration
pub fn generate_pf_conf(config: &SetupConfig) -> String {
    let mut lines = Vec::new();

    lines.push("# AiFw — Generated pf.conf".to_string());
    lines.push(format!("# Generated by aifw-setup on {}", chrono::Utc::now().to_rfc3339()));
    lines.push(String::new());

    // Macros
    lines.push(format!("wan_if = \"{}\"", config.wan_interface));
    if let Some(ref lan) = config.lan_interface {
        lines.push(format!("lan_if = \"{lan}\""));
    }
    if let Some(ref ip) = config.lan_ip {
        let net = ip.split('/').next().unwrap_or("192.168.1.0");
        let prefix = ip.split('/').nth(1).unwrap_or("24");
        // Derive network from IP (simplified)
        lines.push(format!("lan_net = \"{net}/{prefix}\""));
    }
    lines.push(String::new());

    // Tables
    lines.push("# Tables for overload protection".to_string());
    lines.push("table <bruteforce> persist".to_string());
    lines.push("table <ai_blocked> persist".to_string());
    lines.push(String::new());

    // Options
    lines.push("# Options".to_string());
    lines.push("set skip on lo0".to_string());
    lines.push("set block-policy drop".to_string());
    lines.push("set optimization aggressive".to_string());
    lines.push("set state-policy if-bound".to_string());
    lines.push(String::new());

    // Scrub
    lines.push("# Normalization".to_string());
    lines.push("scrub in all".to_string());
    lines.push(String::new());

    // AiFw anchors
    lines.push("# AiFw managed anchors".to_string());
    lines.push("anchor \"aifw\"".to_string());
    lines.push("anchor \"aifw-nat\"".to_string());
    lines.push("anchor \"aifw-ratelimit\"".to_string());
    lines.push("anchor \"aifw-vpn\"".to_string());
    lines.push("anchor \"aifw-geoip\"".to_string());
    lines.push("anchor \"aifw-tls\"".to_string());
    lines.push("anchor \"aifw-ha\"".to_string());
    lines.push(String::new());

    // Default policy
    lines.push("# Default policy".to_string());
    match config.default_policy {
        DefaultPolicy::Standard => {
            lines.push("block in log all".to_string());
            lines.push("pass out all keep state".to_string());
        }
        DefaultPolicy::Strict => {
            lines.push("block log all".to_string());
        }
        DefaultPolicy::Permissive => {
            lines.push("pass all keep state".to_string());
        }
    }
    lines.push(String::new());

    // Anti-spoof
    lines.push("# Anti-spoofing".to_string());
    lines.push(format!("antispoof quick for $wan_if"));
    if config.lan_interface.is_some() {
        lines.push("antispoof quick for $lan_if".to_string());
    }
    lines.push(String::new());

    // Block overloaded IPs
    lines.push("# Overload block rules".to_string());
    lines.push("block in quick from <bruteforce>".to_string());
    lines.push("block in quick from <ai_blocked>".to_string());
    lines.push(String::new());

    // Allow ICMP
    lines.push("# ICMP".to_string());
    lines.push("pass in quick inet proto icmp icmp-type echoreq keep state".to_string());
    lines.push(String::new());

    // Allow API access
    lines.push("# AiFw API access".to_string());
    lines.push(format!("pass in quick proto tcp to any port {} keep state label \"aifw-api\"", config.api_port));
    lines.push(String::new());

    // LAN to WAN
    if config.lan_interface.is_some() {
        lines.push("# LAN to WAN".to_string());
        lines.push("pass in on $lan_if from $lan_net keep state".to_string());
        lines.push(String::new());

        // NAT for LAN
        lines.push("# NAT — LAN masquerade".to_string());
        lines.push("nat on $wan_if from $lan_net to any -> ($wan_if)".to_string());
        lines.push(String::new());
    }

    // Load AiFw managed rules
    lines.push("# Load AiFw managed rules".to_string());
    lines.push("load anchor \"aifw\" from \"/usr/local/etc/aifw/anchors/aifw\"".to_string());
    lines.push(String::new());

    lines.join("\n")
}

/// Write FreeBSD rc.d service scripts
fn write_rcd_scripts(config: &SetupConfig) -> Result<(), String> {
    let daemon_script = format!(r#"#!/bin/sh
# PROVIDE: aifw_daemon
# REQUIRE: NETWORKING pf
# KEYWORD: shutdown

. /etc/rc.subr

name="aifw_daemon"
rcvar="aifw_daemon_enable"
command="/usr/local/sbin/aifw-daemon"
command_args="--db {db} --log-level info"
pidfile="/var/run/${{name}}.pid"
start_cmd="${{name}}_start"

aifw_daemon_start()
{{
    /usr/sbin/daemon -p $pidfile -f $command $command_args
}}

load_rc_config $name
: ${{aifw_daemon_enable:="NO"}}
run_rc_command "$1"
"#, db = config.db_path);

    let api_script = format!(r#"#!/bin/sh
# PROVIDE: aifw_api
# REQUIRE: NETWORKING aifw_daemon
# KEYWORD: shutdown

. /etc/rc.subr

name="aifw_api"
rcvar="aifw_api_enable"
command="/usr/local/sbin/aifw-api"
command_args="--db {db} --listen {listen}:{port} --log-level info"
pidfile="/var/run/${{name}}.pid"
start_cmd="${{name}}_start"

aifw_api_start()
{{
    /usr/sbin/daemon -p $pidfile -f $command $command_args
}}

load_rc_config $name
: ${{aifw_api_enable:="NO"}}
run_rc_command "$1"
"#, db = config.db_path, listen = config.api_listen, port = config.api_port);

    // Write scripts (on non-FreeBSD just write to config dir)
    let rcd_dir = if std::path::Path::new("/usr/local/etc/rc.d").exists() {
        "/usr/local/etc/rc.d"
    } else {
        &config.config_dir
    };

    write_file(&format!("{rcd_dir}/aifw_daemon"), &daemon_script)?;
    write_file(&format!("{rcd_dir}/aifw_api"), &api_script)?;

    // Make executable
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        let _ = std::fs::set_permissions(format!("{rcd_dir}/aifw_daemon"), perms.clone());
        let _ = std::fs::set_permissions(format!("{rcd_dir}/aifw_api"), perms);
    }

    Ok(())
}

/// Generate pf rules for testing (non-FreeBSD)
#[cfg(test)]
pub mod tests_support {
    use super::*;
    use crate::config::SetupConfig;

    pub fn test_pf_conf() -> String {
        let config = SetupConfig {
            wan_interface: "em0".to_string(),
            lan_interface: Some("em1".to_string()),
            lan_ip: Some("192.168.1.1/24".to_string()),
            api_port: 8080,
            ..Default::default()
        };
        generate_pf_conf(&config)
    }
}
