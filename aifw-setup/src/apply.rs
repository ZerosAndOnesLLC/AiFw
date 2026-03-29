use crate::config::{DefaultPolicy, SetupConfig};
use crate::console;
use crate::tuning::{self, TuningItem};

/// Apply the setup configuration: write files, init DB, start services
pub async fn apply(config: &SetupConfig, tuning_items: &[TuningItem]) -> Result<(), String> {
    console::header("Applying Configuration");

    // 1. Create service user
    console::info("Creating aifw service user...");
    create_service_user()?;
    console::success("Service user ready");

    // 2. Create directories
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

    // 3b. Fix DB ownership (DB was created as root, aifw user needs write access)
    #[cfg(target_os = "freebsd")]
    {
        let _ = std::process::Command::new("chown").args(["-R", "aifw:aifw", "/var/db/aifw"]).output();
    }

    // 4. Generate pf rules
    console::info("Generating pf ruleset...");
    let pf_rules = generate_pf_conf(config);
    write_file(&format!("{}/pf.conf.aifw", config.config_dir), &pf_rules)?;
    // Create empty anchor files so pfctl doesn't error on load
    let anchors_dir = format!("{}/anchors", config.config_dir);
    std::fs::create_dir_all(&anchors_dir).map_err(|e| format!("failed to create anchors dir: {e}"))?;
    for anchor in ["aifw", "aifw-nat", "aifw-ratelimit", "aifw-vpn", "aifw-geoip", "aifw-tls", "aifw-ha"] {
        let path = format!("{anchors_dir}/{anchor}");
        if !std::path::Path::new(&path).exists() {
            write_file(&path, "# AiFw managed anchor\n")?;
        }
    }
    console::success("pf ruleset generated");

    // 5. Write rc.d scripts
    console::info("Installing service scripts...");
    write_rcd_scripts(config)?;
    console::success("Service scripts installed");

    // 5b. Grant aifw user sudo access to pfctl (no password)
    #[cfg(target_os = "freebsd")]
    {
        let sudoers_line = "\
aifw ALL=(ALL) NOPASSWD: /sbin/pfctl *\n\
aifw ALL=(ALL) NOPASSWD: /sbin/pfctl\n\
aifw ALL=(ALL) NOPASSWD: /usr/sbin/service *\n\
aifw ALL=(ALL) NOPASSWD: /usr/sbin/sysrc *\n\
aifw ALL=(ALL) NOPASSWD: /usr/sbin/pkg *\n\
aifw ALL=(ALL) NOPASSWD: /usr/sbin/freebsd-update *\n\
aifw ALL=(ALL) NOPASSWD: /sbin/shutdown *\n\
aifw ALL=(ALL) NOPASSWD: /bin/cat *\n\
aifw ALL=(ALL) NOPASSWD: /usr/local/sbin/kea-admin *\n";
        let sudoers_path = "/usr/local/etc/sudoers.d/aifw";
        if !std::path::Path::new(sudoers_path).exists() {
            let _ = std::fs::create_dir_all("/usr/local/etc/sudoers.d");
            let _ = std::fs::write(sudoers_path, sudoers_line);
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(sudoers_path, std::fs::Permissions::from_mode(0o440));
            }
        }
    }

    // 5c. Configure devfs rules for /dev/pf and /dev/bpf* access
    console::info("Configuring device permissions...");
    configure_devfs()?;
    console::success("Device permissions configured");

    // 5c. Generate self-signed TLS certificate
    console::info("Generating TLS certificate...");
    generate_tls_cert()?;
    console::success("TLS certificate generated");

    // 6. Write tuning files
    let enabled_tunings = tuning_items.iter().filter(|t| t.enabled).count();
    if enabled_tunings > 0 {
        console::info("Writing kernel tuning files...");

        let sysctl_conf = tuning::generate_sysctl_conf(tuning_items);
        if sysctl_conf.lines().filter(|l| l.contains('=')).count() > 0 {
            write_file("/etc/sysctl.conf.aifw", &sysctl_conf)?;
            console::success("sysctl.conf.aifw written");
        }

        let loader_conf = tuning::generate_loader_conf(tuning_items);
        if loader_conf.lines().filter(|l| l.contains('=')).count() > 0 {
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
    console::info(&format!("  Web UI:   https://{}:{}/", config.api_listen, config.api_port));
    console::info(&format!("  API:      https://{}:{}/api/v1/", config.api_listen, config.api_port));
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

/// Create the aifw service user and group if they don't exist
fn create_service_user() -> Result<(), String> {
    #[cfg(target_os = "freebsd")]
    {
        use std::process::Command;
        // Check if user already exists
        let status = Command::new("pw").args(["usershow", "aifw"]).output();
        if let Ok(out) = status {
            if out.status.success() {
                return Ok(()); // user exists
            }
        }
        // Create group
        let _ = Command::new("pw")
            .args(["groupadd", "aifw", "-g", "470"])
            .output();
        // Create user: no login shell, no home, system account
        let out = Command::new("pw")
            .args([
                "useradd", "aifw",
                "-u", "470",
                "-g", "aifw",
                "-d", "/nonexistent",
                "-s", "/usr/sbin/nologin",
                "-c", "AiFw Service Account",
            ])
            .output()
            .map_err(|e| format!("failed to create aifw user: {e}"))?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            // Ignore "already exists" errors
            if !stderr.contains("already exists") {
                return Err(format!("pw useradd failed: {stderr}"));
            }
        }
    }
    Ok(())
}

/// Configure devfs rules so the aifw group can access /dev/pf and /dev/bpf*
fn configure_devfs() -> Result<(), String> {
    #[cfg(target_os = "freebsd")]
    {
        use std::process::Command;

        // Write rules directly to /etc/devfs.rules (the canonical location)
        let devfs_rules_path = "/etc/devfs.rules";
        let existing = std::fs::read_to_string(devfs_rules_path).unwrap_or_default();
        if !existing.contains("aifw_devfs") {
            let mut content = existing;
            if !content.ends_with('\n') && !content.is_empty() {
                content.push('\n');
            }
            content.push_str("\n# AiFw device access rules\n");
            content.push_str("[aifw_devfs=10]\n");
            content.push_str("add path 'pf' mode 0660 group aifw\n");
            content.push_str("add path 'bpf*' mode 0660 group aifw\n");
            write_file(devfs_rules_path, &content)?;
        }

        // Enable the ruleset in rc.conf
        let _ = Command::new("sysrc")
            .args(["devfs_system_ruleset=aifw_devfs"])
            .output();

        // Apply immediately
        let _ = Command::new("service")
            .args(["devfs", "restart"])
            .output();
    }
    Ok(())
}

/// Generate a self-signed TLS cert for the API server
fn generate_tls_cert() -> Result<(), String> {
    let cert_path = "/usr/local/etc/aifw/tls/cert.pem";
    let key_path = "/usr/local/etc/aifw/tls/key.pem";

    if std::path::Path::new(cert_path).exists() && std::path::Path::new(key_path).exists() {
        return Ok(());
    }

    std::fs::create_dir_all("/usr/local/etc/aifw/tls")
        .map_err(|e| format!("failed to create tls dir: {e}"))?;

    // Generate using openssl CLI (available on FreeBSD base)
    let status = std::process::Command::new("openssl")
        .args([
            "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-keyout", key_path, "-out", cert_path,
            "-days", "3650", "-nodes",
            "-subj", "/CN=AiFw Firewall/O=AiFw",
        ])
        .status()
        .map_err(|e| format!("openssl failed: {e}"))?;

    if !status.success() {
        return Err("openssl cert generation failed".to_string());
    }

    // Set permissions: aifw group can read
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o640));
        let _ = std::process::Command::new("chown").args(["root:aifw", key_path]).output();
        let _ = std::process::Command::new("chown").args(["root:aifw", cert_path]).output();
    }

    Ok(())
}

fn create_dirs(config: &SetupConfig) -> Result<(), String> {
    for dir in [&config.config_dir, "/var/db/aifw", "/var/log/aifw"] {
        std::fs::create_dir_all(dir).map_err(|e| format!("failed to create {dir}: {e}"))?;
    }

    // Set ownership: config dir readable by aifw, db/log owned by aifw
    #[cfg(target_os = "freebsd")]
    {
        use std::process::Command;
        // Config dir: root owns, aifw group can read
        let _ = Command::new("chown").args(["root:aifw", &config.config_dir]).output();
        let _ = Command::new("chmod").args(["750", &config.config_dir]).output();
        // DB dir: aifw owns (API needs write access)
        let _ = Command::new("chown").args(["-R", "aifw:aifw", "/var/db/aifw"]).output();
        let _ = Command::new("chmod").args(["750", "/var/db/aifw"]).output();
        // Log dir: aifw owns
        let _ = Command::new("chown").args(["-R", "aifw:aifw", "/var/log/aifw"]).output();
        let _ = Command::new("chmod").args(["750", "/var/log/aifw"]).output();
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

    // Allow all traffic from local subnet
    lines.push("# Local subnet — allow all".to_string());
    if let Some(ref ip) = config.lan_ip {
        let net = ip.split('/').next().unwrap_or("192.168.1.0");
        let prefix = ip.split('/').nth(1).unwrap_or("24");
        lines.push(format!("pass in quick from {net}/{prefix} keep state label \"local-subnet\""));
    } else {
        // Derive subnet from WAN if no LAN — use common private ranges
        lines.push("pass in quick from 10.0.0.0/8 keep state label \"local-rfc1918\"".to_string());
        lines.push("pass in quick from 172.16.0.0/12 keep state label \"local-rfc1918\"".to_string());
        lines.push("pass in quick from 192.168.0.0/16 keep state label \"local-rfc1918\"".to_string());
    }
    lines.push(String::new());

    // Allow SSH from anywhere (management access)
    lines.push("# SSH access".to_string());
    lines.push("pass in quick proto tcp to any port 22 keep state label \"ssh\"".to_string());
    lines.push(String::new());

    // Allow API/UI access
    lines.push("# AiFw API/UI access".to_string());
    lines.push(format!("pass in quick proto tcp to any port {} keep state label \"aifw-api\"", config.api_port));
    lines.push(String::new());

    // LAN to WAN (only with dual-NIC + NAT enabled)
    if config.lan_interface.is_some() && config.nat_enabled {
        lines.push("# LAN to WAN".to_string());
        lines.push("pass in on $lan_if from $lan_net keep state".to_string());
        lines.push(String::new());

        lines.push("# NAT — LAN masquerade".to_string());
        lines.push("nat on $wan_if from $lan_net to any -> ($wan_if)".to_string());
        lines.push(String::new());
    } else if config.lan_interface.is_some() {
        lines.push("# LAN to WAN (NAT disabled)".to_string());
        lines.push("pass in on $lan_if from $lan_net keep state".to_string());
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
# REQUIRE: NETWORKING pf devfs
# KEYWORD: shutdown

. /etc/rc.subr

name="aifw_daemon"
rcvar="aifw_daemon_enable"
command="/usr/local/sbin/aifw-daemon"
command_args="--db {db} --log-level info"
pidfile="/var/run/${{name}}.pid"
start_cmd="${{name}}_start"
aifw_daemon_user="aifw"

aifw_daemon_start()
{{
    /usr/sbin/daemon -u $aifw_daemon_user -p $pidfile -f $command $command_args
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
command_args="--db {db} --listen {listen}:{port} --ui-dir /usr/local/share/aifw/ui --log-level info"
pidfile="/var/run/${{name}}.pid"
start_cmd="${{name}}_start"
aifw_api_user="aifw"

aifw_api_start()
{{
    /usr/sbin/daemon -u $aifw_api_user -p $pidfile -f $command $command_args
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
