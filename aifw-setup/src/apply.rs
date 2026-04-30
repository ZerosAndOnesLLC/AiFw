use crate::config::{DefaultPolicy, SetupConfig};
use crate::console;
use crate::tuning::{self, TuningItem};
use aifw_common::{CarpVip, ClusterNode, ClusterRole, Interface, PfsyncConfig};

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
    console::success(&format!(
        "Config written to {}/aifw.conf",
        config.config_dir
    ));

    // 3. Initialize database
    console::info("Initializing database...");
    init_database(config).await?;
    console::success(&format!("Database initialized at {}", config.db_path));

    // 3b. Fix DB ownership (DB was created as root, aifw user needs write access)
    #[cfg(target_os = "freebsd")]
    {
        let _ = std::process::Command::new("chown")
            .args(["-R", "aifw:aifw", "/var/db/aifw"])
            .output();
    }

    // 4. Generate pf rules
    console::info("Generating pf ruleset...");
    let pf_rules = generate_pf_conf(config);
    write_file(&format!("{}/pf.conf.aifw", config.config_dir), &pf_rules)?;
    // Create empty anchor files so pfctl doesn't error on load
    let anchors_dir = format!("{}/anchors", config.config_dir);
    std::fs::create_dir_all(&anchors_dir)
        .map_err(|e| format!("failed to create anchors dir: {e}"))?;
    for anchor in [
        "aifw",
        "aifw-nat",
        "aifw-ratelimit",
        "aifw-vpn",
        "aifw-geoip",
        "aifw-tls",
        "aifw-ha",
        "aifw-pbr",
        "aifw-mwan-leak",
        "aifw-mwan-reply",
    ] {
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

    // 5b. Grant aifw user sudo access to the specific commands the daemon
    // needs. Most call sites still rely on broad wildcards while the
    // end-to-end wrapper-script migration is in flight (tracked as a
    // follow-up to GHSA-mjqh-2vx8-7hq7). The lines below tighten the two
    // highest-impact categories:
    //   - pfctl is restricted to aifw-* anchors + a small set of
    //     read-only / anchor-flush forms; a compromised daemon can no
    //     longer rewrite the host ruleset outside its anchors.
    //   - shutdown is restricted to the two commands the daemon actually
    //     issues; arbitrary shutdown flags are no longer permitted.
    // The remainder is kept permissive for now — documented openly so
    // operators understand the residual risk.
    #[cfg(target_os = "freebsd")]
    {
        let sudoers_line = "\
# --- pfctl (restricted to aifw anchors) ---
aifw ALL=(root) NOPASSWD: /sbin/pfctl -a aifw* -f /tmp/aifw_pf_*.conf
aifw ALL=(root) NOPASSWD: /sbin/pfctl -a aifw* -f /usr/local/etc/aifw/anchors/aifw*
aifw ALL=(root) NOPASSWD: /sbin/pfctl -nf /tmp/aifw_pf_*.conf
aifw ALL=(root) NOPASSWD: /sbin/pfctl -a aifw* -F all
aifw ALL=(root) NOPASSWD: /sbin/pfctl -a aifw* -sr
aifw ALL=(root) NOPASSWD: /sbin/pfctl -a aifw* -ss
aifw ALL=(root) NOPASSWD: /sbin/pfctl -k label -k aifw*
aifw ALL=(root) NOPASSWD: /sbin/pfctl -sr
aifw ALL=(root) NOPASSWD: /sbin/pfctl -ss
aifw ALL=(root) NOPASSWD: /sbin/pfctl -si
aifw ALL=(root) NOPASSWD: /sbin/pfctl -f /etc/pf.conf

# --- shutdown (exact forms only; -p power-off or -r reboot with +10s grace) ---
aifw ALL=(root) NOPASSWD: /sbin/shutdown -p +10s *
aifw ALL=(root) NOPASSWD: /sbin/shutdown -r +10s *

# --- Network configuration ---
# TODO(GHSA-mjqh-2vx8-7hq7): the wildcards below still grant broad root.
# Migrate each call site to a narrow wrapper script and replace these
# lines with the wrapper path.
aifw ALL=(ALL) NOPASSWD: /sbin/ifconfig *
aifw ALL=(ALL) NOPASSWD: /sbin/dhclient *
aifw ALL=(ALL) NOPASSWD: /sbin/route *
aifw ALL=(ALL) NOPASSWD: /usr/sbin/service *
aifw ALL=(ALL) NOPASSWD: /usr/sbin/sysrc *
aifw ALL=(ALL) NOPASSWD: /usr/sbin/pkg *
aifw ALL=(ALL) NOPASSWD: /usr/sbin/freebsd-update *
aifw ALL=(ALL) NOPASSWD: /bin/cat *
aifw ALL=(ALL) NOPASSWD: /bin/cp *
aifw ALL=(ALL) NOPASSWD: /bin/rm *
aifw ALL=(ALL) NOPASSWD: /bin/mkdir *
aifw ALL=(ALL) NOPASSWD: /bin/chmod *
aifw ALL=(ALL) NOPASSWD: /bin/pkill *
aifw ALL=(ALL) NOPASSWD: /usr/bin/install *
aifw ALL=(ALL) NOPASSWD: /usr/bin/pkill *
aifw ALL=(ALL) NOPASSWD: /usr/bin/tar *
aifw ALL=(ALL) NOPASSWD: /usr/bin/tee *
aifw ALL=(ALL) NOPASSWD: /usr/sbin/chown *
aifw ALL=(ALL) NOPASSWD: /usr/sbin/tcpdump *
aifw ALL=(ALL) NOPASSWD: /usr/bin/wg *

# --- Detached restart driver ---
# Required by aifw-core/src/updater.rs `restart_services()` so post-update
# bounces survive aifw-api dying mid-iteration. -f flag double-forks
# /usr/local/libexec/aifw-restart.sh into its own session.
aifw ALL=(root) NOPASSWD: /usr/sbin/daemon -f *
";
        let sudoers_path = "/usr/local/etc/sudoers.d/aifw";
        let _ = std::fs::create_dir_all("/usr/local/etc/sudoers.d");
        let _ = std::fs::write(sudoers_path, sudoers_line);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(sudoers_path, std::fs::Permissions::from_mode(0o440));
        }
    }

    // 5c. Setup unbound directory
    console::info("Configuring Unbound DNS resolver...");
    let _ = std::fs::create_dir_all("/var/unbound");
    let _ = std::process::Command::new("chown")
        .args(["-R", "unbound:unbound", "/var/unbound"])
        .status();
    console::success("Unbound configured");

    // 5c2. Setup rDHCP directories
    console::info("Configuring rDHCP DHCP server...");
    for dir in [
        "/var/db/rdhcpd/leases",
        "/var/log/rdhcpd",
        "/usr/local/etc/rdhcpd",
    ] {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::process::Command::new("chown")
        .args(["-R", "aifw:aifw", "/var/db/rdhcpd"])
        .status();
    let _ = std::process::Command::new("chown")
        .args(["-R", "aifw:aifw", "/var/log/rdhcpd"])
        .status();
    let _ = std::process::Command::new("chown")
        .args(["-R", "aifw:aifw", "/usr/local/etc/rdhcpd"])
        .status();
    console::success("rDHCP configured");

    // 5c3. Setup rDNS directories and user
    console::info("Configuring rDNS DNS server...");
    for dir in [
        "/usr/local/etc/rdns/zones",
        "/usr/local/etc/rdns/rpz",
        "/var/run/rdns",
        "/var/log/rdns",
    ] {
        let _ = std::fs::create_dir_all(dir);
    }
    // Create rdns user if not exists
    let _ = std::process::Command::new("pw")
        .args(["user", "show", "rdns"])
        .status()
        .and_then(|s| {
            if !s.success() {
                std::process::Command::new("pw")
                    .args([
                        "useradd",
                        "rdns",
                        "-d",
                        "/nonexistent",
                        "-s",
                        "/usr/sbin/nologin",
                        "-c",
                        "rDNS DNS Server",
                    ])
                    .status()
            } else {
                Ok(s)
            }
        });
    console::success("rDNS configured");

    // 5c4. Setup rTIME directories
    console::info("Configuring rTIME time service...");
    for dir in ["/usr/local/etc/rtime", "/var/run/rtime", "/var/log/rtime"] {
        let _ = std::fs::create_dir_all(dir);
    }
    let _ = std::process::Command::new("chown")
        .args(["-R", "aifw:aifw", "/usr/local/etc/rtime"])
        .status();
    let _ = std::process::Command::new("chown")
        .args(["-R", "aifw:aifw", "/var/log/rtime"])
        .status();
    console::success("rTIME configured");

    // 5d. Configure devfs rules for /dev/pf and /dev/bpf* access
    console::info("Configuring device permissions...");
    configure_devfs()?;
    console::success("Device permissions configured");

    // 5c. Generate self-signed TLS certificate
    console::info("Generating TLS certificate...");
    generate_tls_cert()?;
    console::success("TLS certificate generated");

    // 5d. Configure SSH
    console::info("Configuring SSH...");
    configure_ssh(config)?;
    console::success("SSH configured");

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
        let resolv: Vec<String> = config
            .dns_servers
            .iter()
            .map(|s| format!("nameserver {s}"))
            .collect();
        write_file("/etc/resolv.conf.aifw", &resolv.join("\n"))?;
        console::success("DNS configured");
    }

    // 8. Configure network interfaces in rc.conf
    #[cfg(target_os = "freebsd")]
    {
        use std::process::Command;
        console::info("Configuring network interfaces...");

        // WAN interface
        match config.wan_mode {
            crate::config::WanMode::Dhcp => {
                let _ = Command::new("sysrc")
                    .args([&format!("ifconfig_{}=DHCP", config.wan_interface)])
                    .output();
            }
            crate::config::WanMode::Static => {
                if let Some(ref ip) = config.wan_ip {
                    let _ = Command::new("sysrc")
                        .args([&format!("ifconfig_{}=inet {}", config.wan_interface, ip)])
                        .output();
                }
                if let Some(ref gw) = config.wan_gateway {
                    let _ = Command::new("sysrc")
                        .args([&format!("defaultrouter={}", gw)])
                        .output();
                }
            }
            crate::config::WanMode::Pppoe => {
                let _ = Command::new("sysrc")
                    .args([&format!("ifconfig_{}=DHCP", config.wan_interface)])
                    .output();
            }
        }

        // LAN interface
        if let (Some(iface), Some(ip)) = (&config.lan_interface, &config.lan_ip) {
            let _ = Command::new("sysrc")
                .args([&format!("ifconfig_{}=inet {}", iface, ip)])
                .output();
            // Apply immediately
            let _ = Command::new("ifconfig")
                .args([iface.as_str(), "inet", ip])
                .output();
        }

        // Gateway forwarding
        let _ = Command::new("sysrc").args(["gateway_enable=YES"]).output();

        console::success("Network interfaces configured");
    }

    // 9. Start services
    #[cfg(target_os = "freebsd")]
    {
        use std::process::Command;
        console::info("Starting services...");

        // Anchor population is handled at runtime by aifw-daemon reading from
        // the DB. We deliberately do NOT write anchor files here — see
        // generate_pf_conf() notes. Writing them once at install created a
        // stale on-disk source of truth that pf.conf's `load anchor` would
        // keep re-applying over the daemon's DB-driven updates (v5.57.3 fix).

        // Load pf rules
        let _ = Command::new("pfctl")
            .args(["-f", &format!("{}/pf.conf.aifw", config.config_dir)])
            .output();
        console::success("pf rules loaded");

        // sysrc-enable AiFw services so existing-install upgrades and
        // re-runs of aifw-setup pick up newly added services (aifw_ids was
        // added in v5.76.0). aifw_firstboot also does this, but only on
        // first boot — running aifw-setup on an existing appliance never
        // hits firstboot, so we belt-and-braces it here too.
        let _ = Command::new("sysrc")
            .args(["aifw_daemon_enable=YES"])
            .output();
        let _ = Command::new("sysrc")
            .args(["aifw_ids_enable=YES"])
            .output();
        let _ = Command::new("sysrc")
            .args(["aifw_api_enable=YES"])
            .output();
        let _ = Command::new("sysrc")
            .args(["aifw_watchdog_enable=YES"])
            .output();

        // HA cluster rc.conf keys
        let cluster_enabled = config.cluster.is_some();
        let _ = run_sysrc("aifw_cluster_enabled", if cluster_enabled { "YES" } else { "NO" });
        if let Some(c) = &config.cluster {
            let _ = run_sysrc("aifw_cluster_role", &c.role.to_string());
            let _ = run_sysrc("pfsync_enable", "YES");
            let pfsync_args = format!("syncdev {} defer up", c.pfsync_iface);
            let _ = run_sysrc("ifconfig_pfsync0", &pfsync_args);
            let timing = aifw_common::CarpLatencyProfile::default().timing_for(c.role);
            for vip in &c.vips {
                let key = format!("ifconfig_{}_aliases", vip.interface);
                let alias = format!(
                    "inet vhid {} advskew {} advbase {} pass {} {}/{}",
                    vip.vhid,
                    timing.advskew,
                    timing.advbase,
                    shell_quote_for_rcconf(&c.password),
                    vip.virtual_ip, vip.prefix,
                );
                let _ = run_sysrc_append(&key, &alias);
            }
            let _ = run_sysrc("aifw_carp_demote_enable", "YES");
            let _ = run_sysrc("aifw_demote_on_shutdown_enable", "YES");
        } else {
            let _ = run_sysrc("aifw_cluster_role", "standalone");
        }

        // Start core services
        let _ = Command::new("service")
            .args(["aifw_daemon", "start"])
            .output();
        // aifw_ids must come up before aifw_api (aifw_api REQUIREs aifw_ids)
        let _ = Command::new("service")
            .args(["aifw_ids", "start"])
            .output();
        let _ = Command::new("service").args(["aifw_api", "start"]).output();
        // Watchdog last so it doesn't observe the others mid-startup and
        // try to "heal" them.
        let _ = Command::new("service")
            .args(["aifw_watchdog", "start"])
            .output();
        console::success("AiFw daemon, IDS, API, and watchdog started");

        // Start rDNS
        let _ = Command::new("service").args(["rdns", "start"]).output();
        console::success("rDNS started");

        // Start rDHCP if enabled
        if config.dhcp_enabled {
            let _ = Command::new("service").args(["rdhcpd", "start"]).output();
            console::success("rDHCP started");
        }
    }

    console::header("Setup Complete");
    console::success(&format!("AiFw is configured on {}", config.hostname));
    console::info("");
    // Show a usable URL — if listening on 0.0.0.0, show the WAN/LAN IP or hostname
    let display_host = if config.api_listen == "0.0.0.0" || config.api_listen == "::" {
        config
            .wan_ip
            .as_ref()
            .and_then(|ip| ip.split('/').next().map(String::from))
            .or(config
                .lan_ip
                .as_ref()
                .and_then(|ip| ip.split('/').next().map(String::from)))
            .unwrap_or_else(|| config.hostname.clone())
    } else {
        config.api_listen.clone()
    };
    console::info(&format!(
        "  Web UI:   https://{}:{}/",
        display_host, config.api_port
    ));
    console::info(&format!(
        "  API:      https://{}:{}/api/v1/",
        display_host, config.api_port
    ));
    console::info(&format!("  Admin:    {}", config.admin_username));
    console::info(&format!("  SSH:      {}", config.ssh_auth_method));
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
                "useradd",
                "aifw",
                "-u",
                "470",
                "-g",
                "aifw",
                "-d",
                "/nonexistent",
                "-s",
                "/usr/sbin/nologin",
                "-c",
                "AiFw Service Account",
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
        let _ = Command::new("service").args(["devfs", "restart"]).output();
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
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-keyout",
            key_path,
            "-out",
            cert_path,
            "-days",
            "3650",
            "-nodes",
            "-subj",
            "/CN=AiFw Firewall/O=AiFw",
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
        let _ = std::process::Command::new("chown")
            .args(["root:aifw", key_path])
            .output();
        let _ = std::process::Command::new("chown")
            .args(["root:aifw", cert_path])
            .output();
    }

    Ok(())
}

/// Configure SSH: authorized_keys, sshd_config, enable sshd
fn configure_ssh(config: &SetupConfig) -> Result<(), String> {
    use crate::config::SshAuthMethod;

    // Write authorized_keys if we have keys
    if !config.ssh_authorized_keys.is_empty() {
        let ssh_dir = "/root/.ssh";
        std::fs::create_dir_all(ssh_dir).map_err(|e| format!("failed to create {ssh_dir}: {e}"))?;

        let keys_content = config.ssh_authorized_keys.join("\n") + "\n";
        std::fs::write(format!("{ssh_dir}/authorized_keys"), &keys_content)
            .map_err(|e| format!("failed to write authorized_keys: {e}"))?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(ssh_dir, std::fs::Permissions::from_mode(0o700));
            let _ = std::fs::set_permissions(
                format!("{ssh_dir}/authorized_keys"),
                std::fs::Permissions::from_mode(0o600),
            );
        }
    }

    // Configure sshd_config
    let sshd_config = match config.ssh_auth_method {
        SshAuthMethod::KeyOnly => {
            "# AiFw SSH configuration — key authentication only\n\
             PermitRootLogin prohibit-password\n\
             PubkeyAuthentication yes\n\
             PasswordAuthentication no\n\
             ChallengeResponseAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             UsePAM no\n\
             AuthorizedKeysFile .ssh/authorized_keys\n\
             X11Forwarding no\n\
             PrintMotd yes\n\
             Subsystem sftp /usr/libexec/sftp-server\n"
        }
        SshAuthMethod::Password => {
            "# AiFw SSH configuration — password authentication (not recommended)\n\
             PermitRootLogin yes\n\
             PubkeyAuthentication yes\n\
             PasswordAuthentication yes\n\
             ChallengeResponseAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             UsePAM no\n\
             AuthorizedKeysFile .ssh/authorized_keys\n\
             X11Forwarding no\n\
             PrintMotd yes\n\
             Subsystem sftp /usr/libexec/sftp-server\n"
        }
    };

    #[cfg(target_os = "freebsd")]
    {
        std::fs::write("/etc/ssh/sshd_config", sshd_config)
            .map_err(|e| format!("failed to write sshd_config: {e}"))?;

        // Enable sshd at boot
        let _ = std::process::Command::new("sysrc")
            .args(["sshd_enable=YES"])
            .output();

        // Restart sshd to apply config
        let _ = std::process::Command::new("service")
            .args(["sshd", "restart"])
            .output();
    }

    #[cfg(not(target_os = "freebsd"))]
    {
        let _ = sshd_config; // suppress unused warning on non-FreeBSD
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
        let _ = Command::new("chown")
            .args(["root:aifw", &config.config_dir])
            .output();
        let _ = Command::new("chmod")
            .args(["750", &config.config_dir])
            .output();
        // DB dir: aifw owns (API needs write access)
        let _ = Command::new("chown")
            .args(["-R", "aifw:aifw", "/var/db/aifw"])
            .output();
        let _ = Command::new("chmod").args(["750", "/var/db/aifw"]).output();
        // Log dir: aifw owns
        let _ = Command::new("chown")
            .args(["-R", "aifw:aifw", "/var/log/aifw"])
            .output();
        let _ = Command::new("chmod")
            .args(["750", "/var/log/aifw"])
            .output();
    }

    Ok(())
}

fn write_file(path: &str, content: &str) -> Result<(), String> {
    std::fs::write(path, content).map_err(|e| format!("failed to write {path}: {e}"))
}

/// Write a single sysrc key=value pair (FreeBSD only).
#[cfg(target_os = "freebsd")]
fn run_sysrc(key: &str, value: &str) -> Result<(), String> {
    let out = std::process::Command::new("sysrc")
        .arg(format!("{key}={value}"))
        .output()
        .map_err(|e| format!("sysrc {key}: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "sysrc {key}={value} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Append a value to a sysrc list key (space-separated, FreeBSD only).
#[cfg(target_os = "freebsd")]
fn run_sysrc_append(key: &str, value: &str) -> Result<(), String> {
    let existing = std::process::Command::new("sysrc")
        .arg("-n")
        .arg(key)
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
        .unwrap_or_default();
    let combined = if existing.is_empty() {
        value.to_string()
    } else {
        format!("{existing} {value}")
    };
    run_sysrc(key, &combined)
}

/// Single-quote-wrap a string for safe inclusion in /etc/rc.conf values, which
/// are sourced by /bin/sh at boot. Returns the value wrapped in single quotes
/// with any inner single quotes escaped as `'\''`. Caller embeds the result
/// directly into the larger value string.
#[cfg(target_os = "freebsd")]
fn shell_quote_for_rcconf(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn write_config_file(config: &SetupConfig) -> Result<(), String> {
    let json = serde_json::to_string_pretty(config).map_err(|e| format!("serialize error: {e}"))?;
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
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS interface_roles (interface_name TEXT PRIMARY KEY, role TEXT NOT NULL, updated_at TEXT NOT NULL)"
    ).execute(&pool).await.map_err(|e| format!("interface_roles table: {e}"))?;

    let now = chrono::Utc::now().to_rfc3339();
    let _ = sqlx::query("INSERT OR REPLACE INTO interface_roles (interface_name, role, updated_at) VALUES (?1, 'WAN', ?2)")
        .bind(&config.wan_interface).bind(&now).execute(&pool).await;
    if let Some(ref lan) = config.lan_interface {
        let _ = sqlx::query("INSERT OR REPLACE INTO interface_roles (interface_name, role, updated_at) VALUES (?1, 'LAN', ?2)")
            .bind(lan).bind(&now).execute(&pool).await;
    }

    // Seed DNS resolver config — rDNS enabled by default with forwarding to user's DNS servers
    sqlx::query("CREATE TABLE IF NOT EXISTS dns_resolver_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        .execute(&pool).await.map_err(|e| format!("dns config table: {e}"))?;

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
            let _ = sqlx::query(
                "INSERT OR IGNORE INTO dns_resolver_config (key, value) VALUES (?1, ?2)",
            )
            .bind(k)
            .bind(v)
            .execute(&pool)
            .await;
        }
        // Forward to user's configured DNS servers
        if !config.dns_servers.is_empty() {
            let _ = sqlx::query("INSERT OR IGNORE INTO dns_resolver_config (key, value) VALUES ('forwarding_servers', ?1)")
                .bind(config.dns_servers.join(",")).execute(&pool).await;
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

    let _ = std::fs::create_dir_all("/usr/local/etc/rdns");
    let _ = std::fs::write("/usr/local/etc/rdns/rdns.toml", &rdns_conf);

    // Enable rDNS at boot
    #[cfg(target_os = "freebsd")]
    {
        let _ = std::process::Command::new("sysrc")
            .args(["rdns_enable=YES"])
            .status();
        // Disable unbound to avoid port conflict
        let _ = std::process::Command::new("sysrc")
            .args(["local_unbound_enable=NO"])
            .status();
    }

    // Seed DNS ACL entries — allow LAN subnet and localhost
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dns_access_lists (id TEXT PRIMARY KEY, network TEXT NOT NULL, action TEXT NOT NULL, description TEXT, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL)"
    ).execute(&pool).await.map_err(|e| format!("dns acl table: {e}"))?;

    let acl_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM dns_access_lists")
        .fetch_one(&pool)
        .await
        .map_err(|e| format!("acl count: {e}"))?;
    if acl_count.0 == 0 {
        let now = chrono::Utc::now().to_rfc3339();
        // Allow localhost
        let _ = sqlx::query("INSERT INTO dns_access_lists (id, network, action, description, created_at) VALUES (?1, '127.0.0.0/8', 'allow', 'Localhost', ?2)")
            .bind(uuid::Uuid::new_v4().to_string()).bind(&now).execute(&pool).await;
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
                let _ = sqlx::query("INSERT INTO dns_access_lists (id, network, action, description, created_at) VALUES (?1, ?2, 'allow', 'LAN subnet', ?3)")
                    .bind(uuid::Uuid::new_v4().to_string()).bind(&subnet).bind(&now).execute(&pool).await;
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
    }

    Ok(())
}

async fn seed_dhcp_config(
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

    // Create DHCP config table
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS dhcp_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    )
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
        let _ = sqlx::query("INSERT OR IGNORE INTO dhcp_config (key, value) VALUES (?1, ?2)")
            .bind(k)
            .bind(v)
            .execute(pool)
            .await;
    }
    // Bind to LAN interface
    if let Some(ref li) = config.lan_interface {
        let _ =
            sqlx::query("INSERT OR IGNORE INTO dhcp_config (key, value) VALUES ('interfaces', ?1)")
                .bind(li)
                .execute(pool)
                .await;
    }
    // DNS for scope = LAN IP (rDNS is on the firewall)
    let _ =
        sqlx::query("INSERT OR IGNORE INTO dhcp_config (key, value) VALUES ('dns_servers', ?1)")
            .bind(lan_ip)
            .execute(pool)
            .await;

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
    let _ = sqlx::query(
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

    let _ = std::fs::create_dir_all("/usr/local/etc/rdhcpd");
    let _ = std::fs::create_dir_all("/var/db/rdhcpd/leases");
    let _ = std::fs::create_dir_all("/var/log/rdhcpd");
    let _ = std::fs::write("/usr/local/etc/rdhcpd/config.toml", &rdhcp_conf);

    // Enable rDHCP at boot
    #[cfg(target_os = "freebsd")]
    {
        let _ = std::process::Command::new("sysrc")
            .args(["rdhcpd_enable=YES"])
            .status();
    }

    Ok(())
}

async fn seed_default_rules(pool: &sqlx::SqlitePool, config: &SetupConfig) -> Result<(), String> {
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

            let _ = sqlx::query(
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

fn hash_for_db(password: &str) -> String {
    use argon2::{
        Argon2, PasswordHasher, password_hash::SaltString, password_hash::rand_core::OsRng,
    };
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .unwrap_or_default()
}

/// Generate a pf.conf based on the setup configuration
pub fn generate_pf_conf(config: &SetupConfig) -> String {
    let mut lines = Vec::new();

    lines.push("# AiFw — Generated pf.conf".to_string());
    lines.push(format!(
        "# Generated by aifw-setup on {}",
        chrono::Utc::now().to_rfc3339()
    ));
    lines.push(String::new());

    // Macros
    lines.push(format!("wan_if = \"{}\"", config.wan_interface));
    if let Some(ref lan) = config.lan_interface {
        lines.push(format!("lan_if = \"{lan}\""));
    }
    if let Some(ref ip) = config.lan_ip {
        let host = ip.split('/').next().unwrap_or("192.168.1.1");
        let prefix = ip.split('/').nth(1).unwrap_or("24");
        // Derive network address from host IP (e.g. 192.168.1.1 -> 192.168.1.0)
        let octets: Vec<&str> = host.split('.').collect();
        let net = if octets.len() == 4 {
            format!("{}.{}.{}.0", octets[0], octets[1], octets[2])
        } else {
            host.to_string()
        };
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
    lines.push("set skip on pfsync0".to_string());
    lines.push("set block-policy drop".to_string());
    lines.push("set optimization aggressive".to_string());
    // floating (not if-bound) is required for pfsync state migration on
    // failover — without it, replicated states bind to the original
    // interface and don't match traffic on the surviving node's iface.
    lines.push("set state-policy floating".to_string());
    lines.push(String::new());

    // Scrub
    lines.push("# Normalization".to_string());
    lines.push("scrub in all".to_string());
    lines.push(String::new());

    // NAT (must come before filter rules in pf)
    if config.lan_interface.is_some() && config.nat_enabled {
        lines.push("# NAT — LAN masquerade".to_string());
        lines.push("nat on $wan_if from $lan_net to any -> ($wan_if)".to_string());
        lines.push(String::new());
    }

    // AiFw managed anchors — NAT anchors must come before filter anchors
    lines.push("# AiFw NAT anchors".to_string());
    lines.push("nat-anchor \"aifw\"".to_string());
    lines.push("nat-anchor \"aifw-nat\"".to_string());
    lines.push("rdr-anchor \"aifw-nat\"".to_string());
    lines.push("nat-anchor \"aifw-vpn\"".to_string());
    lines.push(String::new());
    // DHCP pass rules — must come BEFORE anchors because anchors contain
    // "block quick" rules that would drop DHCP broadcasts first
    if config.dhcp_enabled {
        let lan = config.lan_interface.as_deref().unwrap_or("$lan_if");
        lines.push("# DHCP server — allow broadcast requests and replies".to_string());
        lines.push(format!("pass in quick on {lan} proto udp from 0.0.0.0 port 68 to 255.255.255.255 port 67 label \"dhcp-discover\""));
        lines.push(format!(
            "pass out quick on {lan} proto udp from any port 67 to any port 68 label \"dhcp-reply\""
        ));
        lines.push(String::new());
    }

    lines.push("# AiFw filter anchors".to_string());
    // Multi-WAN anchors MUST be evaluated first so policy-routing decisions
    // (route-to / rtable) are set before general filtering.
    lines.push("anchor \"aifw-pbr\"".to_string());
    lines.push("anchor \"aifw-mwan-leak\"".to_string());
    lines.push("anchor \"aifw-mwan-reply\"".to_string());
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
    lines.push("antispoof quick for $wan_if".to_string());
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

    // Allow traffic from LAN subnet only
    if config.lan_ip.is_some() {
        lines.push("# LAN subnet — allow inbound".to_string());
        lines.push("pass in quick from $lan_net keep state label \"local-subnet\"".to_string());
    }
    lines.push(String::new());

    // Allow SSH from anywhere (management access)
    lines.push("# SSH access".to_string());
    lines.push("pass in quick proto tcp to any port 22 keep state label \"ssh\"".to_string());
    lines.push(String::new());

    // Allow API/UI access
    lines.push("# AiFw API/UI access".to_string());
    lines.push(format!(
        "pass in quick proto tcp to any port {} keep state label \"aifw-api\"",
        config.api_port
    ));
    lines.push(String::new());

    // LAN to WAN pass rule
    if config.lan_interface.is_some() {
        lines.push("# LAN to WAN".to_string());
        lines.push("pass in on $lan_if from $lan_net keep state".to_string());
        lines.push(String::new());

        // DHCP on LAN (client sends from 0.0.0.0, must allow from any on LAN)
        if config.dhcp_enabled {
            lines.push("# DHCP on LAN".to_string());
            lines.push(
                "pass in quick on $lan_if proto udp from any to any port { 67, 68 } keep state"
                    .to_string(),
            );
            lines.push(String::new());
        }
    }

    // NOTE: we intentionally do NOT `load anchor "aifw" from ...` here.
    //
    // The aifw-daemon / aifw-api processes populate the `aifw` anchor directly
    // via `pfctl -a aifw -f -` from the DB on startup and on every rule change.
    // If pf.conf.aifw ALSO loaded the anchor from a stale on-disk file, any
    // pf.conf reload (service pf reload, `aifw reconcile`, setup re-apply)
    // would wipe the DB-driven rules back to whatever was in the file at
    // install time — which is exactly how user edits to the LAN subnet rule
    // silently regressed on reload. See root-cause write-up in v5.57.x notes.
    //
    // The anchor hook is already declared earlier via `anchor "aifw"`; it
    // starts empty and gets populated by the daemon. The brief window
    // between `service pf start` and `aifw_daemon start` is acceptable —
    // the default-block catches inbound traffic, and daemon fills in the
    // pass rules within ~1 second.
    lines.push("# aifw anchor is populated at runtime by aifw-daemon from the DB.".to_string());
    lines
        .push("# Do NOT add `load anchor \"aifw\" from ...` here — see v5.57.3 notes.".to_string());
    lines.push(String::new());

    lines.join("\n")
}

/// Write FreeBSD rc.d service scripts. Pattern follows `rdns` — supervisor
/// pidfile + child pidfile + start_precmd reaping orphans.
fn write_rcd_scripts(config: &SetupConfig) -> Result<(), String> {
    let daemon_script = format!(
        r#"#!/bin/sh
#
# PROVIDE: aifw_daemon
# REQUIRE: NETWORKING pf devfs
# KEYWORD: shutdown

. /etc/rc.subr

name="aifw_daemon"
rcvar="aifw_daemon_enable"

load_rc_config $name

: ${{aifw_daemon_enable:="NO"}}
: ${{aifw_daemon_pidfile:="/var/run/aifw_daemon.pid"}}
: ${{aifw_daemon_supervisor_pidfile:="/var/run/aifw_daemon-supervisor.pid"}}

pidfile="${{aifw_daemon_supervisor_pidfile}}"
procname="/usr/sbin/daemon"
aifw_daemon_binary="/usr/local/sbin/aifw-daemon"
command="/usr/sbin/daemon"
command_args="-f -p ${{aifw_daemon_pidfile}} -P ${{aifw_daemon_supervisor_pidfile}} -R 5 -S -T aifw_daemon -o /var/log/aifw/daemon.log -u aifw ${{aifw_daemon_binary}} --db {db} --log-level info"

start_precmd="aifw_daemon_precmd"
stop_cmd="aifw_daemon_stop"
stop_postcmd="aifw_daemon_poststop"

aifw_demote_if_clustered()
{{
    if [ "$(sysrc -n aifw_cluster_enabled 2>/dev/null)" = "YES" ]; then
        sysctl net.inet.carp.demotion=240 >/dev/null 2>&1 || true
        sleep 1
    fi
}}

aifw_daemon_precmd()
{{
    /bin/mkdir -p /var/log/aifw
    /usr/sbin/chown aifw:aifw /var/log/aifw
    /usr/bin/pkill -f "daemon:.*aifw-daemon" 2>/dev/null
    /usr/bin/pkill -x aifw-daemon 2>/dev/null
    /bin/rm -f ${{aifw_daemon_pidfile}} ${{aifw_daemon_supervisor_pidfile}}
    # Pre-create singleton lockfile owned by aifw — /var/run is root-only,
    # so the binary (running as aifw via daemon -u aifw) can't create it.
    /usr/bin/touch /var/run/aifw-daemon.lock
    /usr/sbin/chown aifw:aifw /var/run/aifw-daemon.lock
}}

aifw_daemon_stop()
{{
    aifw_demote_if_clustered
    # SIGTERM with a hard 10-second wall-clock timeout, then SIGKILL.
    # The default rc.subr stop sends SIGTERM and pwait()s indefinitely —
    # if the binary's tokio runtime won't exit (e.g. a background metrics
    # exporter holding the process alive after main returns), service
    # restart wedges forever and blocks the in-product update loop.
    if [ -f "${{aifw_daemon_supervisor_pidfile}}" ]; then
        sup_pid=$(cat "${{aifw_daemon_supervisor_pidfile}}")
        echo "Stopping aifw_daemon (supervisor pid ${{sup_pid}})."
        if kill -TERM "${{sup_pid}}" 2>/dev/null; then
            i=0
            while [ $i -lt 10 ] && kill -0 "${{sup_pid}}" 2>/dev/null; do
                sleep 1
                i=$((i+1))
            done
            if kill -0 "${{sup_pid}}" 2>/dev/null; then
                echo "Graceful stop timed out; sending SIGKILL"
                kill -KILL "${{sup_pid}}" 2>/dev/null
                /usr/bin/pkill -KILL -x aifw-daemon 2>/dev/null
            fi
        fi
    elif [ -f "${{aifw_daemon_pidfile}}" ]; then
        pid=$(cat "${{aifw_daemon_pidfile}}")
        kill -TERM "${{pid}}" 2>/dev/null
        sleep 2
        kill -KILL "${{pid}}" 2>/dev/null
    else
        echo "aifw_daemon is not running."
    fi
    /bin/rm -f ${{aifw_daemon_pidfile}} ${{aifw_daemon_supervisor_pidfile}}
}}

aifw_daemon_poststop()
{{
    /bin/rm -f ${{aifw_daemon_pidfile}} ${{aifw_daemon_supervisor_pidfile}}
}}

run_rc_command "$1"
"#,
        db = config.db_path
    );

    let api_script = format!(
        r#"#!/bin/sh
#
# PROVIDE: aifw_api
# REQUIRE: NETWORKING aifw_daemon aifw_ids
# KEYWORD: shutdown

. /etc/rc.subr

name="aifw_api"
rcvar="aifw_api_enable"

load_rc_config $name

: ${{aifw_api_enable:="NO"}}
: ${{aifw_api_pidfile:="/var/run/aifw_api.pid"}}
: ${{aifw_api_supervisor_pidfile:="/var/run/aifw_api-supervisor.pid"}}

pidfile="${{aifw_api_supervisor_pidfile}}"
procname="/usr/sbin/daemon"
aifw_api_binary="/usr/local/sbin/aifw-api"
command="/usr/sbin/daemon"
command_args="-f -p ${{aifw_api_pidfile}} -P ${{aifw_api_supervisor_pidfile}} -R 5 -S -T aifw_api -o /var/log/aifw/api.log -u aifw ${{aifw_api_binary}} --db {db} --listen {listen}:{port} --ui-dir /usr/local/share/aifw/ui --log-level info"

start_precmd="aifw_api_precmd"
stop_cmd="aifw_api_stop"
stop_postcmd="aifw_api_poststop"

aifw_demote_if_clustered()
{{
    if [ "$(sysrc -n aifw_cluster_enabled 2>/dev/null)" = "YES" ]; then
        sysctl net.inet.carp.demotion=240 >/dev/null 2>&1 || true
        sleep 1
    fi
}}

aifw_api_precmd()
{{
    /bin/mkdir -p /var/log/aifw
    /usr/sbin/chown aifw:aifw /var/log/aifw
    /usr/bin/pkill -f "daemon:.*aifw-api" 2>/dev/null
    /usr/bin/pkill -x aifw-api 2>/dev/null
    /bin/rm -f ${{aifw_api_pidfile}} ${{aifw_api_supervisor_pidfile}}
    /usr/bin/touch /var/run/aifw-api.lock
    /usr/sbin/chown aifw:aifw /var/run/aifw-api.lock
}}

aifw_api_stop()
{{
    aifw_demote_if_clustered
    # SIGTERM with a hard 10-second wall-clock timeout, then SIGKILL.
    # The default rc.subr stop sends SIGTERM and pwait()s indefinitely —
    # if the binary's tokio runtime won't exit (e.g. a background metrics
    # exporter holding the process alive after main returns), service
    # restart wedges forever and blocks the in-product update loop.
    if [ -f "${{aifw_api_supervisor_pidfile}}" ]; then
        sup_pid=$(cat "${{aifw_api_supervisor_pidfile}}")
        echo "Stopping aifw_api (supervisor pid ${{sup_pid}})."
        if kill -TERM "${{sup_pid}}" 2>/dev/null; then
            i=0
            while [ $i -lt 10 ] && kill -0 "${{sup_pid}}" 2>/dev/null; do
                sleep 1
                i=$((i+1))
            done
            if kill -0 "${{sup_pid}}" 2>/dev/null; then
                echo "Graceful stop timed out; sending SIGKILL"
                kill -KILL "${{sup_pid}}" 2>/dev/null
                /usr/bin/pkill -KILL -x aifw-api 2>/dev/null
            fi
        fi
    elif [ -f "${{aifw_api_pidfile}}" ]; then
        pid=$(cat "${{aifw_api_pidfile}}")
        kill -TERM "${{pid}}" 2>/dev/null
        sleep 2
        kill -KILL "${{pid}}" 2>/dev/null
    else
        echo "aifw_api is not running."
    fi
    /bin/rm -f ${{aifw_api_pidfile}} ${{aifw_api_supervisor_pidfile}}
}}

aifw_api_poststop()
{{
    /bin/rm -f ${{aifw_api_pidfile}} ${{aifw_api_supervisor_pidfile}}
}}

run_rc_command "$1"
"#,
        db = config.db_path,
        listen = config.api_listen,
        port = config.api_port
    );

    let ids_script = format!(
        r#"#!/bin/sh
#
# PROVIDE: aifw_ids
# REQUIRE: NETWORKING aifw_daemon
# KEYWORD: shutdown

. /etc/rc.subr

name="aifw_ids"
rcvar="aifw_ids_enable"

load_rc_config $name

: ${{aifw_ids_enable:="NO"}}
: ${{aifw_ids_pidfile:="/var/run/aifw_ids.pid"}}
: ${{aifw_ids_supervisor_pidfile:="/var/run/aifw_ids-supervisor.pid"}}

pidfile="${{aifw_ids_supervisor_pidfile}}"
procname="/usr/sbin/daemon"
aifw_ids_binary="/usr/local/sbin/aifw-ids"
command="/usr/sbin/daemon"
command_args="-f -p ${{aifw_ids_pidfile}} -P ${{aifw_ids_supervisor_pidfile}} -R 5 -S -T aifw_ids -o /var/log/aifw/ids.log -u aifw ${{aifw_ids_binary}} --db {db} --socket /var/run/aifw/ids.sock --log-level info"

start_precmd="aifw_ids_precmd"
stop_cmd="aifw_ids_stop"
stop_postcmd="aifw_ids_poststop"

aifw_demote_if_clustered()
{{
    if [ "$(sysrc -n aifw_cluster_enabled 2>/dev/null)" = "YES" ]; then
        sysctl net.inet.carp.demotion=240 >/dev/null 2>&1 || true
        sleep 1
    fi
}}

aifw_ids_precmd()
{{
    /bin/mkdir -p /var/log/aifw /var/run/aifw
    /usr/sbin/chown aifw:aifw /var/log/aifw /var/run/aifw
    /bin/chmod 0750 /var/run/aifw
    /usr/bin/pkill -f "daemon:.*aifw-ids" 2>/dev/null
    /usr/bin/pkill -x aifw-ids 2>/dev/null
    /bin/rm -f ${{aifw_ids_pidfile}} ${{aifw_ids_supervisor_pidfile}} /var/run/aifw/ids.sock
    /usr/bin/touch /var/run/aifw-ids.lock
    /usr/sbin/chown aifw:aifw /var/run/aifw-ids.lock
}}

aifw_ids_stop()
{{
    aifw_demote_if_clustered
    # SIGTERM with a hard 10-second wall-clock timeout, then SIGKILL.
    # The default rc.subr stop sends SIGTERM and pwait()s indefinitely —
    # if the binary's tokio runtime won't exit (e.g. a background metrics
    # exporter holding the process alive after main returns), service
    # restart wedges forever and blocks the in-product update loop.
    if [ -f "${{aifw_ids_supervisor_pidfile}}" ]; then
        sup_pid=$(cat "${{aifw_ids_supervisor_pidfile}}")
        echo "Stopping aifw_ids (supervisor pid ${{sup_pid}})."
        if kill -TERM "${{sup_pid}}" 2>/dev/null; then
            i=0
            while [ $i -lt 10 ] && kill -0 "${{sup_pid}}" 2>/dev/null; do
                sleep 1
                i=$((i+1))
            done
            if kill -0 "${{sup_pid}}" 2>/dev/null; then
                echo "Graceful stop timed out; sending SIGKILL"
                kill -KILL "${{sup_pid}}" 2>/dev/null
                /usr/bin/pkill -KILL -x aifw-ids 2>/dev/null
            fi
        fi
    elif [ -f "${{aifw_ids_pidfile}}" ]; then
        pid=$(cat "${{aifw_ids_pidfile}}")
        kill -TERM "${{pid}}" 2>/dev/null
        sleep 2
        kill -KILL "${{pid}}" 2>/dev/null
    else
        echo "aifw_ids is not running."
    fi
    /bin/rm -f ${{aifw_ids_pidfile}} ${{aifw_ids_supervisor_pidfile}}
}}

aifw_ids_poststop()
{{
    /bin/rm -f ${{aifw_ids_pidfile}} ${{aifw_ids_supervisor_pidfile}}
}}

run_rc_command "$1"
"#,
        db = config.db_path
    );

    let rdhcpd_script = r#"#!/bin/sh
#
# PROVIDE: rdhcpd
# REQUIRE: NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="rdhcpd"
rcvar="rdhcpd_enable"

load_rc_config $name

: ${rdhcpd_enable:="NO"}
: ${rdhcpd_config:="/usr/local/etc/rdhcpd/config.toml"}
: ${rdhcpd_pidfile:="/var/run/rdhcpd/rdhcpd.pid"}
: ${rdhcpd_supervisor_pidfile:="/var/run/rdhcpd/rdhcpd-supervisor.pid"}

pidfile="${rdhcpd_supervisor_pidfile}"
procname="/usr/sbin/daemon"
rdhcpd_binary="/usr/local/sbin/rdhcpd"
command="/usr/sbin/daemon"
command_args="-f -p ${rdhcpd_pidfile} -P ${rdhcpd_supervisor_pidfile} -R 5 -S -T rdhcpd -o /var/log/rdhcpd/rdhcpd.log ${rdhcpd_binary} ${rdhcpd_config}"

start_precmd="rdhcpd_precmd"
stop_cmd="rdhcpd_stop"
stop_postcmd="rdhcpd_poststop"
reload_cmd="rdhcpd_reload"
extra_commands="reload"

rdhcpd_precmd()
{
    /bin/mkdir -p /var/db/rdhcpd/leases /var/log/rdhcpd /usr/local/etc/rdhcpd /var/run/rdhcpd
    /usr/sbin/chown -R aifw:aifw /var/db/rdhcpd /var/log/rdhcpd /usr/local/etc/rdhcpd /var/run/rdhcpd
    /usr/bin/pkill -f "daemon:.*rdhcpd" 2>/dev/null
    /usr/bin/pkill -x rdhcpd 2>/dev/null
    /bin/rm -f ${rdhcpd_pidfile} ${rdhcpd_supervisor_pidfile}

    if [ ! -f ${rdhcpd_config} ]; then
        echo "ERROR: rdhcpd config not found at ${rdhcpd_config}"
        return 1
    fi
}

rdhcpd_stop()
{
    # SIGTERM with a hard 10-second wall-clock timeout, then SIGKILL.
    # The default rc.subr stop sends SIGTERM and pwait()s indefinitely —
    # if the binary's tokio runtime won't exit (e.g. a background metrics
    # exporter holding the process alive after main returns), service
    # restart wedges forever and blocks the in-product update loop.
    if [ -f "${rdhcpd_supervisor_pidfile}" ]; then
        sup_pid=$(cat "${rdhcpd_supervisor_pidfile}")
        echo "Stopping rdhcpd (supervisor pid ${sup_pid})."
        if kill -TERM "${sup_pid}" 2>/dev/null; then
            i=0
            while [ $i -lt 10 ] && kill -0 "${sup_pid}" 2>/dev/null; do
                sleep 1
                i=$((i+1))
            done
            if kill -0 "${sup_pid}" 2>/dev/null; then
                echo "Graceful stop timed out; sending SIGKILL"
                kill -KILL "${sup_pid}" 2>/dev/null
                /usr/bin/pkill -KILL -x rdhcpd 2>/dev/null
            fi
        fi
    elif [ -f "${rdhcpd_pidfile}" ]; then
        pid=$(cat "${rdhcpd_pidfile}")
        kill -TERM "${pid}" 2>/dev/null
        sleep 2
        kill -KILL "${pid}" 2>/dev/null
    else
        echo "rdhcpd is not running."
    fi
    /bin/rm -f ${rdhcpd_pidfile} ${rdhcpd_supervisor_pidfile}
}

rdhcpd_poststop()
{
    /bin/rm -f ${rdhcpd_pidfile} ${rdhcpd_supervisor_pidfile}
}

rdhcpd_reload()
{
    if [ -f "${rdhcpd_pidfile}" ]; then
        pid=$(cat "${rdhcpd_pidfile}")
        echo "Reloading rdhcpd (pid ${pid})."
        /bin/kill -HUP "${pid}" 2>/dev/null
    else
        echo "rdhcpd is not running."
        return 1
    fi
}

run_rc_command "$1"
"#;

    let rcd_dir = if std::path::Path::new("/usr/local/etc/rc.d").exists() {
        "/usr/local/etc/rc.d"
    } else {
        &config.config_dir
    };

    let watchdog_script = r#"#!/bin/sh
#
# PROVIDE: aifw_watchdog
# REQUIRE: aifw_api
# KEYWORD: shutdown

. /etc/rc.subr

name="aifw_watchdog"
rcvar="aifw_watchdog_enable"

load_rc_config $name

: ${aifw_watchdog_enable:="NO"}
: ${aifw_watchdog_pidfile:="/var/run/aifw_watchdog.pid"}
: ${aifw_watchdog_supervisor_pidfile:="/var/run/aifw_watchdog-supervisor.pid"}
: ${aifw_watchdog_interval:="60"}

pidfile="${aifw_watchdog_supervisor_pidfile}"
procname="/usr/sbin/daemon"
command="/usr/sbin/daemon"
command_args="-f -p ${aifw_watchdog_pidfile} -P ${aifw_watchdog_supervisor_pidfile} -R 5 -S -T aifw_watchdog -o /var/log/aifw/watchdog.log /usr/local/libexec/aifw-watchdog.sh"

start_precmd="aifw_watchdog_precmd"
stop_cmd="aifw_watchdog_stop"
stop_postcmd="aifw_watchdog_poststop"

aifw_watchdog_precmd()
{
    /bin/mkdir -p /var/log/aifw
    /usr/bin/pkill -f "daemon:.*aifw-watchdog" 2>/dev/null
    /usr/bin/pkill -f "aifw-watchdog.sh" 2>/dev/null
    /bin/rm -f ${aifw_watchdog_pidfile} ${aifw_watchdog_supervisor_pidfile}
    export AIFW_WATCHDOG_INTERVAL="${aifw_watchdog_interval}"
}

aifw_watchdog_stop()
{
    if [ -f "${aifw_watchdog_supervisor_pidfile}" ]; then
        sup_pid=$(cat "${aifw_watchdog_supervisor_pidfile}")
        echo "Stopping aifw_watchdog (supervisor pid ${sup_pid})."
        if kill -TERM "${sup_pid}" 2>/dev/null; then
            i=0
            while [ $i -lt 5 ] && kill -0 "${sup_pid}" 2>/dev/null; do
                sleep 1
                i=$((i+1))
            done
            if kill -0 "${sup_pid}" 2>/dev/null; then
                echo "Graceful stop timed out; sending SIGKILL"
                kill -KILL "${sup_pid}" 2>/dev/null
                /usr/bin/pkill -KILL -f "aifw-watchdog.sh" 2>/dev/null
            fi
        fi
    elif [ -f "${aifw_watchdog_pidfile}" ]; then
        pid=$(cat "${aifw_watchdog_pidfile}")
        kill -TERM "${pid}" 2>/dev/null
        sleep 2
        kill -KILL "${pid}" 2>/dev/null
    else
        echo "aifw_watchdog is not running."
    fi
    /bin/rm -f ${aifw_watchdog_pidfile} ${aifw_watchdog_supervisor_pidfile}
}

aifw_watchdog_poststop()
{
    /bin/rm -f ${aifw_watchdog_pidfile} ${aifw_watchdog_supervisor_pidfile}
}

run_rc_command "$1"
"#;

    write_file(&format!("{rcd_dir}/aifw_daemon"), &daemon_script)?;
    write_file(&format!("{rcd_dir}/aifw_api"), &api_script)?;
    write_file(&format!("{rcd_dir}/aifw_ids"), &ids_script)?;
    write_file(&format!("{rcd_dir}/aifw_watchdog"), watchdog_script)?;
    write_file(&format!("{rcd_dir}/rdhcpd"), rdhcpd_script)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o755);
        let _ = std::fs::set_permissions(format!("{rcd_dir}/aifw_daemon"), perms.clone());
        let _ = std::fs::set_permissions(format!("{rcd_dir}/aifw_api"), perms.clone());
        let _ = std::fs::set_permissions(format!("{rcd_dir}/aifw_ids"), perms.clone());
        let _ = std::fs::set_permissions(format!("{rcd_dir}/aifw_watchdog"), perms.clone());
        let _ = std::fs::set_permissions(format!("{rcd_dir}/rdhcpd"), perms);
    }

    Ok(())
}

/// Generate pf rules for testing (non-FreeBSD)
#[cfg(test)]
pub mod tests_support {
    use super::*;
    use crate::config::SetupConfig;

    #[allow(dead_code)]
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
