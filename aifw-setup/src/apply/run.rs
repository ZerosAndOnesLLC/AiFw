//! `apply()` — the orchestration that turns a `SetupConfig` into a configured box.

use crate::config::SetupConfig;
use crate::console;
use crate::tuning::{self, TuningItem};

use super::database::init_database;
use super::pf_conf::generate_pf_conf;
use super::rcd::write_rcd_scripts;
use super::system::*;

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
        run_best_effort("chown", &["-R", "aifw:aifw", "/var/db/aifw"]);
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
    // needs. The originally-broad NOPASSWD grants from
    // GHSA-mjqh-2vx8-7hq7 have been split into three tiers:
    //
    //   1. `pfctl` and `shutdown` — restricted to a small set of exact
    //      forms (anchor scope, +10s grace, etc.).
    //   2. Narrow wrapper scripts under `/usr/local/libexec/aifw-sudo-*`
    //      — each enforces its own internal allowlist of valid arguments
    //      (paths, services, interfaces, rcvars). #204 closed the original
    //      9 broad grants (tee/wg/freebsd-update/pkg/service/chown/
    //      ifconfig/install/sysrc); SEC-C2 closed the remaining seven
    //      (dhclient/route/pkill/rm/mkdir/cp/tar/tcpdump) and dropped the
    //      unused cat/chmod grants entirely.
    //
    // The full sudoers content is exposed as `sudoers_content()` so a
    // unit test can validate it structurally and CI can run
    // `visudo -cf` against it.
    #[cfg(target_os = "freebsd")]
    {
        let sudoers_path = "/usr/local/etc/sudoers.d/aifw";
        warn_on_err(
            "mkdir /usr/local/etc/sudoers.d",
            std::fs::create_dir_all("/usr/local/etc/sudoers.d"),
        );
        warn_on_err(
            "write sudoers grants",
            std::fs::write(sudoers_path, sudoers_content()),
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            warn_on_err(
                "chmod sudoers to 0440",
                std::fs::set_permissions(sudoers_path, std::fs::Permissions::from_mode(0o440)),
            );
        }
    }

    // 5c. Setup unbound directory
    console::info("Configuring Unbound DNS resolver...");
    warn_on_err(
        "mkdir /var/unbound",
        std::fs::create_dir_all("/var/unbound"),
    );
    run_best_effort("chown", &["-R", "unbound:unbound", "/var/unbound"]);
    console::success("Unbound configured");

    // 5c2. Setup rDHCP directories
    console::info("Configuring rDHCP DHCP server...");
    for dir in [
        "/var/db/rdhcpd/leases",
        "/var/log/rdhcpd",
        "/usr/local/etc/rdhcpd",
    ] {
        warn_on_err(&format!("mkdir {dir}"), std::fs::create_dir_all(dir));
    }
    run_best_effort("chown", &["-R", "aifw:aifw", "/var/db/rdhcpd"]);
    run_best_effort("chown", &["-R", "aifw:aifw", "/var/log/rdhcpd"]);
    run_best_effort("chown", &["-R", "aifw:aifw", "/usr/local/etc/rdhcpd"]);
    console::success("rDHCP configured");

    // 5c3. Setup rDNS directories and user
    console::info("Configuring rDNS DNS server...");
    for dir in [
        "/usr/local/etc/rdns/zones",
        "/usr/local/etc/rdns/rpz",
        "/var/run/rdns",
        "/var/log/rdns",
    ] {
        warn_on_err(&format!("mkdir {dir}"), std::fs::create_dir_all(dir));
    }
    // Create rdns user if not exists
    let rdns_exists = std::process::Command::new("pw")
        .args(["user", "show", "rdns"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !rdns_exists {
        run_best_effort(
            "pw",
            &[
                "useradd",
                "rdns",
                "-d",
                "/nonexistent",
                "-s",
                "/usr/sbin/nologin",
                "-c",
                "rDNS DNS Server",
            ],
        );
    }
    console::success("rDNS configured");

    // 5c4. Setup rTIME directories
    console::info("Configuring rTIME time service...");
    for dir in ["/usr/local/etc/rtime", "/var/run/rtime", "/var/log/rtime"] {
        warn_on_err(&format!("mkdir {dir}"), std::fs::create_dir_all(dir));
    }
    run_best_effort("chown", &["-R", "aifw:aifw", "/usr/local/etc/rtime"]);
    run_best_effort("chown", &["-R", "aifw:aifw", "/var/log/rtime"]);
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
        console::info("Configuring network interfaces...");

        // WAN interface
        match config.wan_mode {
            crate::config::WanMode::Dhcp => {
                run_best_effort(
                    "sysrc",
                    &[&format!("ifconfig_{}=DHCP", config.wan_interface)],
                );
            }
            crate::config::WanMode::Static => {
                if let Some(ref ip) = config.wan_ip {
                    run_best_effort(
                        "sysrc",
                        &[&format!("ifconfig_{}=inet {}", config.wan_interface, ip)],
                    );
                }
                if let Some(ref gw) = config.wan_gateway {
                    run_best_effort("sysrc", &[&format!("defaultrouter={}", gw)]);
                }
            }
            crate::config::WanMode::Pppoe => {
                run_best_effort(
                    "sysrc",
                    &[&format!("ifconfig_{}=DHCP", config.wan_interface)],
                );
            }
        }

        // LAN interface
        if let (Some(iface), Some(ip)) = (&config.lan_interface, &config.lan_ip) {
            run_best_effort("sysrc", &[&format!("ifconfig_{}=inet {}", iface, ip)]);
            // Apply immediately
            run_best_effort("ifconfig", &[iface.as_str(), "inet", ip]);
        }

        // Gateway forwarding
        run_best_effort("sysrc", &["gateway_enable=YES"]);

        console::success("Network interfaces configured");
    }

    // 9. Start services
    #[cfg(target_os = "freebsd")]
    {
        console::info("Starting services...");

        // Anchor population is handled at runtime by aifw-daemon reading from
        // the DB. We deliberately do NOT write anchor files here — see
        // generate_pf_conf() notes. Writing them once at install created a
        // stale on-disk source of truth that pf.conf's `load anchor` would
        // keep re-applying over the daemon's DB-driven updates (v5.57.3 fix).

        // Load pf rules
        run_best_effort(
            "pfctl",
            &["-f", &format!("{}/pf.conf.aifw", config.config_dir)],
        );
        console::success("pf rules loaded");

        // sysrc-enable AiFw services so existing-install upgrades and
        // re-runs of aifw-setup pick up newly added services (aifw_ids was
        // added in v5.76.0). aifw_firstboot also does this, but only on
        // first boot — running aifw-setup on an existing appliance never
        // hits firstboot, so we belt-and-braces it here too.
        run_best_effort("sysrc", &["aifw_daemon_enable=YES"]);
        run_best_effort("sysrc", &["aifw_ids_enable=YES"]);
        run_best_effort("sysrc", &["aifw_api_enable=YES"]);
        run_best_effort("sysrc", &["aifw_watchdog_enable=YES"]);

        // HA cluster rc.conf keys
        let cluster_enabled = config.cluster.is_some();
        warn_on_err(
            "",
            run_sysrc(
                "aifw_cluster_enabled",
                if cluster_enabled { "YES" } else { "NO" },
            ),
        );
        if let Some(c) = &config.cluster {
            warn_on_err("", run_sysrc("aifw_cluster_role", &c.role.to_string()));
            warn_on_err("", run_sysrc("pfsync_enable", "YES"));
            let pfsync_args = format!("syncdev {} defer up", c.pfsync_iface);
            warn_on_err("", run_sysrc("ifconfig_pfsync0", &pfsync_args));
            // Setup writes Conservative timing to rc.conf as the boot-time default.
            // At runtime, aifw-daemon's recover_kernel_state_for_role re-applies
            // the actual stored profile via ifconfig, so any operator change via
            // the cluster API takes effect on next service restart. rc.conf is
            // rewritten only when re-running setup. TODO(#217): when the cluster
            // API changes the profile, have it also rewrite the rc.conf
            // aliases so reboot doesn't briefly fall back to Conservative.
            let timing = aifw_common::CarpLatencyProfile::default().timing_for(c.role);
            for vip in &c.vips {
                let key = format!("ifconfig_{}_aliases", vip.interface);
                let alias = format!(
                    "inet vhid {} advskew {} advbase {} pass {} {}/{}",
                    vip.vhid,
                    timing.advskew,
                    timing.advbase,
                    shell_quote_for_rcconf(&c.password),
                    vip.virtual_ip,
                    vip.prefix,
                );
                warn_on_err("", run_sysrc_append(&key, &alias));
            }
            warn_on_err("", run_sysrc("aifw_carp_demote_enable", "YES"));
            warn_on_err("", run_sysrc("aifw_demote_on_shutdown_enable", "YES"));
        } else {
            warn_on_err("", run_sysrc("aifw_cluster_role", "standalone"));
        }

        // Start core services
        run_best_effort("service", &["aifw_daemon", "start"]);
        // aifw_ids must come up before aifw_api (aifw_api REQUIREs aifw_ids)
        run_best_effort("service", &["aifw_ids", "start"]);
        run_best_effort("service", &["aifw_api", "start"]);
        // Watchdog last so it doesn't observe the others mid-startup and
        // try to "heal" them.
        run_best_effort("service", &["aifw_watchdog", "start"]);
        console::success("AiFw daemon, IDS, API, and watchdog started");

        // Start rDNS
        run_best_effort("service", &["rdns", "start"]);
        console::success("rDNS started");

        // Start rDHCP if enabled
        if config.dhcp_enabled {
            run_best_effort("service", &["rdhcpd", "start"]);
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
