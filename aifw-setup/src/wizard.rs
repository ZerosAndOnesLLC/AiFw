use crate::config::{DefaultPolicy, SetupConfig, SshAuthMethod, WanMode, WizardCarpVip, WizardClusterConfig};
use crate::console;
use crate::hwdetect::SystemProfile;
use crate::tuning::{self, TuningItem};

/// Detect network interfaces (FreeBSD: ifconfig -l, Linux: mock)
fn detect_interfaces() -> Vec<String> {
    #[cfg(target_os = "freebsd")]
    {
        if let Ok(output) = std::process::Command::new("ifconfig").arg("-l").output() {
            let list = String::from_utf8_lossy(&output.stdout);
            return list
                .split_whitespace()
                .filter(|iface| {
                    !iface.starts_with("lo")
                        && !iface.starts_with("pflog")
                        && !iface.starts_with("pfsync")
                        && !iface.starts_with("enc")
                })
                .map(String::from)
                .collect();
        }
    }

    // Linux / fallback — detect from /sys/class/net
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        return entries
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|name| name != "lo")
            .collect();
    }

    vec!["em0".to_string(), "em1".to_string()]
}

/// Set the system root password via pw (FreeBSD)
fn set_root_password() {
    let max_attempts = 5;
    for attempt in 1..=max_attempts {
        let pass1 = console::prompt_password("New root password");
        if pass1.len() < 8 {
            console::error("Password must be at least 8 characters.");
            if attempt == max_attempts {
                console::warn(
                    "Max attempts reached. Skipping root password — set it manually later.",
                );
                return;
            }
            continue;
        }
        let pass2 = console::prompt_password("Confirm root password");
        if pass1 != pass2 {
            console::error("Passwords do not match. Try again.");
            if attempt == max_attempts {
                console::warn("Max attempts reached. Skipping root password.");
                return;
            }
            continue;
        }

        #[cfg(target_os = "freebsd")]
        {
            use std::io::Write;
            use std::process::{Command, Stdio};

            let spawn = Command::new("/usr/sbin/pw")
                .args(["usermod", "root", "-h", "0"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn();

            let mut child = match spawn {
                Ok(c) => c,
                Err(e) => {
                    console::error(&format!("Failed to spawn pw: {}", e));
                    return;
                }
            };

            // Take ownership of stdin so we can drop it (close the pipe)
            // before waiting. `pw -h 0` reads a single line from fd 0 and
            // needs either a newline OR EOF to proceed.
            let mut stdin = match child.stdin.take() {
                Some(s) => s,
                None => {
                    console::error("pw stdin was not piped (internal error)");
                    let _ = child.wait();
                    return;
                }
            };
            let write_res = writeln!(stdin, "{}", pass1);
            drop(stdin); // close pipe → pw sees EOF, proceeds

            if let Err(e) = write_res {
                console::error(&format!("Failed to write password to pw stdin: {}", e));
                let _ = child.wait();
                return;
            }

            match child.wait_with_output() {
                Ok(out) if out.status.success() => {
                    console::success("Root password set.");
                    return;
                }
                Ok(out) => {
                    let stderr = String::from_utf8_lossy(&out.stderr);
                    console::error(&format!(
                        "pw usermod failed (exit={:?}): {}",
                        out.status.code(), stderr.trim()
                    ));
                    return;
                }
                Err(e) => {
                    console::error(&format!("Failed to wait for pw: {}", e));
                    return;
                }
            }
        }

        #[cfg(not(target_os = "freebsd"))]
        {
            console::success("Root password set (simulated).");
            return;
        }
    }
}

/// Result of the setup wizard
pub struct WizardResult {
    pub config: SetupConfig,
    pub tuning: Vec<TuningItem>,
}

/// Print the AiFw splash screen
fn splash_screen() {
    println!();
    println!("  \x1b[1;34m╔══════════════════════════════════════════════════╗\x1b[0m");
    println!(
        "  \x1b[1;34m║\x1b[0m                                                  \x1b[1;34m║\x1b[0m"
    );
    println!(
        "  \x1b[1;34m║\x1b[0m      \x1b[1;36m█████╗ ██╗\x1b[0m\x1b[1;37m███████╗██╗    ██╗\x1b[0m            \x1b[1;34m║\x1b[0m"
    );
    println!(
        "  \x1b[1;34m║\x1b[0m     \x1b[1;36m██╔══██╗██║\x1b[0m\x1b[1;37m██╔════╝██║    ██║\x1b[0m            \x1b[1;34m║\x1b[0m"
    );
    println!(
        "  \x1b[1;34m║\x1b[0m     \x1b[1;36m███████║██║\x1b[0m\x1b[1;37m█████╗  ██║ █╗ ██║\x1b[0m            \x1b[1;34m║\x1b[0m"
    );
    println!(
        "  \x1b[1;34m║\x1b[0m     \x1b[1;36m██╔══██║██║\x1b[0m\x1b[1;37m██╔══╝  ██║███╗██║\x1b[0m            \x1b[1;34m║\x1b[0m"
    );
    println!(
        "  \x1b[1;34m║\x1b[0m     \x1b[1;36m██║  ██║██║\x1b[0m\x1b[1;37m██║     ╚███╔███╔╝\x1b[0m            \x1b[1;34m║\x1b[0m"
    );
    println!(
        "  \x1b[1;34m║\x1b[0m     \x1b[1;36m╚═╝  ╚═╝╚═╝\x1b[0m\x1b[1;37m╚═╝      ╚══╝╚══╝\x1b[0m             \x1b[1;34m║\x1b[0m"
    );
    println!(
        "  \x1b[1;34m║\x1b[0m                                                  \x1b[1;34m║\x1b[0m"
    );
    println!(
        "  \x1b[1;34m║\x1b[0m     \x1b[1;37mAI-Powered Firewall for FreeBSD\x1b[0m               \x1b[1;34m║\x1b[0m"
    );
    println!(
        "  \x1b[1;34m║\x1b[0m     \x1b[0;90mBuilt in Rust  •  MIT License\x1b[0m                 \x1b[1;34m║\x1b[0m"
    );
    println!(
        "  \x1b[1;34m║\x1b[0m     \x1b[0;90mgithub.com/ZerosAndOnesLLC/AiFw\x1b[0m                \x1b[1;34m║\x1b[0m"
    );
    println!(
        "  \x1b[1;34m║\x1b[0m                                                  \x1b[1;34m║\x1b[0m"
    );
    println!("  \x1b[1;34m╚══════════════════════════════════════════════════╝\x1b[0m");
    println!();
}

const TOTAL_STEPS: u32 = 11;

fn step(n: u32, title: &str) {
    console::header(&format!("Step {n}/{TOTAL_STEPS} — {title}"));
}

/// Run the full setup wizard
pub fn run_wizard(reconfigure: bool) -> Option<WizardResult> {
    let mut config = SetupConfig::default();

    // ── Splash Screen ───────────────────────────────────────
    splash_screen();
    console::info("Welcome to the AiFw initial setup wizard.");
    console::info("This will configure networking, SSH, firewall rules,");
    console::info("and create your administrator account.");
    println!();

    if reconfigure {
        console::warn("Running in reconfigure mode. Existing config will be overwritten.");
        if !console::confirm("Continue?", true) {
            return None;
        }
    }

    // ── Step 1: Root Password ────────────────────────────────
    step(1, "Root Password");
    console::info("Set the system root password for console access.");
    set_root_password();

    // ── Step 2: SSH Access ───────────────────────────────────
    step(2, "SSH Access");
    console::info("SSH key authentication is recommended. Password auth is less secure.");
    println!();

    let ssh_method_idx = console::select(
        "SSH authentication method",
        &[
            "SSH Key only (recommended)",
            "Password authentication (not recommended)",
        ],
        0,
    );
    config.ssh_auth_method = if ssh_method_idx == 1 {
        SshAuthMethod::Password
    } else {
        SshAuthMethod::KeyOnly
    };

    if config.ssh_auth_method == SshAuthMethod::KeyOnly {
        console::info("You can import SSH keys from your GitHub account.");
        let github_user = console::prompt("GitHub username (leave empty to skip)", "");
        if !github_user.is_empty() {
            console::info(&format!("Fetching keys from github.com/{github_user}..."));
            match fetch_github_keys(&github_user) {
                Ok(keys) if !keys.is_empty() => {
                    console::success(&format!(
                        "Found {} SSH key(s) for {github_user}.",
                        keys.len()
                    ));
                    config.ssh_github_user = Some(github_user);
                    config.ssh_authorized_keys = keys;
                }
                Ok(_) => {
                    console::warn("No SSH keys found for that GitHub user.");
                    console::info(
                        "You can add keys manually later via /root/.ssh/authorized_keys.",
                    );
                }
                Err(e) => {
                    console::warn(&format!("Could not fetch keys: {e}"));
                    console::info("You can add keys manually later.");
                }
            }
        }

        if config.ssh_authorized_keys.is_empty() {
            console::info("You can paste an SSH public key now (or press Enter to skip).");
            let key = console::prompt("SSH public key", "");
            if !key.is_empty()
                && (key.starts_with("ssh-") || key.starts_with("ecdsa-") || key.starts_with("sk-"))
            {
                config.ssh_authorized_keys.push(key);
                console::success("Key added.");
            } else if !key.is_empty() {
                console::warn("Doesn't look like a valid SSH public key. Skipped.");
            }
        }

        if config.ssh_authorized_keys.is_empty() {
            console::warn("No SSH keys configured. Enabling password auth as fallback.");
            config.ssh_auth_method = SshAuthMethod::Password;
        }
    }

    // ── Step 3: Hostname ─────────────────────────────────────
    step(3, "Hostname");
    loop {
        config.hostname = console::prompt("Hostname", &config.hostname);
        // Basic RFC 1123 validation
        if config.hostname.is_empty()
            || config.hostname.len() > 63
            || !config
                .hostname
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
            || config.hostname.starts_with('-')
        {
            console::warn(
                "Invalid hostname. Use letters, numbers, hyphens, and dots (max 63 chars).",
            );
            config.hostname = "aifw".to_string();
            continue;
        }
        break;
    }

    // ── Step 4: System Tuning (auto-detected) ────────────────
    let profile = SystemProfile::detect();
    config.ram_mb = profile.memory.total_mb;
    let tuning_items = tuning::run_tuning_wizard(&profile);

    // ── Step 5: Network Interfaces ───────────────────────────
    step(5, "Network Interfaces");
    let interfaces = detect_interfaces();

    if interfaces.is_empty() {
        console::error("No network interfaces detected!");
        console::info("Continuing with manual configuration...");
        config.wan_interface = console::prompt_required("WAN interface name");
    } else {
        console::info("Detected interfaces:");
        for iface in &interfaces {
            console::info(&format!("  - {iface}"));
        }
        println!();

        if interfaces.len() == 1 {
            config.wan_interface = interfaces[0].clone();
            console::success(&format!(
                "Single interface detected: {}",
                config.wan_interface
            ));
            println!();
            console::warn("Single NIC mode — NAT is not available.");
            console::info("The firewall will operate in filtering mode only.");
            println!();
            config.nat_enabled = false;
        } else {
            let iface_refs: Vec<&str> = interfaces.iter().map(|s| s.as_str()).collect();
            let wan_idx = console::select("Select WAN interface", &iface_refs, 0);
            config.wan_interface = interfaces[wan_idx].clone();

            let remaining: Vec<&str> = interfaces
                .iter()
                .filter(|i| **i != config.wan_interface)
                .map(|s| s.as_str())
                .collect();

            if !remaining.is_empty() && console::confirm("Configure a LAN interface?", true) {
                let lan_idx = console::select("Select LAN interface", &remaining, 0);
                config.lan_interface = Some(remaining[lan_idx].to_string());
                config.nat_enabled = true;
                console::success("NAT will be enabled between WAN and LAN.");
            } else {
                console::info("No LAN interface — NAT disabled.");
                config.nat_enabled = false;
            }
        }
    }

    // ── Step 6: WAN Configuration ────────────────────────────
    step(6, "WAN Configuration");
    let wan_mode_idx = console::select(
        "WAN IP configuration",
        &["DHCP (automatic)", "Static IP"],
        0,
    );
    config.wan_mode = match wan_mode_idx {
        1 => WanMode::Static,
        _ => WanMode::Dhcp,
    };

    if config.wan_mode == WanMode::Static {
        loop {
            let ip = console::prompt_required("WAN IP address (e.g., 203.0.113.1/24)");
            if console::validate_cidr(&ip) {
                config.wan_ip = Some(ip);
                break;
            }
            console::warn("Invalid IP/prefix format. Use format: x.x.x.x/xx");
        }
        loop {
            let gw = console::prompt_required("Default gateway");
            if console::validate_ip(&gw) {
                config.wan_gateway = Some(gw);
                break;
            }
            console::warn("Invalid IP address.");
        }
    }

    // ── Step 7: LAN Configuration ────────────────────────────
    if config.lan_interface.is_some() {
        step(7, "LAN Configuration");
        loop {
            let ip = console::prompt("LAN IP address", "192.168.1.1/24");
            if console::validate_cidr(&ip) {
                config.lan_ip = Some(ip);
                break;
            }
            console::warn("Invalid IP/prefix format.");
        }
        if console::confirm("Enable DHCP server on the LAN interface?", true) {
            config.dhcp_enabled = true;
            console::success("DHCP server will be enabled on LAN.");
        }
    }

    // ── Step 8: Admin Account ────────────────────────────────
    step(8, "Admin Account");
    console::info("Create the administrator account for the web UI.");
    console::info("Password requires 8+ characters: uppercase, lowercase, and number.");
    println!();

    loop {
        config.admin_username = console::prompt("Admin username", "admin");
        if config.admin_username.is_empty()
            || config.admin_username.contains(' ')
            || config.admin_username.len() > 32
        {
            console::warn("Username must be 1-32 characters with no spaces.");
            continue;
        }
        break;
    }

    loop {
        let password = console::prompt_password_confirm("Password");
        match console::validate_password(&password) {
            Ok(()) => {
                config.admin_password_hash = hash_password(&password);
                if config.admin_password_hash.is_empty() {
                    console::error("Password hashing failed. Try again.");
                    continue;
                }
                console::success("Password set.");
                break;
            }
            Err(e) => {
                console::warn(&e);
            }
        }
    }

    // ── Step 9: API & Web UI ─────────────────────────────────
    step(9, "API & Web UI");
    config.api_listen = console::prompt("API listen address", &config.api_listen);
    loop {
        let port_str = console::prompt("API port", &config.api_port.to_string());
        match port_str.parse::<u16>() {
            Ok(p) if p > 0 => {
                config.api_port = p;
                break;
            }
            _ => {
                console::warn("Invalid port number. Enter 1-65535.");
            }
        }
    }
    config.ui_enabled = console::confirm("Enable web UI?", true);

    // ── Step 10: DNS Servers ─────────────────────────────────
    step(10, "DNS Servers");
    loop {
        let dns = console::prompt("DNS servers (comma-separated)", "1.1.1.1,8.8.8.8");
        let servers: Vec<String> = dns
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let all_valid = servers.iter().all(|s| console::validate_ip(s));
        if servers.is_empty() || !all_valid {
            console::warn("Enter valid IP addresses separated by commas.");
            continue;
        }
        config.dns_servers = servers;
        break;
    }

    // ── Step 11: Firewall Policy ─────────────────────────────
    step(11, "Default Firewall Policy");
    let policy_idx = console::select(
        "Default firewall policy",
        &[
            "Standard — block inbound, allow outbound",
            "Strict — block all, explicit allow only",
            "Permissive — allow all (testing only!)",
        ],
        0,
    );
    config.default_policy = match policy_idx {
        1 => DefaultPolicy::Strict,
        2 => DefaultPolicy::Permissive,
        _ => DefaultPolicy::Standard,
    };

    // ── Optional HA step ────────────────────────────────────
    config.cluster = ask_cluster(&config);

    // ── Summary ──────────────────────────────────────────────
    console::header("Configuration Summary");
    println!();
    console::info(&format!("  Hostname:       {}", config.hostname));
    console::info(&format!(
        "  WAN:            {} ({})",
        config.wan_interface, config.wan_mode
    ));
    if let Some(ref ip) = config.wan_ip {
        console::info(&format!("    IP:           {ip}"));
    }
    if let Some(ref gw) = config.wan_gateway {
        console::info(&format!("    Gateway:      {gw}"));
    }
    if let Some(ref iface) = config.lan_interface {
        console::info(&format!("  LAN:            {iface}"));
        if let Some(ref ip) = config.lan_ip {
            console::info(&format!("    IP:           {ip}"));
        }
    }
    console::info(&format!("  SSH:            {}", config.ssh_auth_method));
    if let Some(ref gh) = config.ssh_github_user {
        console::info(&format!(
            "    GitHub keys:  {gh} ({} key(s))",
            config.ssh_authorized_keys.len()
        ));
    } else if !config.ssh_authorized_keys.is_empty() {
        console::info(&format!(
            "    Keys:         {} manual key(s)",
            config.ssh_authorized_keys.len()
        ));
    }
    console::info(&format!("  Admin:          {}", config.admin_username));
    console::info(&format!(
        "  API:            {}:{}",
        config.api_listen, config.api_port
    ));
    console::info(&format!(
        "  Web UI:         {}",
        if config.ui_enabled {
            "enabled"
        } else {
            "disabled"
        }
    ));
    console::info(&format!(
        "  NAT:            {}",
        if config.nat_enabled {
            "enabled"
        } else {
            "disabled"
        }
    ));
    console::info(&format!(
        "  DHCP:           {}",
        if config.dhcp_enabled {
            "enabled (LAN)"
        } else {
            "disabled"
        }
    ));
    console::info(&format!(
        "  DNS:            {}",
        config.dns_servers.join(", ")
    ));
    console::info(&format!("  Policy:         {}", config.default_policy));
    let tuning_enabled = tuning_items.iter().filter(|t| t.enabled).count();
    console::info(&format!(
        "  Tuning:         {} optimizations",
        tuning_enabled
    ));
    if let Some(ref c) = config.cluster {
        console::info(&format!("  HA role:        {}", c.role));
        console::info(&format!("  pfsync iface:   {}", c.pfsync_iface));
        console::info(&format!("  Peer:           {}", c.peer_address));
        console::info(&format!("  CARP VIPs:      {}", c.vips.len()));
    } else {
        console::info("  HA:             standalone");
    }
    println!();

    if console::confirm("Apply this configuration?", true) {
        Some(WizardResult {
            config,
            tuning: tuning_items,
        })
    } else {
        console::info("Setup cancelled.");
        None
    }
}

/// Ask whether this node is part of an HA pair and collect cluster settings.
/// Returns `None` if the operator declines or enters invalid data.
fn ask_cluster(config: &SetupConfig) -> Option<WizardClusterConfig> {
    if !console::confirm(
        "Configure this node as part of an HA pair? (Two AiFw boxes sharing a virtual IP via CARP + pfsync)",
        false,
    ) {
        return None;
    }

    let role_idx = console::select(
        "Is this the PRIMARY (master under normal load) or SECONDARY node?",
        &["primary", "secondary"],
        0,
    );
    let role = match role_idx {
        0 => aifw_common::ClusterRole::Primary,
        _ => aifw_common::ClusterRole::Secondary,
    };

    let pfsync_iface = console::prompt_required("Which interface carries pfsync traffic? (a dedicated NIC is strongly recommended)");

    let peer_address = loop {
        let s = console::prompt_required("Peer node IP on the pfsync link:");
        match s.parse::<std::net::IpAddr>() {
            Ok(addr) => break addr,
            Err(_) => console::error("Not a valid IP address."),
        }
    };

    // CARP password — min 8 chars, and must not contain characters that are
    // shell-significant inside double-quoted rc.conf values (" ' ` $ \).
    // rc.conf is sourced by /bin/sh at boot; these chars would corrupt the
    // value or execute arbitrary code as root.
    let password = loop {
        let pw = console::prompt_password("CARP password (will be shared with peer; min 8 chars):");
        if pw.len() < 8 {
            console::error("Password must be at least 8 characters.");
            continue;
        }
        if pw.chars().any(|c| matches!(c, '"' | '\'' | '`' | '$' | '\\')) {
            console::error(
                "CARP password may not contain quotes, backticks, dollar signs, or backslashes.",
            );
            continue;
        }
        break pw;
    };

    let mut vips = Vec::new();
    for iface_label in &["WAN", "LAN"] {
        if !console::confirm(&format!("Add a CARP VIP on the {iface_label} interface?"), true) {
            continue;
        }
        let default_iface = if *iface_label == "WAN" {
            config.wan_interface.as_str()
        } else {
            config.lan_interface.as_deref().unwrap_or("")
        };
        let interface = console::prompt(&format!("{iface_label} interface name:"), default_iface);
        if interface.is_empty() {
            console::warn("Interface name required — skipping this VIP.");
            continue;
        }
        let vip_str = console::prompt_required(&format!("Virtual IP on {interface} (e.g. 192.0.2.1):"));
        let virtual_ip = match vip_str.parse::<std::net::IpAddr>() {
            Ok(ip) => ip,
            Err(_) => {
                console::error("Invalid IP address — skipping this VIP.");
                continue;
            }
        };
        let prefix: u8 = loop {
            let s = console::prompt("Prefix length (e.g. 24):", "24");
            match s.parse::<u8>() {
                Ok(p) if p <= 128 => break p,
                _ => console::warn("Enter a valid prefix length (0-32 for IPv4, 0-128 for IPv6)."),
            }
        };
        let vhid: u8 = loop {
            let s = console::prompt_required("CARP VHID (1-255, must match peer):");
            match s.parse::<u8>() {
                Ok(v) if v >= 1 => break v,
                _ => console::warn("VHID must be 1-255."),
            }
        };
        vips.push(WizardCarpVip {
            interface,
            vhid,
            virtual_ip,
            prefix,
            // 100 is a conservative backup-skew default — operator can tune via the
            // cluster config UI later (see #227 latency profiles).  Primary nodes
            // always render advskew=0 at apply time regardless of this value.
            advskew: 100,
            // 1 is the minimum stable advbase per CARP spec.
            advbase: 1,
        });
    }

    Some(WizardClusterConfig {
        role,
        pfsync_iface,
        peer_address,
        vips,
        password,
    })
}

/// Fetch SSH public keys from a GitHub user's profile.
fn fetch_github_keys(username: &str) -> Result<Vec<String>, String> {
    let url = format!("https://github.com/{username}.keys");

    let output = std::process::Command::new("fetch")
        .args(["-qo", "-", &url])
        .output()
        .or_else(|_| {
            std::process::Command::new("curl")
                .args(["-sL", &url])
                .output()
        })
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    if !output.status.success() {
        return Err("Failed to fetch keys (HTTP error)".to_string());
    }

    let body = String::from_utf8_lossy(&output.stdout);
    let keys: Vec<String> = body
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| l.starts_with("ssh-") || l.starts_with("ecdsa-") || l.starts_with("sk-"))
        .collect();

    Ok(keys)
}

fn hash_password(password: &str) -> String {
    use argon2::{
        Argon2, PasswordHasher, password_hash::SaltString, password_hash::rand_core::OsRng,
    };
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .unwrap_or_default()
}
