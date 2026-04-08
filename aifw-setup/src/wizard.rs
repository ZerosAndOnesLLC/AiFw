use crate::config::{DefaultPolicy, SetupConfig, SshAuthMethod, WanMode};
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

    // Ultimate fallback
    vec!["em0".to_string(), "em1".to_string()]
}

/// Set the system root password via chpasswd/pw
fn set_root_password() {
    loop {
        let pass1 = console::prompt_password("New root password");
        if pass1.len() < 8 {
            console::error("Password must be at least 8 characters.");
            continue;
        }
        let pass2 = console::prompt_password("Confirm root password");
        if pass1 != pass2 {
            console::error("Passwords do not match. Try again.");
            continue;
        }

        // Use pw on FreeBSD, chpasswd on Linux (dev)
        #[cfg(target_os = "freebsd")]
        {
            use std::process::{Command, Stdio};
            let mut child = Command::new("pw")
                .args(["usermod", "root", "-h", "0"])
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .ok();
            if let Some(ref mut c) = child {
                use std::io::Write;
                if let Some(ref mut stdin) = c.stdin {
                    let _ = stdin.write_all(pass1.as_bytes());
                }
                match c.wait() {
                    Ok(status) if status.success() => {
                        console::success("Root password set.");
                        return;
                    }
                    _ => {
                        console::error("Failed to set root password.");
                    }
                }
            }
        }

        #[cfg(not(target_os = "freebsd"))]
        {
            console::success("Root password set (simulated — not on FreeBSD).");
            return;
        }
    }
}

/// Result of the setup wizard
pub struct WizardResult {
    pub config: SetupConfig,
    pub tuning: Vec<TuningItem>,
}

/// Run the full setup wizard
pub fn run_wizard(reconfigure: bool) -> Option<WizardResult> {
    let mut config = SetupConfig::default();

    // ── Step 1: Welcome ──────────────────────────────────────
    console::header("AiFw — AI-Powered Firewall for FreeBSD");
    console::info("Welcome to the AiFw initial setup wizard.");
    console::info("This will configure your firewall, create an admin account,");
    console::info("and set up multi-factor authentication.");
    println!();
    console::info("All features are free and open source (MIT).");
    println!();

    if reconfigure {
        console::warn("Running in reconfigure mode. Existing config will be overwritten.");
        if !console::confirm("Continue?", true) {
            return None;
        }
    }

    // ── Step 1: Root Password ─────────────────────────────────
    console::header("Step 1/12 — Root Password");
    console::info("Set the system root password for console access.");
    set_root_password();

    // ── Step 2: SSH Access ───────────────────────────────────
    console::header("Step 2/12 — SSH Access");
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
    config.ssh_auth_method = if ssh_method_idx == 1 { SshAuthMethod::Password } else { SshAuthMethod::KeyOnly };

    if config.ssh_auth_method == SshAuthMethod::KeyOnly {
        console::info("You can import SSH keys from your GitHub account.");
        let github_user = console::prompt("GitHub username (leave empty to skip)", "");
        if !github_user.is_empty() {
            console::info(&format!("Fetching keys from github.com/{github_user}..."));
            match fetch_github_keys(&github_user) {
                Ok(keys) if !keys.is_empty() => {
                    console::success(&format!("Found {} SSH key(s) for {github_user}.", keys.len()));
                    config.ssh_github_user = Some(github_user);
                    config.ssh_authorized_keys = keys;
                }
                Ok(_) => {
                    console::warn("No SSH keys found for that GitHub user.");
                    console::info("You can add keys manually later via the web UI or /root/.ssh/authorized_keys.");
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
            if !key.is_empty() && (key.starts_with("ssh-") || key.starts_with("ecdsa-") || key.starts_with("sk-")) {
                config.ssh_authorized_keys.push(key);
                console::success("Key added.");
            } else if !key.is_empty() {
                console::warn("Doesn't look like a valid SSH public key. Skipped.");
            }
        }

        if config.ssh_authorized_keys.is_empty() {
            console::warn("No SSH keys configured. You will need to add keys manually before SSH key auth works.");
            console::info("Temporarily enabling password auth as fallback.");
            config.ssh_auth_method = SshAuthMethod::Password;
        }
    }

    // ── Step 3: Hostname ─────────────────────────────────────
    console::header("Step 3/12 — Hostname");
    config.hostname = console::prompt("Hostname", &config.hostname);

    // ── Step 3: System Detection & Tuning ──────────────────
    let profile = SystemProfile::detect();
    let tuning_items = tuning::run_tuning_wizard(&profile);

    // ── Step 3: Network Interfaces ───────────────────────────
    console::header("Step 5/12 — Network Interfaces");
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
            // Single NIC mode
            config.wan_interface = interfaces[0].clone();
            console::success(&format!("Single interface detected: {}", config.wan_interface));
            println!();
            console::warn("Single NIC mode — NAT is not available.");
            console::info("NAT requires a WAN and LAN interface (minimum 2 NICs).");
            console::info("The firewall will operate in filtering mode only.");
            println!();
            config.nat_enabled = false;
        } else {
            // Multi-NIC mode
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
                console::info("No LAN interface configured — NAT disabled.");
                config.nat_enabled = false;
            }
        }
    }

    // ── Step 4: WAN Configuration ────────────────────────────
    console::header("Step 6/12 — WAN Configuration");
    let wan_mode_idx = console::select(
        "WAN IP configuration",
        &["DHCP (automatic)", "Static IP", "PPPoE"],
        0,
    );
    config.wan_mode = match wan_mode_idx {
        1 => WanMode::Static,
        2 => WanMode::Pppoe,
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

    // ── Step 5: LAN Configuration ────────────────────────────
    if config.lan_interface.is_some() {
        console::header("Step 7/12 — LAN Configuration");
        loop {
            let ip = console::prompt("LAN IP address", "192.168.1.1/24");
            if console::validate_cidr(&ip) {
                config.lan_ip = Some(ip);
                break;
            }
            console::warn("Invalid IP/prefix format.");
        }
        // Ask about DHCP server on LAN
        if console::confirm("Enable DHCP server on the LAN interface?", true) {
            config.dhcp_enabled = true;
            console::success("DHCP server will be enabled on LAN.");
        }
    } else {
        console::header("Step 7/12 — LAN Configuration");
        if config.nat_enabled {
            console::info("No LAN interface configured. NAT disabled.");
        } else {
            console::info("Single NIC mode — skipping LAN configuration.");
        }
    }

    // ── Step 6: Admin Account ────────────────────────────────
    console::header("Step 8/12 — Admin Account");
    console::info("Create the administrator account.");
    console::info("Password must be 8+ characters with uppercase, lowercase, and number.");
    println!();

    config.admin_username = console::prompt("Admin username", "admin");

    loop {
        let password = console::prompt_password_confirm("Password");
        match console::validate_password(&password) {
            Ok(()) => {
                // Hash the password
                config.admin_password_hash = hash_password(&password);
                console::success("Password set.");
                break;
            }
            Err(e) => {
                console::warn(&e);
            }
        }
    }

    // MFA is configured via the web UI after first login

    // ── Step 7: API / UI Access ──────────────────────────────
    console::header("Step 9/12 — API & Web UI");
    config.api_listen = console::prompt("API listen address", &config.api_listen);
    let port_str = console::prompt("API port", &config.api_port.to_string());
    config.api_port = port_str.parse().unwrap_or(8080);
    config.ui_enabled = console::confirm("Enable web UI?", true);

    // ── Step 9: DNS ──────────────────────────────────────────
    console::header("Step 10/12 — DNS Servers");
    let dns = console::prompt("DNS servers (comma-separated)", "1.1.1.1,8.8.8.8");
    config.dns_servers = dns.split(',').map(|s| s.trim().to_string()).collect();

    // ── Step 10: Firewall Policy ─────────────────────────────
    console::header("Step 11/12 — Default Firewall Policy");
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

    // ── Summary ──────────────────────────────────────────────
    console::header("Step 12/12 — Summary");
    console::info(&format!("Hostname:       {}", config.hostname));
    console::info(&format!("WAN:            {} ({})", config.wan_interface, config.wan_mode));
    if let Some(ref ip) = config.wan_ip {
        console::info(&format!("  IP:           {ip}"));
    }
    if let Some(ref gw) = config.wan_gateway {
        console::info(&format!("  Gateway:      {gw}"));
    }
    if let Some(ref iface) = config.lan_interface {
        console::info(&format!("LAN:            {iface}"));
        if let Some(ref ip) = config.lan_ip {
            console::info(&format!("  IP:           {ip}"));
        }
    }
    console::info(&format!("SSH:            {}", config.ssh_auth_method));
    if let Some(ref gh) = config.ssh_github_user {
        console::info(&format!("  GitHub keys:  {gh} ({} key(s))", config.ssh_authorized_keys.len()));
    } else if !config.ssh_authorized_keys.is_empty() {
        console::info(&format!("  Keys:         {} manual key(s)", config.ssh_authorized_keys.len()));
    }
    console::info(&format!("Admin:          {}", config.admin_username));
    console::info(&format!("MFA:            {}", if config.totp_enabled { "enabled" } else { "disabled" }));
    console::info(&format!("API:            {}:{}", config.api_listen, config.api_port));
    console::info(&format!("Web UI:         {}", if config.ui_enabled { "enabled" } else { "disabled" }));
    console::info(&format!("NAT:            {}", if config.nat_enabled { "enabled" } else { "disabled (single NIC)" }));
    console::info(&format!("DHCP Server:    {}", if config.dhcp_enabled { "enabled (LAN)" } else { "disabled" }));
    console::info(&format!("DNS:            {}", config.dns_servers.join(", ")));
    console::info(&format!("Policy:         {}", config.default_policy));
    console::info(&format!("Database:       {}", config.db_path));
    let tuning_enabled = tuning_items.iter().filter(|t| t.enabled).count();
    console::info(&format!("Tuning:         {} optimizations", tuning_enabled));
    println!();

    if console::confirm("Apply this configuration?", true) {
        Some(WizardResult { config, tuning: tuning_items })
    } else {
        console::info("Setup cancelled.");
        None
    }
}

/// Fetch SSH public keys from a GitHub user's profile.
fn fetch_github_keys(username: &str) -> Result<Vec<String>, String> {
    let url = format!("https://github.com/{username}.keys");

    // Try fetch (FreeBSD) then curl
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
    use argon2::{Argon2, PasswordHasher, password_hash::SaltString, password_hash::rand_core::OsRng};
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .unwrap_or_default()
}
