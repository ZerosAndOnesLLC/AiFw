use serde::{Deserialize, Serialize};

/// Complete setup configuration produced by the wizard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupConfig {
    pub hostname: String,

    // Network
    pub wan_interface: String,
    pub wan_mode: WanMode,
    pub wan_ip: Option<String>,
    pub wan_gateway: Option<String>,
    pub lan_interface: Option<String>,
    pub lan_ip: Option<String>,

    // Admin
    pub admin_username: String,
    pub admin_password_hash: String,
    pub totp_secret: String,
    pub totp_enabled: bool,
    pub recovery_codes: Vec<String>,

    // Services
    pub api_listen: String,
    pub api_port: u16,
    pub ui_enabled: bool,

    // DNS
    pub dns_servers: Vec<String>,

    // Services
    pub dhcp_enabled: bool,

    // Firewall
    pub default_policy: DefaultPolicy,
    pub nat_enabled: bool,

    // SSH
    pub ssh_auth_method: SshAuthMethod,
    pub ssh_github_user: Option<String>,
    pub ssh_authorized_keys: Vec<String>,

    // System
    /// Detected RAM in MB — used to auto-size memory caches
    #[serde(default = "default_ram_mb")]
    pub ram_mb: u64,

    // Paths
    pub db_path: String,
    pub config_dir: String,

    // Unattended-seed-only secrets (#533 Phase 2). Accepted when loading a
    // seed file via `aifw-setup --config`, converted by
    // `resolve_seed_secrets()`, and NEVER serialized back into aifw.conf
    // (`skip_serializing`) so plaintext never lands on disk post-setup.
    /// Plaintext admin password; hashed into `admin_password_hash` at load.
    /// Ignored when `admin_password_hash` is already set.
    #[serde(default, skip_serializing)]
    pub admin_password: Option<String>,
    /// Plaintext root password, applied non-interactively during setup.
    #[serde(default, skip_serializing)]
    pub root_password: Option<String>,

    // HA cluster (set by wizard; not persisted in aifw.conf JSON)
    #[serde(skip)]
    pub cluster: Option<WizardClusterConfig>,
}

impl SetupConfig {
    /// Convert seed-file secrets into their applied form: hash a plaintext
    /// `admin_password` into `admin_password_hash` (unless a hash was
    /// already provided, which wins) and drop the plaintext. Errors when
    /// the seed carries neither, or the password is under 8 characters
    /// (matching the wizard's policy).
    pub fn resolve_seed_secrets(&mut self) -> Result<(), String> {
        if self.admin_password_hash.is_empty() {
            match self.admin_password.take() {
                Some(p) if p.len() >= 8 => {
                    self.admin_password_hash = hash_password(&p)
                        .map_err(|e| format!("failed to hash admin_password: {e}"))?;
                }
                Some(_) => {
                    return Err("admin_password must be at least 8 characters".to_string());
                }
                None => {
                    return Err(
                        "seed must provide admin_password or admin_password_hash".to_string()
                    );
                }
            }
        } else {
            // Hash present — discard any plaintext so it can't leak onward.
            self.admin_password = None;
        }
        Ok(())
    }

    /// Sanity checks for an unattended seed before applying it.
    pub fn validate_seed(&self) -> Result<(), String> {
        if self.admin_username.trim().is_empty() {
            return Err("admin_username must not be empty".to_string());
        }
        if self.hostname.trim().is_empty() {
            return Err("hostname must not be empty".to_string());
        }
        if self.wan_interface.trim().is_empty() {
            return Err("wan_interface must not be empty".to_string());
        }
        if matches!(self.wan_mode, WanMode::Static) && self.wan_ip.is_none() {
            return Err("static wan_mode requires wan_ip".to_string());
        }
        if self.lan_ip.is_some() && self.lan_interface.is_none() {
            return Err("lan_ip requires lan_interface".to_string());
        }
        if self.api_port == 0 {
            return Err("api_port must not be 0".to_string());
        }
        Ok(())
    }

    /// Example seed file for `aifw-setup --config` (unattended setup).
    /// Placeholder values are deliberately invalid-looking so an unedited
    /// template can't produce a silently misconfigured appliance.
    pub fn seed_template() -> String {
        serde_json::to_string_pretty(&serde_json::json!({
            "hostname": "aifw",
            "wan_interface": "CHANGE-ME-eg-vtnet0",
            "wan_mode": "dhcp",
            "wan_ip": null,
            "wan_gateway": null,
            "lan_interface": null,
            "lan_ip": null,
            "admin_username": "admin",
            "admin_password": "CHANGE-ME-min-8-chars",
            "admin_password_hash": "",
            "root_password": null,
            "totp_secret": "",
            "totp_enabled": false,
            "recovery_codes": [],
            "api_listen": "0.0.0.0",
            "api_port": 8080,
            "ui_enabled": true,
            "dns_servers": ["9.9.9.9", "1.1.1.1"],
            "dhcp_enabled": false,
            "default_policy": "standard",
            "nat_enabled": true,
            "ssh_auth_method": "password",
            "ssh_github_user": null,
            "ssh_authorized_keys": [],
            "db_path": "/var/db/aifw/aifw.db",
            "config_dir": "/usr/local/etc/aifw"
        }))
        .unwrap_or_default()
            + "\n"
    }
}

/// Argon2id password hashing — delegates to the workspace-wide pinned
/// parameters in `aifw_common::password` so the first admin's hash is
/// identical in shape to every hash the API writes later (SEC-M4 #301).
/// Shared by the wizard and the unattended seed loader.
pub fn hash_password(password: &str) -> Result<String, String> {
    aifw_common::password::hash_password(password).map_err(|e| e.to_string())
}

fn default_ram_mb() -> u64 {
    1024
}

// ============================================================
// HA / Cluster wizard config (not serialized — only used in-process
// during wizard run → apply())
// ============================================================

/// Per-VIP configuration collected by the HA wizard step
#[derive(Debug, Clone)]
pub struct WizardCarpVip {
    pub interface: String,
    pub vhid: u8,
    pub virtual_ip: std::net::IpAddr,
    pub prefix: u8,
}

/// Cluster configuration collected by the HA wizard step
#[derive(Debug, Clone)]
pub struct WizardClusterConfig {
    pub role: aifw_common::ClusterRole,
    pub pfsync_iface: String,
    pub peer_address: std::net::IpAddr,
    pub vips: Vec<WizardCarpVip>,
    pub password: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum SshAuthMethod {
    /// SSH key authentication only (recommended)
    KeyOnly,
    /// Password authentication (not recommended)
    Password,
}

impl std::fmt::Display for SshAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SshAuthMethod::KeyOnly => write!(f, "SSH Key (recommended)"),
            SshAuthMethod::Password => write!(f, "Password (not recommended)"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum WanMode {
    Dhcp,
    Static,
    Pppoe,
}

impl std::fmt::Display for WanMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WanMode::Dhcp => write!(f, "DHCP"),
            WanMode::Static => write!(f, "Static"),
            WanMode::Pppoe => write!(f, "PPPoE"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DefaultPolicy {
    /// Block inbound, allow outbound
    Standard,
    /// Block all, explicit allow only
    Strict,
    /// Allow all (testing only)
    Permissive,
}

impl std::fmt::Display for DefaultPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DefaultPolicy::Standard => write!(f, "Standard (block inbound, allow outbound)"),
            DefaultPolicy::Strict => write!(f, "Strict (block all, explicit allow only)"),
            DefaultPolicy::Permissive => write!(f, "Permissive (allow all — testing only)"),
        }
    }
}

impl Default for SetupConfig {
    fn default() -> Self {
        Self {
            hostname: "aifw".to_string(),
            wan_interface: "em0".to_string(),
            wan_mode: WanMode::Dhcp,
            wan_ip: None,
            wan_gateway: None,
            lan_interface: None,
            lan_ip: None,
            admin_username: "admin".to_string(),
            admin_password_hash: String::new(),
            totp_secret: String::new(),
            totp_enabled: false,
            recovery_codes: Vec::new(),
            api_listen: "0.0.0.0".to_string(),
            api_port: 8080,
            ui_enabled: true,
            dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            dhcp_enabled: false,
            default_policy: DefaultPolicy::Standard,
            nat_enabled: false,
            ssh_auth_method: SshAuthMethod::KeyOnly,
            ssh_github_user: None,
            ssh_authorized_keys: Vec::new(),
            ram_mb: 1024,
            db_path: "/var/db/aifw/aifw.db".to_string(),
            admin_password: None,
            root_password: None,
            config_dir: "/usr/local/etc/aifw".to_string(),
            cluster: None,
        }
    }
}
