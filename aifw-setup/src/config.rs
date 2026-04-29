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

    // HA cluster (set by wizard; not persisted in aifw.conf JSON)
    #[serde(skip)]
    pub cluster: Option<WizardClusterConfig>,
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
    /// Backup advskew; primary always renders 0 at apply time
    pub advskew: u8,
    pub advbase: u8,
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
            config_dir: "/usr/local/etc/aifw".to_string(),
            cluster: None,
        }
    }
}
