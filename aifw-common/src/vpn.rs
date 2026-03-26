use crate::types::{Address, Interface};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================
// WireGuard
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgTunnel {
    pub id: Uuid,
    pub name: String,
    pub interface: Interface,
    pub private_key: String,
    pub public_key: String,
    pub listen_port: u16,
    pub address: Address,
    pub dns: Option<String>,
    pub mtu: Option<u16>,
    pub status: VpnStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl WgTunnel {
    pub fn new(name: String, interface: Interface, listen_port: u16, address: Address) -> Self {
        let (private_key, public_key) = generate_wg_keypair();
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            interface,
            private_key,
            public_key,
            listen_port,
            address,
            dns: None,
            mtu: None,
            status: VpnStatus::Down,
            created_at: now,
            updated_at: now,
        }
    }

    /// Generate ifconfig commands to create the WireGuard interface
    pub fn to_ifconfig_cmds(&self) -> Vec<String> {
        let mut cmds = vec![
            format!("ifconfig {} create", self.interface),
            format!(
                "ifconfig {} inet {} up",
                self.interface, self.address
            ),
        ];
        if let Some(mtu) = self.mtu {
            cmds.push(format!("ifconfig {} mtu {mtu}", self.interface));
        }
        cmds
    }

    /// Generate pf rules to allow WireGuard traffic
    pub fn to_pf_rules(&self) -> Vec<String> {
        vec![
            // Allow WireGuard UDP port
            format!(
                "pass in quick proto udp to any port {} keep state label \"wg-{}\"",
                self.listen_port, self.name
            ),
            // Allow all traffic on the WireGuard interface
            format!(
                "pass quick on {} keep state label \"wg-{}-tunnel\"",
                self.interface, self.name
            ),
        ]
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgPeer {
    pub id: Uuid,
    pub tunnel_id: Uuid,
    pub name: String,
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<Address>,
    pub persistent_keepalive: Option<u16>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl WgPeer {
    pub fn new(tunnel_id: Uuid, name: String, public_key: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            tunnel_id,
            name,
            public_key,
            preshared_key: None,
            endpoint: None,
            allowed_ips: vec![Address::Any],
            persistent_keepalive: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Generate wg set command for this peer
    pub fn to_wg_cmd(&self, iface: &Interface) -> String {
        let mut parts = vec![format!(
            "wg set {} peer {}",
            iface, self.public_key
        )];

        if let Some(ref endpoint) = self.endpoint {
            parts.push(format!("endpoint {endpoint}"));
        }

        let allowed: Vec<String> = self.allowed_ips.iter().map(|a| a.to_string()).collect();
        if !allowed.is_empty() {
            parts.push(format!("allowed-ips {}", allowed.join(",")));
        }

        if let Some(ka) = self.persistent_keepalive {
            parts.push(format!("persistent-keepalive {ka}"));
        }

        if let Some(ref psk) = self.preshared_key {
            parts.push(format!("preshared-key {psk}"));
        }

        parts.join(" ")
    }
}

// ============================================================
// IPsec
// ============================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IpsecProtocol {
    Esp,
    Ah,
    EspAh,
}

impl std::fmt::Display for IpsecProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpsecProtocol::Esp => write!(f, "esp"),
            IpsecProtocol::Ah => write!(f, "ah"),
            IpsecProtocol::EspAh => write!(f, "esp+ah"),
        }
    }
}

impl IpsecProtocol {
    pub fn parse(s: &str) -> crate::Result<Self> {
        match s.to_lowercase().as_str() {
            "esp" => Ok(IpsecProtocol::Esp),
            "ah" => Ok(IpsecProtocol::Ah),
            "esp+ah" | "espah" | "esp_ah" => Ok(IpsecProtocol::EspAh),
            _ => Err(crate::AifwError::Validation(format!("unknown IPsec protocol: {s}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IpsecMode {
    Tunnel,
    Transport,
}

impl std::fmt::Display for IpsecMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpsecMode::Tunnel => write!(f, "tunnel"),
            IpsecMode::Transport => write!(f, "transport"),
        }
    }
}

/// IPsec Security Association
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpsecSa {
    pub id: Uuid,
    pub name: String,
    pub src_addr: Address,
    pub dst_addr: Address,
    pub protocol: IpsecProtocol,
    pub mode: IpsecMode,
    pub spi: u32,
    pub enc_algo: String,
    pub auth_algo: String,
    pub status: VpnStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl IpsecSa {
    pub fn new(
        name: String,
        src_addr: Address,
        dst_addr: Address,
        protocol: IpsecProtocol,
        mode: IpsecMode,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            src_addr,
            dst_addr,
            protocol,
            mode,
            spi: rand_spi(),
            enc_algo: "aes-256-gcm".to_string(),
            auth_algo: "hmac-sha256".to_string(),
            status: VpnStatus::Down,
            created_at: now,
            updated_at: now,
        }
    }

    /// Generate pf rules for IPsec traffic
    pub fn to_pf_rules(&self) -> Vec<String> {
        let proto = match self.protocol {
            IpsecProtocol::Esp | IpsecProtocol::EspAh => "esp",
            IpsecProtocol::Ah => "ah",
        };

        let mut rules = vec![
            // Allow IPsec protocol traffic between endpoints
            format!(
                "pass in quick proto {} from {} to {} keep state label \"ipsec-{}-in\"",
                proto, self.src_addr, self.dst_addr, self.name
            ),
            format!(
                "pass out quick proto {} from {} to {} keep state label \"ipsec-{}-out\"",
                proto, self.dst_addr, self.src_addr, self.name
            ),
            // Allow IKE (UDP 500 + 4500)
            format!(
                "pass in quick proto udp from {} to {} port {{ 500 4500 }} keep state label \"ike-{}-in\"",
                self.src_addr, self.dst_addr, self.name
            ),
            format!(
                "pass out quick proto udp from {} to {} port {{ 500 4500 }} keep state label \"ike-{}-out\"",
                self.dst_addr, self.src_addr, self.name
            ),
        ];

        // If tunnel mode, also allow enc0 traffic
        if self.mode == IpsecMode::Tunnel {
            rules.push(format!(
                "pass quick on enc0 keep state label \"ipsec-{}-tunnel\"",
                self.name
            ));
        }

        rules
    }
}

/// IPsec Security Policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpsecSp {
    pub id: Uuid,
    pub sa_id: Uuid,
    pub direction: SpDirection,
    pub src_network: Address,
    pub dst_network: Address,
    pub protocol: IpsecProtocol,
    pub mode: IpsecMode,
    pub level: SpLevel,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SpDirection {
    In,
    Out,
}

impl std::fmt::Display for SpDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpDirection::In => write!(f, "in"),
            SpDirection::Out => write!(f, "out"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SpLevel {
    Require,
    Use,
    Unique,
}

impl std::fmt::Display for SpLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpLevel::Require => write!(f, "require"),
            SpLevel::Use => write!(f, "use"),
            SpLevel::Unique => write!(f, "unique"),
        }
    }
}

impl IpsecSp {
    pub fn new(
        sa_id: Uuid,
        direction: SpDirection,
        src_network: Address,
        dst_network: Address,
        protocol: IpsecProtocol,
        mode: IpsecMode,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            sa_id,
            direction,
            src_network,
            dst_network,
            protocol,
            mode,
            level: SpLevel::Require,
            created_at: Utc::now(),
        }
    }

    /// Generate setkey policy line
    pub fn to_setkey_cmd(&self) -> String {
        format!(
            "spdadd {} {} any -P {} ipsec {}/{}/{}/{}",
            self.src_network,
            self.dst_network,
            self.direction,
            self.protocol,
            self.mode,
            self.src_network,
            self.level,
        )
    }
}

// ============================================================
// Common VPN types
// ============================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VpnStatus {
    Up,
    Down,
    Error,
}

impl std::fmt::Display for VpnStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VpnStatus::Up => write!(f, "up"),
            VpnStatus::Down => write!(f, "down"),
            VpnStatus::Error => write!(f, "error"),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VpnType {
    WireGuard,
    Ipsec,
}

impl std::fmt::Display for VpnType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VpnType::WireGuard => write!(f, "wireguard"),
            VpnType::Ipsec => write!(f, "ipsec"),
        }
    }
}

// ============================================================
// Key generation helpers (mock for non-FreeBSD)
// ============================================================

/// Generate a WireGuard keypair.
/// On non-FreeBSD this returns placeholder base64 strings.
/// On FreeBSD, this would shell out to `wg genkey` / `wg pubkey`.
pub fn generate_wg_keypair() -> (String, String) {
    // Generate deterministic-looking but unique placeholder keys
    let id = Uuid::new_v4();
    let bytes = id.as_bytes();
    let private = base64_encode(bytes);
    // "Public key" derived by reversing bytes (placeholder)
    let mut pub_bytes = *bytes;
    pub_bytes.reverse();
    let public = base64_encode(&pub_bytes);
    (private, public)
}

/// Generate a WireGuard preshared key
pub fn generate_wg_psk() -> String {
    let id = Uuid::new_v4();
    base64_encode(id.as_bytes())
}

fn base64_encode(data: &[u8]) -> String {
    use std::fmt::Write;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        let _ = write!(result, "{}", CHARS[((triple >> 18) & 0x3F) as usize] as char);
        let _ = write!(result, "{}", CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            let _ = write!(result, "{}", CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            let _ = write!(result, "{}", CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

/// Generate a random SPI value for IPsec
fn rand_spi() -> u32 {
    let id = Uuid::new_v4();
    let bytes = id.as_bytes();
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) | 0x100
}
