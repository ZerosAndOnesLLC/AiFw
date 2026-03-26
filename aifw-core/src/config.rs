use serde::{Deserialize, Serialize};

/// The complete firewall configuration — single source of truth.
/// Every config change produces a new version of this struct.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    /// Schema version for forward compatibility
    pub schema_version: u32,

    pub system: SystemConfig,
    pub auth: AuthConfig,
    pub rules: Vec<RuleConfig>,
    pub nat: Vec<NatRuleConfig>,
    pub queues: Vec<QueueConfigEntry>,
    pub rate_limits: Vec<RateLimitEntry>,
    pub vpn: VpnConfig,
    pub geoip: Vec<GeoIpEntry>,
    pub tls: TlsConfig,
    pub ha: HaConfig,
    pub tuning: Vec<TuningEntry>,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            schema_version: 1,
            system: SystemConfig::default(),
            auth: AuthConfig::default(),
            rules: Vec::new(),
            nat: Vec::new(),
            queues: Vec::new(),
            rate_limits: Vec::new(),
            vpn: VpnConfig::default(),
            geoip: Vec::new(),
            tls: TlsConfig::default(),
            ha: HaConfig::default(),
            tuning: Vec::new(),
        }
    }
}

impl FirewallConfig {
    /// Compute a SHA-256 hash of the config for diff detection
    pub fn hash(&self) -> String {
        let json = serde_json::to_string(self).unwrap_or_default();
        sha256_hex(&json)
    }

    /// Serialize to pretty JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    /// Deserialize from JSON
    pub fn from_json(json: &str) -> Result<Self, String> {
        serde_json::from_str(json).map_err(|e| format!("config parse error: {e}"))
    }

    /// Count total resources
    pub fn resource_count(&self) -> usize {
        self.rules.len()
            + self.nat.len()
            + self.queues.len()
            + self.rate_limits.len()
            + self.vpn.wireguard.len()
            + self.vpn.ipsec.len()
            + self.geoip.len()
            + self.tls.sni_rules.len()
    }
}

// ============================================================
// Sub-config sections
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfig {
    pub hostname: String,
    pub dns_servers: Vec<String>,
    pub wan_interface: String,
    pub lan_interface: Option<String>,
    pub lan_ip: Option<String>,
    pub api_listen: String,
    pub api_port: u16,
    pub ui_enabled: bool,
}

impl Default for SystemConfig {
    fn default() -> Self {
        Self {
            hostname: "aifw".to_string(),
            dns_servers: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            wan_interface: "em0".to_string(),
            lan_interface: None,
            lan_ip: None,
            api_listen: "0.0.0.0".to_string(),
            api_port: 8080,
            ui_enabled: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    pub access_token_expiry_mins: i64,
    pub refresh_token_expiry_days: i64,
    pub require_totp: bool,
    pub require_totp_for_oauth: bool,
    pub auto_create_oauth_users: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            access_token_expiry_mins: 15,
            refresh_token_expiry_days: 7,
            require_totp: false,
            require_totp_for_oauth: false,
            auto_create_oauth_users: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    pub id: String,
    pub priority: i32,
    pub action: String,
    pub direction: String,
    pub protocol: String,
    pub interface: Option<String>,
    pub src_addr: Option<String>,
    pub src_port_start: Option<u16>,
    pub src_port_end: Option<u16>,
    pub dst_addr: Option<String>,
    pub dst_port_start: Option<u16>,
    pub dst_port_end: Option<u16>,
    pub log: bool,
    pub quick: bool,
    pub label: Option<String>,
    pub state_tracking: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatRuleConfig {
    pub id: String,
    pub nat_type: String,
    pub interface: String,
    pub protocol: String,
    pub src_addr: Option<String>,
    pub src_port_start: Option<u16>,
    pub src_port_end: Option<u16>,
    pub dst_addr: Option<String>,
    pub dst_port_start: Option<u16>,
    pub dst_port_end: Option<u16>,
    pub redirect_addr: String,
    pub redirect_port_start: Option<u16>,
    pub redirect_port_end: Option<u16>,
    pub label: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueConfigEntry {
    pub id: String,
    pub name: String,
    pub interface: String,
    pub queue_type: String,
    pub bandwidth_value: u64,
    pub bandwidth_unit: String,
    pub traffic_class: String,
    pub bandwidth_pct: Option<u8>,
    pub default: bool,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitEntry {
    pub id: String,
    pub name: String,
    pub interface: Option<String>,
    pub protocol: String,
    pub dst_port_start: Option<u16>,
    pub dst_port_end: Option<u16>,
    pub max_connections: u32,
    pub window_secs: u32,
    pub overload_table: String,
    pub flush_states: bool,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VpnConfig {
    pub wireguard: Vec<WireguardTunnelConfig>,
    pub ipsec: Vec<IpsecSaConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireguardTunnelConfig {
    pub id: String,
    pub name: String,
    pub interface: String,
    pub listen_port: u16,
    pub address: String,
    pub private_key: String,
    pub public_key: String,
    pub dns: Option<String>,
    pub mtu: Option<u16>,
    pub peers: Vec<WireguardPeerConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireguardPeerConfig {
    pub id: String,
    pub name: String,
    pub public_key: String,
    pub preshared_key: Option<String>,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpsecSaConfig {
    pub id: String,
    pub name: String,
    pub src_addr: String,
    pub dst_addr: String,
    pub protocol: String,
    pub mode: String,
    pub enc_algo: String,
    pub auth_algo: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpEntry {
    pub id: String,
    pub country: String,
    pub action: String,
    pub label: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    pub min_version: String,
    pub block_self_signed: bool,
    pub block_expired: bool,
    pub block_weak_keys: bool,
    pub blocked_ja3: Vec<String>,
    pub sni_rules: Vec<SniRuleConfig>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            min_version: "tls12".to_string(),
            block_self_signed: false,
            block_expired: true,
            block_weak_keys: true,
            blocked_ja3: Vec::new(),
            sni_rules: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SniRuleConfig {
    pub id: String,
    pub pattern: String,
    pub action: String,
    pub label: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HaConfig {
    pub carp_vips: Vec<CarpVipConfig>,
    pub pfsync: Option<PfsyncEntry>,
    pub nodes: Vec<ClusterNodeConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarpVipConfig {
    pub id: String,
    pub vhid: u8,
    pub virtual_ip: String,
    pub prefix: u8,
    pub interface: String,
    pub advskew: u8,
    pub advbase: u8,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PfsyncEntry {
    pub sync_interface: String,
    pub sync_peer: Option<String>,
    pub defer: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNodeConfig {
    pub id: String,
    pub name: String,
    pub address: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuningEntry {
    pub key: String,
    pub value: String,
    pub target: String,
    pub reason: String,
    pub enabled: bool,
}

// ============================================================
// SHA-256 (pure Rust, for config hashing)
// ============================================================

fn sha256_hex(input: &str) -> String {
    let bytes = input.as_bytes();
    let hash = sha256(bytes);
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256(msg: &[u8]) -> [u8; 32] {
    let k: [u32; 64] = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
    ];
    let bit_len = (msg.len() as u64) * 8;
    let mut padded = msg.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 { padded.push(0); }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }
        let [mut a,mut b,mut c,mut d,mut e,mut f,mut g,mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(k[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh=g; g=f; f=e; e=d.wrapping_add(t1); d=c; c=b; b=a; a=t1.wrapping_add(t2);
        }
        for (i, v) in [a,b,c,d,e,f,g,hh].iter().enumerate() {
            h[i] = h[i].wrapping_add(*v);
        }
    }
    let mut result = [0u8; 32];
    for (i, val) in h.iter().enumerate() {
        result[i*4..i*4+4].copy_from_slice(&val.to_be_bytes());
    }
    result
}
