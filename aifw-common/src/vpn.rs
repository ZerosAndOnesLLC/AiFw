use crate::types::{Address, Interface};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ============================================================
// WireGuard
// ============================================================

/// A server-side WireGuard tunnel (one wg interface with its keypair and subnet)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgTunnel {
    /// Unique identifier
    pub id: Uuid,
    /// Human-readable tunnel name; also used in pf rule labels
    pub name: String,
    /// WireGuard interface (e.g. "wg0")
    pub interface: Interface,
    /// Server private key (base64)
    pub private_key: String,
    /// Server public key (base64), embedded in client configs
    pub public_key: String,
    /// UDP port the tunnel listens on
    pub listen_port: u16,
    /// Server's tunnel address with prefix (e.g. 10.10.0.1/24); defines the tunnel subnet
    pub address: Address,
    /// DNS server(s) pushed to clients in generated configs; None omits the DNS line
    pub dns: Option<String>,
    /// Interface MTU; None uses the system default
    pub mtu: Option<u16>,
    /// Physical interface to listen on (e.g. "vtnet0"). None = listen on all.
    pub listen_interface: Option<String>,
    /// Comma-separated CIDRs to route through the tunnel when a client uses
    /// split-tunnel mode (e.g. `172.29.0.0/16, 10.0.0.0/8`). When `None`, the
    /// split-tunnel config falls back to the tunnel's own network CIDR.
    #[serde(default)]
    pub split_routes: Option<String>,
    /// Current tunnel state (up/down/error)
    pub status: VpnStatus,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp
    pub updated_at: DateTime<Utc>,
}

impl WgTunnel {
    /// Create a tunnel with a freshly generated in-process X25519 keypair,
    /// status `Down`, and no DNS/MTU overrides. Fails if the OS CSPRNG is
    /// unavailable — never constructs a tunnel with an invalid keypair.
    pub fn new(
        name: String,
        interface: Interface,
        listen_port: u16,
        address: Address,
    ) -> crate::Result<Self> {
        let (private_key, public_key) = generate_wg_keypair()?;
        let now = Utc::now();
        Ok(Self {
            id: Uuid::new_v4(),
            name,
            interface,
            private_key,
            public_key,
            listen_port,
            address,
            dns: None,
            mtu: None,
            listen_interface: None,
            split_routes: None,
            status: VpnStatus::Down,
            created_at: now,
            updated_at: now,
        })
    }

    /// Generate ifconfig commands to create the WireGuard interface
    pub fn to_ifconfig_cmds(&self) -> Vec<String> {
        let mut cmds = vec![
            format!("ifconfig {} create", self.interface),
            format!("ifconfig {} inet {} up", self.interface, self.address),
        ];
        if let Some(mtu) = self.mtu {
            cmds.push(format!("ifconfig {} mtu {mtu}", self.interface));
        }
        cmds
    }

    /// Generate pf rules to allow WireGuard traffic
    pub fn to_pf_rules(&self) -> Vec<String> {
        // If listen_interface is set, bind the UDP rule to that interface
        let on_iface = match &self.listen_interface {
            Some(iface) if !iface.is_empty() && iface != "any" => format!(" on {iface}"),
            _ => String::new(),
        };
        vec![
            // Allow WireGuard UDP port (optionally on specific interface)
            format!(
                "pass in quick{on_iface} proto udp to any port {} keep state label \"wg-{}\"",
                self.listen_port, self.name
            ),
            // Allow all traffic on the WireGuard tunnel interface (flags any = ICMP/UDP too)
            format!(
                "pass quick on {} flags any keep state label \"wg-{}-tunnel\"",
                self.interface, self.name
            ),
        ]
    }

    /// Network CIDR of the tunnel subnet, masked to the network boundary
    /// (e.g. address 10.10.0.1/24 → "10.10.0.0/24").
    pub fn network_cidr(&self) -> String {
        address_network_cidr(&self.address)
    }

    /// Outbound NAT rule so tunnel clients reach the internet through the
    /// WAN (#469). Only IPv4 tunnel subnets are NAT'd — returns None for
    /// IPv6 / alias / any addresses so we never masquerade 0.0.0.0/0.
    pub fn to_nat_rule(&self, wan_if: &str) -> Option<String> {
        use std::net::IpAddr;
        match &self.address {
            Address::Single(IpAddr::V4(_)) | Address::Network(IpAddr::V4(_), _) => Some(format!(
                "nat on {wan_if} from {} to any -> ({wan_if})",
                self.network_cidr()
            )),
            _ => None,
        }
    }
}

/// AllowedIPs for a full-tunnel client config, scoped to the address
/// families the tunnel's inner network can carry.
fn full_tunnel_allowed_ips(addr: &Address) -> &'static str {
    use std::net::IpAddr;
    match addr {
        Address::Single(IpAddr::V4(_)) | Address::Network(IpAddr::V4(_), _) => "0.0.0.0/0",
        Address::Single(IpAddr::V6(_)) | Address::Network(IpAddr::V6(_), _) => "::/0",
        _ => "0.0.0.0/0, ::/0",
    }
}

/// A WireGuard peer (client) attached to a tunnel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgPeer {
    /// Unique identifier
    pub id: Uuid,
    /// Tunnel this peer belongs to
    pub tunnel_id: Uuid,
    /// Human-readable peer name
    pub name: String,
    /// Peer public key (base64)
    pub public_key: String,
    /// Optional preshared key (base64) for an extra symmetric encryption layer
    pub preshared_key: Option<String>,
    /// Client private key — stored so we can generate the client config.
    /// Only present when the keypair was auto-generated by the server.
    pub client_private_key: Option<String>,
    /// Peer's remote address as host:port; None for roaming clients
    pub endpoint: Option<String>,
    /// Addresses allowed from/routed to this peer; the first entry doubles as
    /// the client's address in generated configs
    pub allowed_ips: Vec<Address>,
    /// Keepalive interval in seconds, for peers behind NAT; None disables keepalives
    pub persistent_keepalive: Option<u16>,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp
    pub updated_at: DateTime<Utc>,
}

impl WgPeer {
    /// Create a peer with an externally supplied public key, allowed_ips
    /// defaulting to `Any`, and no PSK/endpoint/keepalive
    pub fn new(tunnel_id: Uuid, name: String, public_key: String) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            tunnel_id,
            name,
            public_key,
            preshared_key: None,
            client_private_key: None,
            endpoint: None,
            allowed_ips: vec![Address::Any],
            persistent_keepalive: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// Create a peer with an auto-generated keypair (private key stored for
    /// config export). Fails if the OS CSPRNG is unavailable.
    pub fn new_with_generated_key(tunnel_id: Uuid, name: String) -> crate::Result<Self> {
        let (private_key, public_key) = generate_wg_keypair()?;
        let mut peer = Self::new(tunnel_id, name, public_key);
        peer.client_private_key = Some(private_key);
        Ok(peer)
    }

    /// Generate a WireGuard client .conf file for this peer.
    /// `tunnel` is the server-side tunnel this peer belongs to.
    /// `server_endpoint` is the firewall's public IP or hostname.
    /// `split_tunnel` — if true, only routes the tunnel subnet through the VPN (split VPN).
    ///                   if false, routes all traffic through the VPN (full tunnel).
    pub fn to_client_config(
        &self,
        tunnel: &WgTunnel,
        server_endpoint: &str,
        split_tunnel: bool,
    ) -> String {
        let mut conf = String::from("[Interface]\n");
        if let Some(ref pk) = self.client_private_key {
            conf.push_str(&format!("PrivateKey = {pk}\n"));
        } else {
            conf.push_str("PrivateKey = <paste-your-private-key-here>\n");
        }
        // Use the first allowed_ip as the client's address
        if let Some(addr) = self.allowed_ips.first() {
            conf.push_str(&format!("Address = {addr}\n"));
        }
        if let Some(ref dns) = tunnel.dns
            && !dns.is_empty()
        {
            conf.push_str(&format!("DNS = {dns}\n"));
        }
        if let Some(mtu) = tunnel.mtu {
            conf.push_str(&format!("MTU = {mtu}\n"));
        }
        conf.push_str(&format!("\n[Peer]\nPublicKey = {}\n", tunnel.public_key));
        if let Some(ref psk) = self.preshared_key {
            conf.push_str(&format!("PresharedKey = {psk}\n"));
        }
        conf.push_str(&format!(
            "Endpoint = {server_endpoint}:{}\n",
            tunnel.listen_port
        ));
        if split_tunnel {
            // Prefer admin-configured split routes; otherwise derive the
            // network CIDR from the tunnel address (so 172.29.240.1/24 yields
            // 172.29.240.0/24 instead of a host/prefix that confuses some
            // clients).
            let routes = tunnel
                .split_routes
                .as_deref()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .unwrap_or_else(|| address_network_cidr(&tunnel.address));
            conf.push_str(&format!("AllowedIPs = {routes}\n"));
        } else {
            // Route all traffic through the VPN — but only the address
            // families the tunnel's inner network actually carries. Emitting
            // ::/0 for a v4-only tunnel blackholes all IPv6 traffic on
            // dual-stack clients (#469).
            conf.push_str(&format!(
                "AllowedIPs = {}\n",
                full_tunnel_allowed_ips(&tunnel.address)
            ));
        }
        if let Some(ka) = self.persistent_keepalive {
            conf.push_str(&format!("PersistentKeepalive = {ka}\n"));
        }
        conf
    }

    /// Generate wg set command for this peer
    pub fn to_wg_cmd(&self, iface: &Interface) -> String {
        let mut parts = vec![format!("wg set {} peer {}", iface, self.public_key)];

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

/// IPsec protocol selection (wire values are snake_case)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IpsecProtocol {
    /// ESP — encryption + authentication
    Esp,
    /// AH — authentication only, no encryption
    Ah,
    /// ESP and AH combined
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
    /// Parse a protocol from a string, case-insensitively. Accepts
    /// "esp+ah"/"espah"/"esp_ah" for the combined mode.
    /// Fails with a validation error on any other input.
    pub fn parse(s: &str) -> crate::Result<Self> {
        match s.to_lowercase().as_str() {
            "esp" => Ok(IpsecProtocol::Esp),
            "ah" => Ok(IpsecProtocol::Ah),
            "esp+ah" | "espah" | "esp_ah" => Ok(IpsecProtocol::EspAh),
            _ => Err(crate::AifwError::Validation(format!(
                "unknown IPsec protocol: {s}"
            ))),
        }
    }
}

/// IPsec encapsulation mode (wire values are snake_case)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IpsecMode {
    /// Tunnel mode — encapsulates the whole IP packet (site-to-site); traffic
    /// also flows over the enc0 pseudo-interface
    Tunnel,
    /// Transport mode — protects only the payload between two hosts
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
    /// Unique identifier
    pub id: Uuid,
    /// Human-readable SA name; also used in pf rule labels
    pub name: String,
    /// Local endpoint address
    pub src_addr: Address,
    /// Remote endpoint address
    pub dst_addr: Address,
    /// IPsec protocol (ESP/AH/both)
    pub protocol: IpsecProtocol,
    /// Tunnel or transport mode
    pub mode: IpsecMode,
    /// Security Parameter Index identifying this SA (randomly generated, >= 0x100)
    pub spi: u32,
    /// Encryption algorithm name (default "aes-256-gcm")
    pub enc_algo: String,
    /// Authentication algorithm name (default "hmac-sha256")
    pub auth_algo: String,
    /// Current SA state (up/down/error)
    pub status: VpnStatus,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp
    pub updated_at: DateTime<Utc>,
}

impl IpsecSa {
    /// Create an SA with a random SPI, default algorithms
    /// (aes-256-gcm / hmac-sha256), and status `Down`
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
    /// Unique identifier
    pub id: Uuid,
    /// Security Association this policy is bound to
    pub sa_id: Uuid,
    /// Whether the policy applies to inbound or outbound traffic
    pub direction: SpDirection,
    /// Source network the policy matches
    pub src_network: Address,
    /// Destination network the policy matches
    pub dst_network: Address,
    /// IPsec protocol to apply (ESP/AH/both)
    pub protocol: IpsecProtocol,
    /// Tunnel or transport mode
    pub mode: IpsecMode,
    /// How strictly IPsec is enforced for matching traffic
    pub level: SpLevel,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
}

/// Direction of an IPsec security policy (wire values are lowercase)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SpDirection {
    /// Applies to inbound traffic
    In,
    /// Applies to outbound traffic
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

/// setkey policy level — how strictly IPsec is enforced (wire values are lowercase)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SpLevel {
    /// Matching traffic must be protected by IPsec or it is dropped
    Require,
    /// Use IPsec when an SA is available, otherwise send in the clear
    Use,
    /// Like require, but with an SA unique to this policy
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
    /// Create a policy with level `Require` and the creation time set to now
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

/// Operational state of a VPN tunnel or SA (wire values are lowercase)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VpnStatus {
    /// Tunnel is configured and active
    Up,
    /// Tunnel is configured but not active
    Down,
    /// Tunnel failed to come up or encountered a runtime error
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

/// Kind of VPN a record refers to (wire values are lowercase)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VpnType {
    /// WireGuard tunnel
    WireGuard,
    /// IPsec SA/SP
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
// Key generation (in-process X25519, no `wg` subprocess)
// ============================================================

/// Generate a WireGuard keypair: 32 CSPRNG bytes clamped per the Curve25519
/// convention (matching `wg genkey`), public key derived in-process via
/// X25519. Fails closed if the OS CSPRNG is unavailable — never returns a
/// pair whose halves aren't cryptographically related (#541).
pub fn generate_wg_keypair() -> crate::Result<(String, String)> {
    let mut secret_bytes = [0u8; 32];
    getrandom::fill(&mut secret_bytes)
        .map_err(|e| crate::AifwError::Crypto(format!("OS CSPRNG unavailable: {e}")))?;
    // Clamp so the stored private key is byte-identical to `wg genkey` output
    // for the same entropy; X25519 impls clamp on use, so this is idempotent.
    secret_bytes[0] &= 248;
    secret_bytes[31] &= 127;
    secret_bytes[31] |= 64;
    let secret = x25519_dalek::StaticSecret::from(secret_bytes);
    let public = x25519_dalek::PublicKey::from(&secret);
    Ok((
        base64_encode(&secret.to_bytes()),
        base64_encode(public.as_bytes()),
    ))
}

/// Derive the WireGuard public key for a base64-encoded private key.
/// Errors on malformed input (not valid base64 / not 32 bytes).
pub fn derive_wg_pubkey(private_key_b64: &str) -> crate::Result<String> {
    let bytes = base64_decode(private_key_b64)
        .ok_or_else(|| crate::AifwError::Crypto("private key is not valid base64".to_string()))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| crate::AifwError::Crypto("private key must decode to 32 bytes".to_string()))?;
    let secret = x25519_dalek::StaticSecret::from(arr);
    Ok(base64_encode(
        x25519_dalek::PublicKey::from(&secret).as_bytes(),
    ))
}

/// Generate a WireGuard preshared key (32 OS-CSPRNG bytes, base64 encoded).
/// Fails closed if the OS CSPRNG is unavailable.
pub fn generate_wg_psk() -> crate::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes)
        .map_err(|e| crate::AifwError::Crypto(format!("OS CSPRNG unavailable: {e}")))?;
    Ok(base64_encode(&bytes))
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
        let _ = write!(
            result,
            "{}",
            CHARS[((triple >> 18) & 0x3F) as usize] as char
        );
        let _ = write!(
            result,
            "{}",
            CHARS[((triple >> 12) & 0x3F) as usize] as char
        );
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

/// Decode standard base64 (with padding). Returns `None` on any malformed
/// input. Counterpart to `base64_encode`; kept dependency-free like it.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some((c - b'A') as u32),
            b'a'..=b'z' => Some((c - b'a' + 26) as u32),
            b'0'..=b'9' => Some((c - b'0' + 52) as u32),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let s = s.trim().as_bytes();
    if s.is_empty() || !s.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    for chunk in s.chunks(4) {
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        if pad > 2 || chunk[..4 - pad].iter().any(|&c| val(c).is_none()) {
            return None;
        }
        // '=' only valid as trailing padding
        if chunk[..4 - pad].contains(&b'=') {
            return None;
        }
        let mut triple: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            let v = if c == b'=' { 0 } else { val(c)? };
            triple |= v << (18 - 6 * i);
        }
        out.push((triple >> 16) as u8);
        if pad < 2 {
            out.push((triple >> 8) as u8);
        }
        if pad < 1 {
            out.push(triple as u8);
        }
    }
    Some(out)
}

/// Generate a random SPI value for IPsec
fn rand_spi() -> u32 {
    let id = Uuid::new_v4();
    let bytes = id.as_bytes();
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) | 0x100
}

/// Turn an Address into a WireGuard-friendly network CIDR string.
/// `Address::Network(172.29.240.1, 24)` → `"172.29.240.0/24"` (masked to the
/// network boundary). Falls back to "0.0.0.0/0" for non-network variants.
fn address_network_cidr(addr: &crate::types::Address) -> String {
    use crate::types::Address;
    use std::net::IpAddr;
    match addr {
        Address::Network(ip, prefix) => match ip {
            IpAddr::V4(v4) => {
                let p = (*prefix).min(32);
                let bits = u32::from(*v4);
                let mask: u32 = if p == 0 { 0 } else { u32::MAX << (32 - p) };
                let net = std::net::Ipv4Addr::from(bits & mask);
                format!("{net}/{p}")
            }
            IpAddr::V6(v6) => {
                let p = (*prefix).min(128);
                let bits = u128::from(*v6);
                let mask: u128 = if p == 0 { 0 } else { u128::MAX << (128 - p) };
                let net = std::net::Ipv6Addr::from(bits & mask);
                format!("{net}/{p}")
            }
        },
        Address::Single(ip) => match ip {
            IpAddr::V4(_) => format!("{ip}/32"),
            IpAddr::V6(_) => format!("{ip}/128"),
        },
        _ => "0.0.0.0/0".to_string(),
    }
}

#[cfg(test)]
mod split_tunnel_tests {
    use super::*;
    use crate::types::Address;

    #[test]
    fn network_cidr_masks_to_boundary() {
        let a = Address::Network("172.29.240.1".parse().unwrap(), 24);
        assert_eq!(address_network_cidr(&a), "172.29.240.0/24");
    }

    #[test]
    fn network_cidr_handles_slash_16() {
        let a = Address::Network("172.29.5.1".parse().unwrap(), 16);
        assert_eq!(address_network_cidr(&a), "172.29.0.0/16");
    }

    #[test]
    fn single_address_becomes_host_route() {
        let a = Address::Single("10.0.0.1".parse().unwrap());
        assert_eq!(address_network_cidr(&a), "10.0.0.1/32");
    }

    #[test]
    fn split_routes_override_wins() {
        let tunnel = WgTunnel {
            id: Uuid::new_v4(),
            name: "wg0".into(),
            interface: crate::types::Interface("wg0".into()),
            private_key: "x".into(),
            public_key: "y".into(),
            listen_port: 51820,
            address: Address::Network("172.29.240.1".parse().unwrap(), 24),
            dns: None,
            mtu: None,
            listen_interface: None,
            split_routes: Some("172.29.0.0/16, 10.0.0.0/8".into()),
            status: VpnStatus::Down,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let peer = WgPeer {
            id: Uuid::new_v4(),
            tunnel_id: tunnel.id,
            name: "peer1".into(),
            public_key: "pk".into(),
            preshared_key: None,
            client_private_key: Some("cpk".into()),
            endpoint: None,
            allowed_ips: vec![Address::Network("172.29.240.2".parse().unwrap(), 32)],
            persistent_keepalive: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let cfg = peer.to_client_config(&tunnel, "1.2.3.4", true);
        assert!(cfg.contains("AllowedIPs = 172.29.0.0/16, 10.0.0.0/8"));
    }

    #[test]
    fn split_routes_fallback_is_network_not_host() {
        let tunnel = WgTunnel {
            id: Uuid::new_v4(),
            name: "wg0".into(),
            interface: crate::types::Interface("wg0".into()),
            private_key: "x".into(),
            public_key: "y".into(),
            listen_port: 51820,
            address: Address::Network("172.29.240.1".parse().unwrap(), 24),
            dns: None,
            mtu: None,
            listen_interface: None,
            split_routes: None,
            status: VpnStatus::Down,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let peer = WgPeer {
            id: Uuid::new_v4(),
            tunnel_id: tunnel.id,
            name: "peer1".into(),
            public_key: "pk".into(),
            preshared_key: None,
            client_private_key: Some("cpk".into()),
            endpoint: None,
            allowed_ips: vec![Address::Network("172.29.240.2".parse().unwrap(), 32)],
            persistent_keepalive: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let cfg = peer.to_client_config(&tunnel, "1.2.3.4", true);
        assert!(cfg.contains("AllowedIPs = 172.29.240.0/24"));
        assert!(!cfg.contains("172.29.240.1/24"));
    }

    fn test_tunnel(address: Address) -> WgTunnel {
        WgTunnel {
            id: Uuid::new_v4(),
            name: "wg0".into(),
            interface: crate::types::Interface("wg0".into()),
            private_key: "x".into(),
            public_key: "y".into(),
            listen_port: 51820,
            address,
            dns: None,
            mtu: None,
            listen_interface: None,
            split_routes: None,
            status: VpnStatus::Down,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn test_peer(tunnel_id: Uuid) -> WgPeer {
        WgPeer {
            id: Uuid::new_v4(),
            tunnel_id,
            name: "peer1".into(),
            public_key: "pk".into(),
            preshared_key: None,
            client_private_key: Some("cpk".into()),
            endpoint: None,
            allowed_ips: vec![Address::Network("10.10.0.2".parse().unwrap(), 32)],
            persistent_keepalive: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn full_tunnel_v4_omits_v6_route() {
        let tunnel = test_tunnel(Address::Network("10.10.0.1".parse().unwrap(), 24));
        let cfg = test_peer(tunnel.id).to_client_config(&tunnel, "vpn.example.com", false);
        assert!(cfg.contains("AllowedIPs = 0.0.0.0/0\n"));
        assert!(!cfg.contains("::/0"));
    }

    #[test]
    fn full_tunnel_v6_emits_v6_route_only() {
        let tunnel = test_tunnel(Address::Network("fd00:a1f0::1".parse().unwrap(), 64));
        let cfg = test_peer(tunnel.id).to_client_config(&tunnel, "vpn.example.com", false);
        assert!(cfg.contains("AllowedIPs = ::/0\n"));
        assert!(!cfg.contains("0.0.0.0/0"));
    }

    #[test]
    fn nat_rule_masks_to_network_boundary() {
        let tunnel = test_tunnel(Address::Network("10.10.0.1".parse().unwrap(), 24));
        assert_eq!(
            tunnel.to_nat_rule("em0").as_deref(),
            Some("nat on em0 from 10.10.0.0/24 to any -> (em0)")
        );
    }

    #[test]
    fn nat_rule_skipped_for_non_v4_addresses() {
        let v6 = test_tunnel(Address::Network("fd00:a1f0::1".parse().unwrap(), 64));
        assert_eq!(v6.to_nat_rule("em0"), None);
        let any = test_tunnel(Address::Any);
        assert_eq!(any.to_nat_rule("em0"), None);
    }
}
