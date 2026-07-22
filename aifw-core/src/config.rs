use aifw_common::{
    Action, BandwidthUnit, Direction, GeoIpAction, GeoIpRuleStatus, IpVersion, IpsecMode,
    IpsecProtocol, NatStatus, NatType, Protocol, QueueStatus, QueueType, RateLimitStatus,
    RuleStatus, SniAction, StateTracking, TrafficClass,
};
use serde::{Deserialize, Serialize};

/// Highest `schema_version` that [`FirewallConfig::validate`] will accept.
/// Bump this when adding a required top-level field; older backups with a
/// matching-or-lower version will still restore via the per-field
/// `#[serde(default)]` defaults.
pub const CURRENT_SCHEMA_VERSION: u32 = 1;

/// The complete firewall configuration — single source of truth.
/// Every config change produces a new version of this struct.
///
/// `deny_unknown_fields` at the top level makes corrupt or tampered
/// backups fail loudly rather than silently restoring only the fields
/// we recognize — a future config field added by an attacker (hoping
/// we'd grow support for it and honour the value) is now rejected.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FirewallConfig {
    /// Schema version for forward compatibility
    pub schema_version: u32,

    /// Hostname, interfaces, DNS, API listen address, console/SSH access
    pub system: SystemConfig,
    /// Token lifetimes and TOTP/OAuth login policy
    pub auth: AuthConfig,
    /// Filter rules, ordered by priority
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    /// NAT rules (SNAT, DNAT/port-forward, masquerade, binat, NAT64/46)
    #[serde(default)]
    pub nat: Vec<NatRuleConfig>,
    /// Traffic-shaping queue definitions
    #[serde(default)]
    pub queues: Vec<QueueConfigEntry>,
    /// Per-source-IP connection rate limits
    #[serde(default)]
    pub rate_limits: Vec<RateLimitEntry>,
    /// WireGuard tunnels and IPsec SAs
    #[serde(default)]
    pub vpn: VpnConfig,
    /// Per-country geo-IP allow/block entries
    #[serde(default)]
    pub geoip: Vec<GeoIpEntry>,
    /// TLS inspection policy (min version, cert checks, JA3/SNI rules)
    #[serde(default)]
    pub tls: TlsConfig,
    /// High availability: CARP VIPs, pfsync, cluster nodes
    #[serde(default)]
    pub ha: HaConfig,
    /// Tuning overrides (currently just the `pf.max_states` sysctl)
    #[serde(default)]
    pub tuning: Vec<TuningEntry>,
    /// DHCP subnets, reservations, global config, DDNS, HA. Added in a later
    /// schema rev — `#[serde(default)]` keeps older backups deserialising.
    #[serde(default)]
    pub dhcp: DhcpSection,
    /// Named aliases (host / network / port / urltable). Round-tripped so
    /// snapshot+restore (and the OPNsense importer's pre-import snapshot)
    /// can revert alias additions cleanly.
    #[serde(default)]
    pub aliases: Vec<AliasConfig>,
    /// Static routes. Same rationale as aliases — without this section,
    /// snapshot/restore silently drops every route the user defined.
    #[serde(default)]
    pub static_routes: Vec<StaticRouteConfig>,
    /// rDNS/unbound resolver settings (the `dns_resolver_config` table).
    /// `None` means the backup predates this section (#589) — restore
    /// leaves the box's resolver config untouched rather than resetting
    /// it to defaults.
    #[serde(default)]
    pub dns_resolver: Option<DnsResolverSection>,
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
            dhcp: DhcpSection::default(),
            aliases: Vec::new(),
            static_routes: Vec::new(),
            dns_resolver: None,
        }
    }
}

/// A named pf alias as captured in a config snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AliasConfig {
    /// Unique alias ID (UUID string)
    pub id: String,
    /// Alias name referenced from rules
    pub name: String,
    /// Kind of entries — `host`, `network`, `port`, or `url_table`
    pub alias_type: String,
    /// Member values (IPs, CIDRs, ports, or a URL depending on type)
    pub entries: Vec<String>,
    /// Optional free-form note
    #[serde(default)]
    pub description: Option<String>,
    /// Whether the alias is applied to pf (defaults to true on restore)
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// A static route as captured in a config snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticRouteConfig {
    /// Unique route ID (UUID string)
    pub id: String,
    /// Destination network in CIDR notation
    pub destination: String,
    /// Next-hop gateway IP
    pub gateway: String,
    /// Optional egress interface name; None = let the kernel pick
    #[serde(default)]
    pub interface: Option<String>,
    /// Route metric (lower wins)
    #[serde(default)]
    pub metric: i32,
    /// Whether the route is installed (defaults to true on restore)
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Optional free-form note
    #[serde(default)]
    pub description: Option<String>,
    /// FreeBSD FIB (routing table) number; 0 = default table
    #[serde(default)]
    pub fib: u32,
}

impl FirewallConfig {
    /// Compute a SHA-256 hash of the config for diff detection
    pub fn hash(&self) -> String {
        // Serialization failure is structurally impossible for the
        // current FirewallConfig (no Serialize impl in the tree throws);
        // log loudly if that ever changes so the empty-hash drift is
        // visible instead of silently corrupting config history.
        let json = serde_json::to_string(self).unwrap_or_else(|e| {
            tracing::error!(error = %e, "FirewallConfig::hash serialize failed");
            String::new()
        });
        sha256_hex(&json)
    }

    /// Serialize to pretty JSON
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_else(|e| {
            tracing::error!(error = %e, "FirewallConfig::to_json serialize failed");
            String::new()
        })
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

    /// Basic sanity check for a config being *restored* from a backup file.
    /// Caller should run this before any persistence/apply so a malformed
    /// or adversarial backup can't corrupt the daemon state.
    ///
    /// Not intended as a full semantic validator — per-entity engines
    /// re-validate on add.
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version == 0 || self.schema_version > CURRENT_SCHEMA_VERSION {
            return Err(format!(
                "unsupported schema_version {}: expected 1..={}",
                self.schema_version, CURRENT_SCHEMA_VERSION
            ));
        }
        if self.rules.len() > 10_000 {
            return Err(format!(
                "rules count {} exceeds cap 10000",
                self.rules.len()
            ));
        }
        if self.nat.len() > 10_000 {
            return Err(format!("nat count {} exceeds cap 10000", self.nat.len()));
        }
        if self.geoip.len() > 1_000 {
            return Err(format!("geoip count {} exceeds cap 1000", self.geoip.len()));
        }
        if self.vpn.wireguard.len() > 1_000 || self.vpn.ipsec.len() > 1_000 {
            return Err("vpn tunnel count exceeds cap 1000".to_string());
        }
        if self.system.hostname.len() > 253
            || self.system.hostname.contains('\0')
            || self.system.hostname.contains('\n')
        {
            return Err("system.hostname invalid".to_string());
        }
        for s in &self.system.dns_servers {
            if s.parse::<std::net::IpAddr>().is_err() {
                return Err(format!("system.dns_servers entry {s} is not a valid IP"));
            }
        }
        if self.system.api_port == 0 {
            return Err("system.api_port cannot be 0".to_string());
        }
        if let Some(r) = &self.dns_resolver {
            for s in &r.forwarding_servers {
                if s.parse::<std::net::IpAddr>().is_err() {
                    return Err(format!(
                        "dns_resolver.forwarding_servers entry {s} is not a valid IP"
                    ));
                }
            }
            if r.blocklist_urls.len() > 10_000
                || r.whitelist.len() > 100_000
                || r.forwarding_servers.len() > 100
                || r.dot_upstream.len() > 100
                || r.listen_interfaces.len() > 100
                || r.private_addresses.len() > 1_000
            {
                return Err("dns_resolver list length exceeds cap".to_string());
            }
        }
        Ok(())
    }
}

// ============================================================
// Sub-config sections
// ============================================================

/// System-level settings: identity, interfaces, DNS, API endpoint, and
/// console/SSH access
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemConfig {
    /// System hostname (validated on restore: max 253 chars, no NUL/newline)
    pub hostname: String,
    /// Upstream DNS resolver IPs (validated on restore)
    pub dns_servers: Vec<String>,
    /// WAN-facing network interface name (e.g. `em0`)
    pub wan_interface: String,
    /// LAN interface name; None = no LAN side configured
    pub lan_interface: Option<String>,
    /// LAN interface address; None = no LAN side configured
    pub lan_ip: Option<String>,
    /// Address the REST API binds to
    pub api_listen: String,
    /// TCP port the REST API and web UI listen on (must be non-zero)
    pub api_port: u16,
    /// Whether the API serves the web UI
    pub ui_enabled: bool,

    /// DNS domain suffix for the appliance
    #[serde(default)]
    pub domain: String,
    /// IANA timezone name (defaults to `UTC`)
    #[serde(default = "default_timezone")]
    pub timezone: String,
    /// Banner text shown before login on console/SSH
    #[serde(default)]
    pub login_banner: String,
    /// Message of the day shown after login
    #[serde(default)]
    pub motd: String,
    /// Console output selection (video/serial/dual) and baud rate
    #[serde(default)]
    pub console: ConsoleConfig,
    /// sshd access policy
    #[serde(default)]
    pub ssh: SshAccessConfig,
}

fn default_timezone() -> String {
    "UTC".to_string()
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
            domain: String::new(),
            timezone: default_timezone(),
            login_banner: String::new(),
            motd: String::new(),
            console: ConsoleConfig::default(),
            ssh: SshAccessConfig::default(),
        }
    }
}

/// Which console(s) the system uses for boot and login output
/// (wire values are lowercase)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ConsoleKind {
    /// VGA/video console only (the default)
    #[default]
    Video,
    /// Serial console only
    Serial,
    /// Both video and serial consoles
    Dual,
}

/// Console selection and serial line settings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConsoleConfig {
    /// Active console type(s)
    #[serde(default)]
    pub kind: ConsoleKind,
    /// Serial console baud rate (defaults to 115200)
    #[serde(default = "default_baud")]
    pub baud: u32,
}

fn default_baud() -> u32 {
    115200
}

impl Default for ConsoleConfig {
    fn default() -> Self {
        Self {
            kind: ConsoleKind::default(),
            baud: default_baud(),
        }
    }
}

/// sshd access policy applied to the appliance
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SshAccessConfig {
    /// Whether sshd runs
    pub enabled: bool,
    /// TCP port sshd listens on
    pub port: u16,
    /// Allow password authentication (false = key-only)
    pub password_auth: bool,
    /// Allow direct root login over SSH
    pub permit_root_login: bool,
}

impl Default for SshAccessConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 22,
            password_auth: false,
            permit_root_login: false,
        }
    }
}

/// API authentication policy: token lifetimes and TOTP/OAuth requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthConfig {
    /// JWT access-token lifetime in minutes
    pub access_token_expiry_mins: i64,
    /// Refresh-token lifetime in days
    pub refresh_token_expiry_days: i64,
    /// Require TOTP two-factor for password logins
    pub require_totp: bool,
    /// Also require TOTP for OAuth-authenticated logins
    pub require_totp_for_oauth: bool,
    /// Auto-create a local user on first OAuth login
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

/// A filter rule as stored in a config snapshot (string-typed mirror of
/// the rule engine's `FirewallRule`)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    /// Unique rule ID (UUID string)
    pub id: String,
    /// Ordering key; lower values are emitted to pf first
    pub priority: i32,
    /// What the rule does with matching traffic
    pub action: Action,
    /// Traffic direction the rule matches
    pub direction: Direction,
    /// Protocol match
    pub protocol: Protocol,
    /// Interface the rule applies on; None = all interfaces
    pub interface: Option<String>,
    /// Source address/CIDR/alias; None = any
    pub src_addr: Option<String>,
    /// Start of source port range; None = any port
    pub src_port_start: Option<u16>,
    /// End of source port range (inclusive)
    pub src_port_end: Option<u16>,
    /// Destination address/CIDR/alias; None = any
    pub dst_addr: Option<String>,
    /// Start of destination port range; None = any port
    pub dst_port_start: Option<u16>,
    /// End of destination port range (inclusive)
    pub dst_port_end: Option<u16>,
    /// Log matching packets via pflog
    pub log: bool,
    /// pf `quick` — stop rule evaluation on match
    pub quick: bool,
    /// Optional human-readable label
    pub label: Option<String>,
    /// pf state-tracking mode
    pub state_tracking: StateTracking,
    /// Whether the rule is loaded into pf
    pub status: RuleStatus,
    /// Address family. Older backups predate this field; default to `both`
    /// so historical rules keep their dual-stack semantics on restore.
    #[serde(default)]
    pub ip_version: IpVersion,
    /// Negate the source match (pf `!`)
    #[serde(default)]
    pub src_invert: bool,
    /// Negate the destination match (pf `!`)
    #[serde(default)]
    pub dst_invert: bool,
    /// Schedule reference (#537). Older backups predate this field; restored
    /// rules without it behave as unscheduled (always on).
    #[serde(default)]
    pub schedule_id: Option<String>,
    /// Policy-routing gateway reference (#540); dangling references fall
    /// back to default routing at compile time.
    #[serde(default)]
    pub gateway: Option<String>,
}

/// A NAT rule as stored in a config snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatRuleConfig {
    /// Unique rule ID (UUID string)
    pub id: String,
    /// Kind of translation the rule performs
    pub nat_type: NatType,
    /// Interface the translation applies on
    pub interface: String,
    /// Protocol match
    pub protocol: Protocol,
    /// Source address/CIDR match; None = any
    pub src_addr: Option<String>,
    /// Start of source port range; None = any port
    pub src_port_start: Option<u16>,
    /// End of source port range (inclusive)
    pub src_port_end: Option<u16>,
    /// Destination address/CIDR match; None = any
    pub dst_addr: Option<String>,
    /// Start of destination port range; None = any port
    pub dst_port_start: Option<u16>,
    /// End of destination port range (inclusive)
    pub dst_port_end: Option<u16>,
    /// Translation target address
    pub redirect_addr: String,
    /// Start of translated port range; None = keep original port
    pub redirect_port_start: Option<u16>,
    /// End of translated port range (inclusive)
    pub redirect_port_end: Option<u16>,
    /// Optional human-readable label
    pub label: Option<String>,
    /// Whether the rule is loaded into pf
    pub status: NatStatus,
}

/// A traffic-shaping queue as stored in a config snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueueConfigEntry {
    /// Unique queue ID (UUID string)
    pub id: String,
    /// pf queue name
    pub name: String,
    /// Interface the queue is attached to
    pub interface: String,
    /// Queueing discipline
    pub queue_type: QueueType,
    /// Bandwidth amount, in units of `bandwidth_unit`
    pub bandwidth_value: u64,
    /// Unit for `bandwidth_value`
    pub bandwidth_unit: BandwidthUnit,
    /// Priority class of the queue
    pub traffic_class: TrafficClass,
    /// Percent of parent bandwidth (1-100); overrides the absolute value when set
    pub bandwidth_pct: Option<u8>,
    /// Whether this is the interface's default queue
    pub default: bool,
    /// Whether the queue is loaded into pf
    pub status: QueueStatus,
}

/// A per-source-IP connection rate limit as stored in a config snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitEntry {
    /// Unique rule ID (UUID string)
    pub id: String,
    /// Rule name
    pub name: String,
    /// Interface the limit applies on; None = all interfaces
    pub interface: Option<String>,
    /// Protocol match
    pub protocol: Protocol,
    /// Start of destination port range; None = any port
    pub dst_port_start: Option<u16>,
    /// End of destination port range (inclusive)
    pub dst_port_end: Option<u16>,
    /// Max connections allowed per source IP within the window
    pub max_connections: u32,
    /// Measurement window in seconds
    pub window_secs: u32,
    /// pf table that offending source IPs are added to (and blocked from)
    pub overload_table: String,
    /// Kill existing states from a source when it exceeds the limit
    pub flush_states: bool,
    /// Whether the limit is loaded into pf
    pub status: RateLimitStatus,
}

/// VPN section: WireGuard tunnels, IPsec tunnels, and legacy IPsec SAs
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VpnConfig {
    /// WireGuard tunnel definitions (including peers)
    pub wireguard: Vec<WireguardTunnelConfig>,
    /// Legacy pre-#530 IPsec SA records (configuration-only, no data plane)
    pub ipsec: Vec<IpsecSaConfig>,
    /// Real IPsec tunnels (#530). Full records including PSKs/private
    /// keys, so exports must be treated as secrets (same as WireGuard).
    /// Defaults empty so pre-#530 backups import cleanly.
    #[serde(default)]
    pub ipsec_tunnels: Vec<aifw_common::IpsecTunnel>,
}

/// A WireGuard tunnel as stored in a config snapshot. Contains the
/// tunnel's private key, so exports must be treated as secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireguardTunnelConfig {
    /// Unique tunnel ID (UUID string)
    pub id: String,
    /// Tunnel display name
    pub name: String,
    /// WireGuard interface name (e.g. `wg0`)
    pub interface: String,
    /// UDP port the tunnel listens on
    pub listen_port: u16,
    /// Tunnel interface address (IP/prefix)
    pub address: String,
    /// Optional IPv6 tunnel address for dual-stack tunnels (#471)
    #[serde(default)]
    pub address6: Option<String>,
    /// Local WireGuard private key (base64; sensitive)
    pub private_key: String,
    /// Local WireGuard public key (base64)
    pub public_key: String,
    /// Optional DNS server(s) for the tunnel
    pub dns: Option<String>,
    /// Optional interface MTU override
    pub mtu: Option<u16>,
    /// Peers configured on this tunnel
    pub peers: Vec<WireguardPeerConfig>,
}

/// A WireGuard peer entry within a tunnel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WireguardPeerConfig {
    /// Unique peer ID (UUID string)
    pub id: String,
    /// Peer display name
    pub name: String,
    /// Peer's WireGuard public key (base64)
    pub public_key: String,
    /// Optional preshared key for additional symmetric protection (sensitive)
    pub preshared_key: Option<String>,
    /// Remote endpoint `host:port`; None = wait for the peer to connect
    pub endpoint: Option<String>,
    /// CIDRs routed to / accepted from this peer
    pub allowed_ips: Vec<String>,
    /// Keepalive interval in seconds; None = disabled
    pub persistent_keepalive: Option<u16>,
}

/// An IPsec security association as stored in a config snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpsecSaConfig {
    /// Unique SA ID (UUID string)
    pub id: String,
    /// SA display name
    pub name: String,
    /// Local endpoint address
    pub src_addr: String,
    /// Remote endpoint address
    pub dst_addr: String,
    /// IPsec protocol
    pub protocol: IpsecProtocol,
    /// Encapsulation mode
    pub mode: IpsecMode,
    /// Encryption algorithm (e.g. `aes-gcm-256`)
    pub enc_algo: String,
    /// Authentication algorithm (e.g. `hmac-sha256`)
    pub auth_algo: String,
}

/// A per-country geo-IP filter entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpEntry {
    /// Unique entry ID (UUID string)
    pub id: String,
    /// ISO 3166-1 alpha-2 country code (e.g. `CN`)
    pub country: String,
    /// Whether matching countries are allowed or blocked
    pub action: GeoIpAction,
    /// Optional human-readable label
    pub label: Option<String>,
    /// Whether the entry is enforced
    pub status: GeoIpRuleStatus,
}

/// TLS inspection policy applied to observed handshakes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Minimum accepted TLS version (e.g. `tls12`)
    pub min_version: String,
    /// Block connections presenting self-signed certificates
    pub block_self_signed: bool,
    /// Block connections presenting expired certificates
    pub block_expired: bool,
    /// Block certificates with weak keys
    pub block_weak_keys: bool,
    /// JA3 client-fingerprint blocklist
    pub blocked_ja3: Vec<String>,
    /// Per-SNI-pattern allow/block rules
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

/// A TLS SNI hostname match rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SniRuleConfig {
    /// Unique rule ID (UUID string)
    pub id: String,
    /// SNI hostname pattern to match
    pub pattern: String,
    /// Whether matching connections are allowed or blocked
    pub action: SniAction,
    /// Optional human-readable label
    pub label: Option<String>,
}

/// High-availability section: CARP virtual IPs, pfsync, and cluster membership
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct HaConfig {
    /// CARP virtual IP definitions
    pub carp_vips: Vec<CarpVipConfig>,
    /// pfsync state-sync settings; None = pfsync disabled
    pub pfsync: Option<PfsyncEntry>,
    /// Known cluster nodes
    pub nodes: Vec<ClusterNodeConfig>,
}

/// A CARP virtual IP as stored in a config snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarpVipConfig {
    /// Unique VIP ID (UUID string)
    pub id: String,
    /// CARP virtual host ID, shared by all nodes advertising this VIP
    pub vhid: u8,
    /// The shared virtual IP address
    pub virtual_ip: String,
    /// Network prefix length for the VIP
    pub prefix: u8,
    /// Interface the VIP is configured on
    pub interface: String,
    /// CARP advertisement password (sensitive)
    pub password: String,
}

/// pfsync state-table synchronization settings
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PfsyncEntry {
    /// Interface pfsync traffic is sent over
    pub sync_interface: String,
    /// Unicast peer address; None = multicast on the sync interface
    pub sync_peer: Option<String>,
    /// pf `defer` — hold initial packets until the state syncs to the peer
    pub defer: bool,
}

/// A node in the HA cluster as stored in a config snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNodeConfig {
    /// Unique node ID (UUID string)
    pub id: String,
    /// Node display name
    pub name: String,
    /// Node IP address
    pub address: String,
    /// `primary`, `secondary`, or `standalone`
    pub role: String,
}

/// A key/value tuning override captured in a snapshot. Currently only
/// `pf.max_states` (target `sysctl`) is exported and honoured on restore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TuningEntry {
    /// Tunable name (e.g. `pf.max_states`)
    pub key: String,
    /// Tunable value, stringified
    pub value: String,
    /// Where the tunable applies (currently always `sysctl`)
    pub target: String,
    /// Human-readable justification recorded with the entry
    pub reason: String,
    /// Whether the tunable is applied on restore
    pub enabled: bool,
}

// ============================================================
// DHCP
// ============================================================

/// DHCP configuration section, mirroring the external rDHCP daemon's schema
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DhcpSection {
    /// Server-wide rDHCP settings
    #[serde(default)]
    pub global: DhcpGlobalSection,
    /// DHCP subnet / address-pool definitions
    #[serde(default)]
    pub subnets: Vec<DhcpSubnetConfig>,
    /// Static MAC-to-IP reservations
    #[serde(default)]
    pub reservations: Vec<DhcpReservationConfig>,
    /// Dynamic DNS update settings
    #[serde(default)]
    pub ddns: DhcpDdnsSection,
    /// DHCP failover / HA settings
    #[serde(default)]
    pub dhcp_ha: DhcpHaSection,
}

/// Server-wide DHCP settings (mirrors the rDHCP `[global]` TOML schema)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpGlobalSection {
    /// Whether the DHCP server runs
    pub enabled: bool,
    /// Interfaces the server listens on
    pub interfaces: Vec<String>,
    /// Answer authoritatively (NAK requests for unknown leases)
    pub authoritative: bool,
    /// Default lease duration in seconds
    pub default_lease_time: u32,
    /// Maximum lease duration in seconds
    pub max_lease_time: u32,
    /// DNS servers handed to clients (option 6)
    pub dns_servers: Vec<String>,
    /// Domain name handed to clients (option 15)
    pub domain_name: String,
    /// Domain search list handed to clients (option 119)
    pub domain_search: Vec<String>,
    /// NTP servers handed to clients (option 42)
    pub ntp_servers: Vec<String>,
    /// WINS servers handed to clients (option 44)
    pub wins_servers: Vec<String>,
    /// PXE next-server (siaddr); None = not set
    pub next_server: Option<String>,
    /// PXE boot filename; None = not set
    pub boot_filename: Option<String>,
    /// rDHCP log level (e.g. `info`)
    pub log_level: String,
    /// rDHCP log format (e.g. `text`)
    pub log_format: String,
    /// rDHCP control-API TCP port (default 9967)
    pub api_port: u16,
    /// Number of rDHCP worker threads
    pub workers: u32,
    // DHCP relay — matches rDHCP [global] schema (see rDHCP feature/dhcpv4-accept-relayed).
    /// Accept relayed requests (giaddr set)
    #[serde(default = "default_accept_relayed")]
    pub accept_relayed: bool,
    /// Token-bucket burst size for relayed requests
    #[serde(default = "default_relay_rate_limit_burst")]
    pub relay_rate_limit_burst: u32,
    /// Sustained relayed-request rate limit in packets per second
    #[serde(default = "default_relay_rate_limit_pps")]
    pub relay_rate_limit_pps: f64,
}

fn default_accept_relayed() -> bool {
    true
}
fn default_relay_rate_limit_burst() -> u32 {
    200
}
fn default_relay_rate_limit_pps() -> f64 {
    100.0
}

impl Default for DhcpGlobalSection {
    fn default() -> Self {
        Self {
            enabled: false,
            interfaces: vec![],
            authoritative: true,
            default_lease_time: 3600,
            max_lease_time: 86400,
            dns_servers: vec![],
            domain_name: String::new(),
            domain_search: vec![],
            ntp_servers: vec![],
            wins_servers: vec![],
            next_server: None,
            boot_filename: None,
            log_level: "info".to_string(),
            log_format: "text".to_string(),
            api_port: 9967,
            workers: 1,
            accept_relayed: default_accept_relayed(),
            relay_rate_limit_burst: default_relay_rate_limit_burst(),
            relay_rate_limit_pps: default_relay_rate_limit_pps(),
        }
    }
}

/// A DHCP subnet / address pool. Optional per-subnet fields fall back to
/// the global settings when None.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpSubnetConfig {
    /// Unique subnet ID (UUID string)
    pub id: String,
    /// Subnet in CIDR notation
    pub network: String,
    /// First address of the dynamic pool
    pub pool_start: String,
    /// Last address of the dynamic pool
    pub pool_end: String,
    /// Default gateway handed to clients (option 3)
    pub gateway: String,
    /// Comma-separated DNS server override; None = inherit global
    pub dns_servers: Option<String>,
    /// Domain name override; None = inherit global
    pub domain_name: Option<String>,
    /// Lease duration override in seconds; None = inherit global
    pub lease_time: Option<u32>,
    /// Maximum lease duration override in seconds; None = inherit global
    pub max_lease_time: Option<u32>,
    /// T1 renewal time in seconds; None = server default
    pub renewal_time: Option<u32>,
    /// T2 rebinding time in seconds; None = server default
    pub rebinding_time: Option<u32>,
    /// IPv6 preferred lifetime in seconds; None = server default
    pub preferred_time: Option<u32>,
    /// `address` or `prefix-delegation` (IPv6 PD)
    pub subnet_type: String,
    /// Delegated prefix length for prefix-delegation subnets
    pub delegated_length: Option<u8>,
    /// Whether the subnet is served
    pub enabled: bool,
    /// Optional free-form note
    pub description: Option<String>,
    /// Relay agent IPs allowed to forward requests for this subnet
    #[serde(default)]
    pub trusted_relays: Vec<String>,
    /// Per-subnet NTP (DHCP option 42). Comma-separated IPv4 list; None = inherit.
    #[serde(default)]
    pub ntp_servers: Option<String>,
    /// Generic per-subnet DHCP option overrides (codes not covered by typed fields).
    #[serde(default)]
    pub options: Vec<DhcpOptionOverrideConfig>,
    /// Creation timestamp (RFC 3339 string)
    pub created_at: String,
}

/// A raw per-subnet DHCP option override
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpOptionOverrideConfig {
    /// DHCP option code
    pub code: u8,
    /// How `value` is encoded — `ip`, `ips`, `string`, `u8`, `u16`, `u32`, or `hex`
    pub value_type: String,
    /// Raw option value, parsed per `value_type`
    pub value: String,
}

/// A static DHCP reservation (fixed MAC-to-IP mapping)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpReservationConfig {
    /// Unique reservation ID (UUID string)
    pub id: String,
    /// Owning subnet ID; None = not tied to a specific subnet
    pub subnet_id: Option<String>,
    /// Client MAC address
    pub mac_address: String,
    /// Fixed IP address handed to that MAC
    pub ip_address: String,
    /// Optional hostname to assign to the client
    pub hostname: Option<String>,
    /// Optional DHCP client identifier (option 61) to match on
    pub client_id: Option<String>,
    /// Optional free-form note
    pub description: Option<String>,
    /// Creation timestamp (RFC 3339 string)
    pub created_at: String,
}

/// Dynamic DNS (RFC 2136) update settings for DHCP leases
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DhcpDdnsSection {
    /// Whether DDNS updates are sent for leases
    pub enabled: bool,
    /// Forward DNS zone to update
    pub forward_zone: String,
    /// IPv4 reverse zone (in-addr.arpa)
    pub reverse_zone_v4: String,
    /// IPv6 reverse zone (ip6.arpa)
    pub reverse_zone_v6: String,
    /// DNS server that receives the updates
    pub dns_server: String,
    /// TSIG key name
    pub tsig_key: String,
    /// TSIG algorithm (e.g. `hmac-sha256`)
    pub tsig_algorithm: String,
    /// TSIG shared secret (sensitive)
    #[serde(default)]
    pub tsig_secret: String,
    /// TTL in seconds for created records
    pub ttl: u32,
}

/// DHCP failover / HA settings (mirrors rDHCP's HA schema)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DhcpHaSection {
    /// `standalone`, `active-active`, or `raft`
    pub mode: String,
    /// Failover peer address (active-active mode)
    pub peer: Option<String>,
    /// Local HA listen address (active-active mode)
    pub listen: Option<String>,
    /// Address-pool split ratio between the peers (active-active mode)
    pub scope_split: Option<f64>,
    /// Maximum client lead time in seconds (active-active mode)
    pub mclt: Option<u32>,
    /// Seconds to wait before claiming the full pool after peer loss
    pub partner_down_delay: Option<u32>,
    /// This node's ID (raft mode)
    pub node_id: Option<u64>,
    /// Raft peer addresses (raft mode)
    pub peers: Option<Vec<String>>,
    /// TLS certificate path for HA transport
    pub tls_cert: Option<String>,
    /// TLS private key path for HA transport
    pub tls_key: Option<String>,
    /// TLS CA certificate path for peer verification
    pub tls_ca: Option<String>,
}

// ============================================================
// DNS resolver (rDNS / unbound)
// ============================================================

/// rDNS/unbound resolver settings — the `dns_resolver_config` key/value
/// table materialized as a struct. This is the same type the
/// `/api/v1/dns/resolver/config` endpoint speaks (aifw-api re-exports it
/// as `ResolverConfig`); it lives here so config snapshots can round-trip
/// it (#589).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DnsResolverSection {
    /// Resolver backend: `rdns` or `unbound`
    pub backend: String,
    /// Whether the resolver service runs
    pub enabled: bool,
    /// Listen addresses (e.g. `0.0.0.0`)
    pub listen_interfaces: Vec<String>,
    /// DNS listen port (default 53)
    pub port: u16,
    /// DNSSEC validation
    pub dnssec: bool,
    /// DNS64 synthesis
    pub dns64: bool,
    /// Register DHCP leases in DNS
    pub register_dhcp: bool,
    /// Domain for DHCP lease DNS registration (e.g. `local`)
    pub dhcp_domain: String,
    /// Local zone type — transparent, static, redirect, etc.
    pub local_zone_type: String,
    /// Interface for outgoing queries; None = any
    pub outgoing_interface: Option<String>,
    // Advanced
    /// Worker thread count
    pub num_threads: u32,
    /// Message cache size (e.g. `8m`)
    pub msg_cache_size: String,
    /// RRset cache size (e.g. `16m`)
    pub rrset_cache_size: String,
    /// Maximum cache TTL in seconds
    pub cache_max_ttl: u32,
    /// Minimum cache TTL in seconds
    pub cache_min_ttl: u32,
    /// Prefetch popular records before expiry
    pub prefetch: bool,
    /// Prefetch DNSKEY records
    pub prefetch_key: bool,
    /// Host infrastructure cache TTL in seconds
    pub infra_host_ttl: u32,
    /// Unwanted-reply threshold before cache flush
    pub unwanted_reply_threshold: u32,
    /// Log client queries
    pub log_queries: bool,
    /// Log replies
    pub log_replies: bool,
    /// Log verbosity level
    pub log_verbosity: u32,
    /// Ceiling on a single query's resolution (ms). 0 = rDNS built-in
    /// per-transport defaults (UDP 3000, TCP/DoT 30000).
    #[serde(default)]
    pub query_timeout_ms: u32,
    /// Refuse id.server/hostname.bind queries
    pub hide_identity: bool,
    /// Refuse version.server/version.bind queries
    pub hide_version: bool,
    /// DNS-rebind protection
    pub rebind_protection: bool,
    /// Private address ranges for rebind protection
    pub private_addresses: Vec<String>,
    // Forwarding
    /// Forward to upstream servers instead of full recursion
    pub forwarding_enabled: bool,
    /// Plain upstream DNS IPs (e.g. `8.8.8.8`, `1.1.1.1`)
    pub forwarding_servers: Vec<String>,
    /// Also forward to /etc/resolv.conf nameservers
    pub use_system_nameservers: bool,
    // DoT
    /// DNS-over-TLS forwarding
    pub dot_enabled: bool,
    /// DoT upstreams (`1.1.1.1@853#cloudflare-dns.com`)
    pub dot_upstream: Vec<String>,
    // Blocklists
    /// Enable domain blocklists
    pub blocklists_enabled: bool,
    /// Blocklist source URLs
    pub blocklist_urls: Vec<String>,
    /// Domains exempted from blocklists
    pub whitelist: Vec<String>,
    /// `nxdomain` or `redirect`
    pub blocklist_action: String,
    /// Redirect target when blocklist_action is `redirect`
    pub blocklist_redirect_ip: Option<String>,
    // Custom
    /// Free-form extra config lines appended to the generated config
    pub custom_options: String,
    // Safety
    /// Probe :53 after a resolver switch and auto-rollback on failure.
    /// Default: true. Disable to restore the old fire-and-forget behavior
    /// (e.g. for debugging, or on boxes where the probe misfires).
    #[serde(default = "default_true")]
    pub probe_enabled: bool,
}

impl Default for DnsResolverSection {
    fn default() -> Self {
        Self {
            backend: "rdns".to_string(),
            enabled: false,
            listen_interfaces: vec!["0.0.0.0".to_string()],
            port: 53,
            dnssec: true,
            dns64: false,
            register_dhcp: true,
            dhcp_domain: "local".to_string(),
            local_zone_type: "transparent".to_string(),
            outgoing_interface: None,
            num_threads: 2,
            msg_cache_size: "8m".to_string(),
            rrset_cache_size: "16m".to_string(),
            cache_max_ttl: 86400,
            cache_min_ttl: 0,
            prefetch: true,
            prefetch_key: true,
            infra_host_ttl: 900,
            unwanted_reply_threshold: 10000,
            log_queries: false,
            log_replies: false,
            log_verbosity: 1,
            query_timeout_ms: 0,
            hide_identity: true,
            hide_version: true,
            rebind_protection: true,
            private_addresses: vec![
                "10.0.0.0/8".into(),
                "172.16.0.0/12".into(),
                "192.168.0.0/16".into(),
                "169.254.0.0/16".into(),
                "fd00::/8".into(),
                "fe80::/10".into(),
            ],
            // Default ON. Iterative recursion in rDNS 1.12.8 returns referrals
            // instead of following them to completion, leaving clients with
            // 0-answer responses for anything not already cached. Forwarding
            // to public resolvers is the battle-tested fallback and keeps DNS
            // working out of the box. Operators who want pure recursion can
            // flip this off in the UI.
            forwarding_enabled: true,
            forwarding_servers: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            use_system_nameservers: false,
            dot_enabled: false,
            dot_upstream: vec![
                "1.1.1.1@853#cloudflare-dns.com".into(),
                "1.0.0.1@853#cloudflare-dns.com".into(),
            ],
            blocklists_enabled: false,
            blocklist_urls: vec![],
            whitelist: vec![],
            blocklist_action: "nxdomain".to_string(),
            blocklist_redirect_ip: None,
            custom_options: String::new(),
            probe_enabled: true,
        }
    }
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
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
        0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
        0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
        0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
        0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
        0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
        0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
        0xc67178f2,
    ];
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];
    let bit_len = (msg.len() as u64) * 8;
    let mut padded = msg.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());

    for chunk in padded.chunks(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(k[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (i, v) in [a, b, c, d, e, f, g, hh].iter().enumerate() {
            h[i] = h[i].wrapping_add(*v);
        }
    }
    let mut result = [0u8; 32];
    for (i, val) in h.iter().enumerate() {
        result[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
    }
    result
}
