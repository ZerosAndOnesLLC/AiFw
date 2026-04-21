use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::Interface;

// ============================================================
// TLS Version
// ============================================================

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TlsVersion {
    Ssl30,
    Tls10,
    Tls11,
    Tls12,
    Tls13,
}

impl TlsVersion {
    pub fn from_protocol_version(major: u8, minor: u8) -> Option<Self> {
        match (major, minor) {
            (3, 0) => Some(TlsVersion::Ssl30),
            (3, 1) => Some(TlsVersion::Tls10),
            (3, 2) => Some(TlsVersion::Tls11),
            (3, 3) => Some(TlsVersion::Tls12),
            (3, 4) => Some(TlsVersion::Tls13),
            _ => None,
        }
    }

    pub fn parse(s: &str) -> crate::Result<Self> {
        match s.to_lowercase().replace('.', "").as_str() {
            "ssl30" | "ssl3" | "sslv3" => Ok(TlsVersion::Ssl30),
            "tls10" | "tls1" | "tlsv1" => Ok(TlsVersion::Tls10),
            "tls11" | "tlsv11" => Ok(TlsVersion::Tls11),
            "tls12" | "tlsv12" => Ok(TlsVersion::Tls12),
            "tls13" | "tlsv13" => Ok(TlsVersion::Tls13),
            _ => Err(crate::AifwError::Validation(format!(
                "unknown TLS version: {s}"
            ))),
        }
    }

    pub fn is_deprecated(&self) -> bool {
        matches!(
            self,
            TlsVersion::Ssl30 | TlsVersion::Tls10 | TlsVersion::Tls11
        )
    }
}

impl std::fmt::Display for TlsVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TlsVersion::Ssl30 => write!(f, "SSLv3"),
            TlsVersion::Tls10 => write!(f, "TLSv1.0"),
            TlsVersion::Tls11 => write!(f, "TLSv1.1"),
            TlsVersion::Tls12 => write!(f, "TLSv1.2"),
            TlsVersion::Tls13 => write!(f, "TLSv1.3"),
        }
    }
}

// ============================================================
// JA3 / JA3S Fingerprinting
// ============================================================

/// JA3 fingerprint computed from a TLS ClientHello
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Ja3Fingerprint {
    /// The raw JA3 string (version,ciphers,extensions,elliptic_curves,ec_point_formats)
    pub raw: String,
    /// MD5 hash of the raw string
    pub hash: String,
}

impl Ja3Fingerprint {
    /// Compute a JA3 fingerprint from ClientHello components
    pub fn compute(
        tls_version: u16,
        cipher_suites: &[u16],
        extensions: &[u16],
        elliptic_curves: &[u16],
        ec_point_formats: &[u8],
    ) -> Self {
        let ciphers = join_u16(cipher_suites);
        let exts = join_u16(extensions);
        let curves = join_u16(elliptic_curves);
        let points = ec_point_formats
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join("-");

        let raw = format!("{tls_version},{ciphers},{exts},{curves},{points}");
        let hash = md5_hex(&raw);

        Self { raw, hash }
    }
}

impl std::fmt::Display for Ja3Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hash)
    }
}

/// JA3S fingerprint computed from a TLS ServerHello
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Ja3sFingerprint {
    pub raw: String,
    pub hash: String,
}

impl Ja3sFingerprint {
    pub fn compute(tls_version: u16, cipher_suite: u16, extensions: &[u16]) -> Self {
        let exts = join_u16(extensions);
        let raw = format!("{tls_version},{cipher_suite},{exts}");
        let hash = md5_hex(&raw);
        Self { raw, hash }
    }
}

impl std::fmt::Display for Ja3sFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hash)
    }
}

// ============================================================
// SNI Filtering
// ============================================================

/// Action for SNI-based filtering
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SniAction {
    Allow,
    Block,
}

impl std::fmt::Display for SniAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SniAction::Allow => write!(f, "allow"),
            SniAction::Block => write!(f, "block"),
        }
    }
}

impl SniAction {
    pub fn parse(s: &str) -> crate::Result<Self> {
        match s.to_lowercase().as_str() {
            "allow" | "pass" => Ok(SniAction::Allow),
            "block" | "deny" => Ok(SniAction::Block),
            _ => Err(crate::AifwError::Validation(format!(
                "unknown SNI action: {s}"
            ))),
        }
    }
}

/// SNI-based filtering rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SniRule {
    pub id: Uuid,
    pub pattern: String,
    pub action: SniAction,
    pub label: Option<String>,
    pub status: SniRuleStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SniRuleStatus {
    Active,
    Disabled,
}

impl SniRule {
    pub fn new(pattern: String, action: SniAction) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            pattern,
            action,
            label: None,
            status: SniRuleStatus::Active,
            created_at: now,
            updated_at: now,
        }
    }

    /// Check if a hostname matches this rule's pattern.
    /// Supports exact match and wildcard prefix (e.g., *.example.com)
    pub fn matches(&self, hostname: &str) -> bool {
        let hostname = hostname.to_lowercase();
        let pattern = self.pattern.to_lowercase();

        if pattern.starts_with("*.") {
            let suffix = &pattern[1..]; // ".example.com"
            hostname.ends_with(suffix) || hostname == pattern[2..]
        } else {
            hostname == pattern
        }
    }
}

// ============================================================
// Certificate info
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertInfo {
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub san: Vec<String>,
    pub is_self_signed: bool,
    pub key_bits: u32,
}

impl CertInfo {
    pub fn is_expired(&self) -> bool {
        Utc::now() > self.not_after
    }

    pub fn is_not_yet_valid(&self) -> bool {
        Utc::now() < self.not_before
    }

    pub fn is_valid_time(&self) -> bool {
        !self.is_expired() && !self.is_not_yet_valid()
    }

    pub fn is_weak_key(&self) -> bool {
        self.key_bits < 2048
    }
}

// ============================================================
// TLS Policy
// ============================================================

/// TLS inspection and enforcement policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsPolicy {
    pub id: Uuid,
    /// Minimum allowed TLS version
    pub min_version: TlsVersion,
    /// Block self-signed certificates
    pub block_self_signed: bool,
    /// Block expired certificates
    pub block_expired: bool,
    /// Block weak keys (< 2048 bits)
    pub block_weak_keys: bool,
    /// Blocked JA3 fingerprint hashes
    pub blocked_ja3: Vec<String>,
    pub created_at: DateTime<Utc>,
}

impl Default for TlsPolicy {
    fn default() -> Self {
        Self {
            id: Uuid::new_v4(),
            min_version: TlsVersion::Tls12,
            block_self_signed: false,
            block_expired: true,
            block_weak_keys: true,
            blocked_ja3: Vec::new(),
            created_at: Utc::now(),
        }
    }
}

impl TlsPolicy {
    /// Check if a TLS version is allowed by this policy
    pub fn is_version_allowed(&self, version: TlsVersion) -> bool {
        version >= self.min_version
    }

    /// Check if a JA3 hash is blocked
    pub fn is_ja3_blocked(&self, hash: &str) -> bool {
        self.blocked_ja3.iter().any(|h| h == hash)
    }

    /// Validate a certificate against this policy
    pub fn validate_cert(&self, cert: &CertInfo) -> Vec<String> {
        let mut violations = Vec::new();
        if self.block_expired && cert.is_expired() {
            violations.push("certificate expired".to_string());
        }
        if self.block_expired && cert.is_not_yet_valid() {
            violations.push("certificate not yet valid".to_string());
        }
        if self.block_self_signed && cert.is_self_signed {
            violations.push("self-signed certificate".to_string());
        }
        if self.block_weak_keys && cert.is_weak_key() {
            violations.push(format!("weak key ({} bits)", cert.key_bits));
        }
        violations
    }
}

// ============================================================
// MITM Proxy config
// ============================================================

/// Configuration for optional TLS MITM proxy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MitmProxyConfig {
    /// Enable MITM proxy (explicit opt-in)
    pub enabled: bool,
    /// Path to CA certificate file
    pub ca_cert_path: String,
    /// Path to CA private key file
    pub ca_key_path: String,
    /// Listen port for the proxy
    pub listen_port: u16,
    /// Interface for pf RDR rule
    pub interface: Interface,
    /// Ports to intercept (redirect via pf RDR)
    pub intercept_ports: Vec<u16>,
}

impl Default for MitmProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ca_cert_path: "/var/db/aifw/ca.crt".to_string(),
            ca_key_path: "/var/db/aifw/ca.key".to_string(),
            listen_port: 8443,
            interface: Interface("em0".to_string()),
            intercept_ports: vec![443],
        }
    }
}

impl MitmProxyConfig {
    /// Generate pf RDR rules for transparent interception
    pub fn to_pf_rdr_rules(&self) -> Vec<String> {
        if !self.enabled {
            return Vec::new();
        }

        self.intercept_ports
            .iter()
            .map(|port| {
                format!(
                    "rdr on {} proto tcp to any port {} -> 127.0.0.1 port {} label \"tls-mitm-{}\"",
                    self.interface, port, self.listen_port, port
                )
            })
            .collect()
    }
}

// ============================================================
// Helpers
// ============================================================

fn join_u16(values: &[u16]) -> String {
    values
        .iter()
        .map(|v| v.to_string())
        .collect::<Vec<_>>()
        .join("-")
}

/// Simple MD5 hex digest (no external crate — just for JA3 fingerprint hashing)
fn md5_hex(input: &str) -> String {
    // Minimal MD5 implementation for JA3 hashing
    let bytes = input.as_bytes();
    let digest = md5_compute(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn md5_compute(msg: &[u8]) -> [u8; 16] {
    // Constants
    let s: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];
    let k: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    // Pre-processing: padding
    let orig_len = msg.len();
    let bit_len = (orig_len as u64) * 8;
    let mut padded = msg.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_le_bytes());

    // Process 512-bit chunks
    for chunk in padded.chunks(64) {
        let mut m = [0u32; 16];
        for (i, word) in chunk.chunks(4).enumerate() {
            m[i] = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        }

        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

        for i in 0..64 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i),
                16..=31 => ((d & b) | ((!d) & c), (5 * i + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i) % 16),
            };

            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                (a.wrapping_add(f).wrapping_add(k[i]).wrapping_add(m[g])).rotate_left(s[i]),
            );
            a = temp;
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&a0.to_le_bytes());
    result[4..8].copy_from_slice(&b0.to_le_bytes());
    result[8..12].copy_from_slice(&c0.to_le_bytes());
    result[12..16].copy_from_slice(&d0.to_le_bytes());
    result
}
