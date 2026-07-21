//! IPsec tunnel types for the real data plane (#530).
//!
//! An [`IpsecTunnel`] is the desired configuration for one IKEv2
//! site-to-site tunnel, rendered by `aifw-core` into a swanctl conn +
//! secrets file and negotiated by strongSwan (charon). Live negotiated
//! state is reported separately as [`IpsecLiveStatus`] parsed from
//! `swanctl --list-sas` — the database never stores an "up/down" column.
//!
//! The older [`crate::IpsecSa`]/[`crate::IpsecSp`] types describe the
//! pre-#530 CRUD-only records (`ipsec_sas` table); those rows are kept as
//! read-only legacy data and cannot carry traffic.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::types::Address;

/// How the two IKE endpoints authenticate each other (wire values snake_case)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IpsecAuthMethod {
    /// Pre-shared key
    Psk,
    /// X.509 certificate (pubkey auth)
    Cert,
}

impl std::fmt::Display for IpsecAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpsecAuthMethod::Psk => write!(f, "psk"),
            IpsecAuthMethod::Cert => write!(f, "cert"),
        }
    }
}

impl IpsecAuthMethod {
    /// Parse from the stored/wire string, case-insensitively.
    pub fn parse(s: &str) -> crate::Result<Self> {
        match s.to_lowercase().as_str() {
            "psk" => Ok(IpsecAuthMethod::Psk),
            "cert" | "pubkey" => Ok(IpsecAuthMethod::Cert),
            _ => Err(crate::AifwError::Validation(format!(
                "unknown IPsec auth method: {s}"
            ))),
        }
    }
}

/// Where certificate material for a cert-auth tunnel comes from
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IpsecCertSource {
    /// Reference an issued cert in the ACME store by id
    Acme,
    /// Operator-supplied PEM material stored on the tunnel record
    Manual,
}

impl std::fmt::Display for IpsecCertSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpsecCertSource::Acme => write!(f, "acme"),
            IpsecCertSource::Manual => write!(f, "manual"),
        }
    }
}

impl IpsecCertSource {
    /// Parse from the stored/wire string, case-insensitively.
    pub fn parse(s: &str) -> crate::Result<Self> {
        match s.to_lowercase().as_str() {
            "acme" => Ok(IpsecCertSource::Acme),
            "manual" => Ok(IpsecCertSource::Manual),
            _ => Err(crate::AifwError::Validation(format!(
                "unknown IPsec cert source: {s}"
            ))),
        }
    }
}

/// What charon does with the tunnel's child SA when config is loaded
/// (swanctl `start_action`)
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IpsecStartAction {
    /// Initiate immediately on load and keep up (dpd restart)
    Start,
    /// Install a trap policy; negotiate on first matching traffic
    Trap,
    /// Load only; wait for an explicit start or the peer to initiate
    None,
}

impl std::fmt::Display for IpsecStartAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpsecStartAction::Start => write!(f, "start"),
            IpsecStartAction::Trap => write!(f, "trap"),
            IpsecStartAction::None => write!(f, "none"),
        }
    }
}

impl IpsecStartAction {
    /// Parse from the stored/wire string, case-insensitively.
    pub fn parse(s: &str) -> crate::Result<Self> {
        match s.to_lowercase().as_str() {
            "start" => Ok(IpsecStartAction::Start),
            "trap" => Ok(IpsecStartAction::Trap),
            "none" => Ok(IpsecStartAction::None),
            _ => Err(crate::AifwError::Validation(format!(
                "unknown IPsec start action: {s}"
            ))),
        }
    }
}

/// Default IKE (phase 1) proposal — AEAD + PRF + ECDH group.
pub const DEFAULT_IKE_PROPOSAL: &str = "aes256gcm16-prfsha256-ecp256";
/// Default ESP (phase 2) proposal — AEAD + ECDH group for PFS.
pub const DEFAULT_ESP_PROPOSAL: &str = "aes256gcm16-ecp256";
/// Default IKE SA rekey time (4h).
pub const DEFAULT_IKE_LIFETIME_SECS: u32 = 14_400;
/// Default child SA rekey time (1h).
pub const DEFAULT_ESP_LIFETIME_SECS: u32 = 3_600;
/// Default dead-peer-detection probe interval.
pub const DEFAULT_DPD_DELAY_SECS: u32 = 30;

/// Proposal tokens accepted by FreeBSD's strongSwan build. Curated
/// subset — modern AEAD/hash/DH choices only; validated so a typo fails
/// at create time instead of as a charon parse error at load time.
const PROPOSAL_TOKENS: &[&str] = &[
    // encryption (AEAD)
    "aes128gcm16",
    "aes256gcm16",
    "chacha20poly1305",
    // encryption (CBC, for interop with non-AEAD peers)
    "aes128",
    "aes256",
    // integrity (only meaningful with CBC ciphers)
    "sha256",
    "sha384",
    "sha512",
    // PRF (required in IKE proposals when the cipher is AEAD)
    "prfsha256",
    "prfsha384",
    "prfsha512",
    // DH groups
    "ecp256",
    "ecp384",
    "ecp521",
    "curve25519",
    "modp2048",
    "modp3072",
    "modp4096",
];

/// Validate a swanctl proposal string: dash-separated tokens, each from
/// the curated allowlist. `kind` names the field in error messages.
pub fn validate_proposal(kind: &str, proposal: &str) -> crate::Result<()> {
    if proposal.is_empty() {
        return Err(crate::AifwError::Validation(format!(
            "{kind} proposal must not be empty"
        )));
    }
    for token in proposal.split('-') {
        if !PROPOSAL_TOKENS.contains(&token) {
            return Err(crate::AifwError::Validation(format!(
                "{kind} proposal token not supported: {token:?} (allowed: {})",
                PROPOSAL_TOKENS.join(", ")
            )));
        }
    }
    Ok(())
}

/// One desired IKEv2 site-to-site tunnel (tunnel mode).
///
/// Secret fields (`psk`, `local_key_pem`) must be redacted before the
/// struct leaves the API — see `IpsecTunnel::redacted`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpsecTunnel {
    /// Unique identifier; also the basis of the swanctl conn name
    /// (`aifw-<id>`)
    pub id: Uuid,
    /// Human-readable tunnel name (UI/label only, not the conn name)
    pub name: String,
    /// Disabled tunnels are not rendered into swanctl config at all
    pub enabled: bool,
    /// Local IKE endpoint address; empty = any local address (`%any`)
    pub local_addr: String,
    /// Remote IKE endpoint — IP address or DNS name
    pub remote_addr: String,
    /// Local IKE identity; empty = derive from `local_addr`
    pub local_id: String,
    /// Remote IKE identity; empty = derive from `remote_addr`
    pub remote_id: String,
    /// PSK or certificate authentication
    pub auth_method: IpsecAuthMethod,
    /// Pre-shared key (auth_method = psk). Redacted in API output.
    pub psk: String,
    /// Certificate source (auth_method = cert)
    pub cert_source: Option<IpsecCertSource>,
    /// ACME store certificate id (cert_source = acme)
    pub acme_cert_id: Option<Uuid>,
    /// Local certificate PEM (cert_source = manual)
    pub local_cert_pem: String,
    /// Local private key PEM (cert_source = manual). Redacted in API output.
    pub local_key_pem: String,
    /// CA certificate PEM used to verify the peer (cert auth)
    pub ca_cert_pem: String,
    /// IKE (phase 1) proposal string
    pub ike_proposal: String,
    /// ESP (phase 2) proposal string
    pub esp_proposal: String,
    /// Local traffic selectors — subnets behind this side
    pub local_ts: Vec<String>,
    /// Remote traffic selectors — subnets behind the peer
    pub remote_ts: Vec<String>,
    /// IKE SA rekey time in seconds
    pub ike_lifetime_secs: u32,
    /// Child SA rekey time in seconds
    pub esp_lifetime_secs: u32,
    /// DPD probe interval in seconds; 0 disables DPD
    pub dpd_delay_secs: u32,
    /// Behavior on config load
    pub start_action: IpsecStartAction,
    /// Creation timestamp
    pub created_at: DateTime<Utc>,
    /// Last modification timestamp
    pub updated_at: DateTime<Utc>,
}

impl IpsecTunnel {
    /// Create a PSK tunnel with defaults (AES-256-GCM proposals, 4h/1h
    /// lifetimes, DPD 30s, start on load). Callers adjust fields then run
    /// [`IpsecTunnel::validate`].
    pub fn new(
        name: String,
        remote_addr: String,
        psk: String,
        local_ts: Vec<String>,
        remote_ts: Vec<String>,
    ) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            enabled: true,
            local_addr: String::new(),
            remote_addr,
            local_id: String::new(),
            remote_id: String::new(),
            auth_method: IpsecAuthMethod::Psk,
            psk,
            cert_source: None,
            acme_cert_id: None,
            local_cert_pem: String::new(),
            local_key_pem: String::new(),
            ca_cert_pem: String::new(),
            ike_proposal: DEFAULT_IKE_PROPOSAL.to_string(),
            esp_proposal: DEFAULT_ESP_PROPOSAL.to_string(),
            local_ts,
            remote_ts,
            ike_lifetime_secs: DEFAULT_IKE_LIFETIME_SECS,
            esp_lifetime_secs: DEFAULT_ESP_LIFETIME_SECS,
            dpd_delay_secs: DEFAULT_DPD_DELAY_SECS,
            start_action: IpsecStartAction::Start,
            created_at: now,
            updated_at: now,
        }
    }

    /// swanctl connection name for this tunnel. The `aifw-` prefix is
    /// load-bearing: the `aifw-sudo-swanctl` wrapper only permits
    /// operations on names in this namespace.
    pub fn conn_name(&self) -> String {
        format!("aifw-{}", self.id)
    }

    /// swanctl child SA name for this tunnel's (single) child.
    pub fn child_name(&self) -> String {
        format!("aifw-{}-1", self.id)
    }

    /// Copy with secret material blanked, safe for API responses.
    /// Non-secret cert PEMs are kept (they're public material).
    pub fn redacted(&self) -> Self {
        let mut t = self.clone();
        if !t.psk.is_empty() {
            t.psk = "REDACTED".to_string();
        }
        if !t.local_key_pem.is_empty() {
            t.local_key_pem = "REDACTED".to_string();
        }
        t
    }

    /// Validate the whole tunnel config. Everything here ends up inside
    /// a root-parsed swanctl config file, so the checks double as
    /// injection guards (no quotes/newlines in any rendered value).
    pub fn validate(&self) -> crate::Result<()> {
        let fail = |msg: String| Err(crate::AifwError::Validation(msg));

        if self.name.is_empty() || self.name.len() > 64 {
            return fail("tunnel name must be 1-64 characters".into());
        }
        if !self
            .name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || " _-.".contains(c))
        {
            return fail(format!(
                "tunnel name contains invalid characters (allowed: alphanumeric, space, _, -, .): {:?}",
                self.name
            ));
        }

        validate_endpoint("remote_addr", &self.remote_addr)?;
        if self.remote_addr.is_empty() {
            return fail("remote_addr is required".into());
        }
        if !self.local_addr.is_empty() {
            // Local side must be a concrete address, not a DNS name.
            if self.local_addr.parse::<std::net::IpAddr>().is_err() {
                return fail(format!(
                    "local_addr must be an IP address or empty: {:?}",
                    self.local_addr
                ));
            }
        }
        validate_ike_id("local_id", &self.local_id)?;
        validate_ike_id("remote_id", &self.remote_id)?;

        match self.auth_method {
            IpsecAuthMethod::Psk => {
                if self.psk.len() < 16 {
                    return fail("PSK must be at least 16 characters".into());
                }
                if !self.psk.chars().all(|c| c.is_ascii_graphic()) || self.psk.contains('"') {
                    return fail(
                        "PSK must be printable ASCII without spaces or double quotes".into(),
                    );
                }
            }
            IpsecAuthMethod::Cert => match self.cert_source {
                Some(IpsecCertSource::Acme) => {
                    if self.acme_cert_id.is_none() {
                        return fail("cert_source acme requires acme_cert_id".into());
                    }
                }
                Some(IpsecCertSource::Manual) => {
                    validate_pem("local_cert_pem", &self.local_cert_pem, "CERTIFICATE")?;
                    validate_pem_key("local_key_pem", &self.local_key_pem)?;
                    if !self.ca_cert_pem.is_empty() {
                        validate_pem("ca_cert_pem", &self.ca_cert_pem, "CERTIFICATE")?;
                    }
                }
                None => return fail("auth_method cert requires cert_source".into()),
            },
        }

        validate_proposal("ike", &self.ike_proposal)?;
        validate_proposal("esp", &self.esp_proposal)?;

        for (field, list) in [("local_ts", &self.local_ts), ("remote_ts", &self.remote_ts)] {
            if list.is_empty() {
                return fail(format!("{field} requires at least one subnet"));
            }
            for ts in list {
                match Address::parse(ts) {
                    Ok(Address::Single(_)) | Ok(Address::Network(_, _)) => {}
                    _ => {
                        return fail(format!(
                            "{field} entry must be an IP or CIDR subnet: {ts:?}"
                        ));
                    }
                }
            }
        }

        if !(600..=604_800).contains(&self.ike_lifetime_secs) {
            return fail("ike_lifetime_secs must be between 600 and 604800".into());
        }
        if !(300..=86_400).contains(&self.esp_lifetime_secs) {
            return fail("esp_lifetime_secs must be between 300 and 86400".into());
        }
        if self.dpd_delay_secs > 3_600 {
            return fail("dpd_delay_secs must be at most 3600".into());
        }

        Ok(())
    }
}

/// Endpoint: IP address or DNS hostname (letters/digits/dot/hyphen).
fn validate_endpoint(field: &str, value: &str) -> crate::Result<()> {
    if value.is_empty() {
        return Ok(());
    }
    if value.parse::<std::net::IpAddr>().is_ok() {
        return Ok(());
    }
    let hostname_ok = value.len() <= 253
        && !value.starts_with('-')
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-');
    if !hostname_ok {
        return Err(crate::AifwError::Validation(format!(
            "{field} must be an IP address or DNS name: {value:?}"
        )));
    }
    Ok(())
}

/// IKE identity: FQDN, IP, email-style, or DN-style string. Rendered
/// double-quoted into swanctl config, so quotes/control chars are the
/// injection surface and are rejected.
fn validate_ike_id(field: &str, value: &str) -> crate::Result<()> {
    if value.is_empty() {
        return Ok(());
    }
    if value.len() > 128 {
        return Err(crate::AifwError::Validation(format!(
            "{field} must be at most 128 characters"
        )));
    }
    if !value.chars().all(|c| c.is_ascii_graphic() || c == ' ')
        || value.contains('"')
        || value.contains('\\')
    {
        return Err(crate::AifwError::Validation(format!(
            "{field} contains invalid characters (printable ASCII, no quotes/backslash): {value:?}"
        )));
    }
    Ok(())
}

/// A PEM blob with the expected BEGIN tag and no stray characters that
/// could smuggle content into an adjacent config context.
fn validate_pem(field: &str, value: &str, tag: &str) -> crate::Result<()> {
    let begin = format!("-----BEGIN {tag}-----");
    if !value.contains(&begin) {
        return Err(crate::AifwError::Validation(format!(
            "{field} does not look like a {tag} PEM block"
        )));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_graphic() || c == '\n' || c == '\r' || c == ' ')
    {
        return Err(crate::AifwError::Validation(format!(
            "{field} contains non-PEM characters"
        )));
    }
    Ok(())
}

/// Private keys come in several PEM flavors (PRIVATE KEY, RSA PRIVATE
/// KEY, EC PRIVATE KEY) — accept any `... PRIVATE KEY-----` header.
fn validate_pem_key(field: &str, value: &str) -> crate::Result<()> {
    if !value.contains("PRIVATE KEY-----") || !value.contains("-----BEGIN") {
        return Err(crate::AifwError::Validation(format!(
            "{field} does not look like a private key PEM block"
        )));
    }
    if !value
        .chars()
        .all(|c| c.is_ascii_graphic() || c == '\n' || c == '\r' || c == ' ')
    {
        return Err(crate::AifwError::Validation(format!(
            "{field} contains non-PEM characters"
        )));
    }
    Ok(())
}

/// Live negotiated state of one tunnel, parsed from `swanctl --list-sas`.
/// Absence of a matching IKE SA means the tunnel is down/not negotiated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpsecLiveStatus {
    /// Tunnel this status belongs to
    pub tunnel_id: Uuid,
    /// swanctl conn name (`aifw-<id>`)
    pub conn_name: String,
    /// IKE SA state as reported by charon (e.g. `ESTABLISHED`,
    /// `CONNECTING`); `DOWN` when no SA exists
    pub ike_state: String,
    /// Seconds since the IKE SA was established
    pub established_secs: Option<u64>,
    /// Peer address the SA is actually talking to
    pub remote_host: Option<String>,
    /// IKE version in use (2 for everything AiFw configures)
    pub ike_version: Option<u8>,
    /// Negotiated child SAs (normally exactly one)
    pub child_sas: Vec<ChildSaStatus>,
}

impl IpsecLiveStatus {
    /// A "no SA present" status for a tunnel charon knows nothing about.
    pub fn down(tunnel_id: Uuid, conn_name: String) -> Self {
        Self {
            tunnel_id,
            conn_name,
            ike_state: "DOWN".to_string(),
            established_secs: None,
            remote_host: None,
            ike_version: None,
            child_sas: Vec::new(),
        }
    }
}

/// Live state of one child (ESP) SA.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChildSaStatus {
    /// Child SA name (`aifw-<id>-1`)
    pub name: String,
    /// Child SA state (e.g. `INSTALLED`, `REKEYING`)
    pub state: String,
    /// Negotiated local traffic selectors
    pub local_ts: Vec<String>,
    /// Negotiated remote traffic selectors
    pub remote_ts: Vec<String>,
    /// Bytes received over this SA
    pub bytes_in: u64,
    /// Bytes sent over this SA
    pub bytes_out: u64,
    /// Seconds until charon rekeys this SA
    pub rekey_in_secs: Option<u64>,
    /// Negotiated encryption algorithm (e.g. `AES_GCM_16-256`)
    pub enc_alg: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_tunnel() -> IpsecTunnel {
        IpsecTunnel::new(
            "site-a".to_string(),
            "203.0.113.10".to_string(),
            "correct-horse-battery-staple".to_string(),
            vec!["10.0.0.0/24".to_string()],
            vec!["10.1.0.0/24".to_string()],
        )
    }

    #[test]
    fn default_tunnel_validates() {
        base_tunnel().validate().unwrap();
    }

    #[test]
    fn conn_names_are_in_wrapper_namespace() {
        let t = base_tunnel();
        assert!(t.conn_name().starts_with("aifw-"));
        assert!(t.child_name().starts_with("aifw-"));
        assert!(
            t.conn_name()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        );
    }

    #[test]
    fn short_psk_rejected() {
        let mut t = base_tunnel();
        t.psk = "short".to_string();
        assert!(t.validate().is_err());
    }

    #[test]
    fn psk_with_quote_rejected() {
        let mut t = base_tunnel();
        t.psk = "aaaaaaaaaaaaaaa\"injection".to_string();
        assert!(t.validate().is_err());
    }

    #[test]
    fn bad_proposal_rejected() {
        let mut t = base_tunnel();
        t.ike_proposal = "des-md5-modp768".to_string();
        assert!(t.validate().is_err());
        t.ike_proposal = "aes256gcm16-prfsha256-ecp256".to_string();
        t.esp_proposal = "aes256gcm16\nevil".to_string();
        assert!(t.validate().is_err());
    }

    #[test]
    fn hostname_remote_accepted_garbage_rejected() {
        let mut t = base_tunnel();
        t.remote_addr = "vpn.example.com".to_string();
        t.validate().unwrap();
        t.remote_addr = "peer;rm -rf /".to_string();
        assert!(t.validate().is_err());
        t.remote_addr = String::new();
        assert!(t.validate().is_err());
    }

    #[test]
    fn ike_id_injection_rejected() {
        let mut t = base_tunnel();
        t.local_id = "C=US, O=AiFw, CN=site-a".to_string();
        t.validate().unwrap();
        t.remote_id = "peer\"\n}\nsecrets {".to_string();
        assert!(t.validate().is_err());
    }

    #[test]
    fn traffic_selectors_validated() {
        let mut t = base_tunnel();
        t.local_ts = vec![];
        assert!(t.validate().is_err());
        t.local_ts = vec!["any".to_string()];
        assert!(t.validate().is_err());
        t.local_ts = vec!["10.0.0.0/24".to_string(), "192.168.5.1".to_string()];
        t.validate().unwrap();
    }

    #[test]
    fn cert_auth_requires_material() {
        let mut t = base_tunnel();
        t.auth_method = IpsecAuthMethod::Cert;
        t.psk = String::new();
        assert!(t.validate().is_err()); // no cert_source

        t.cert_source = Some(IpsecCertSource::Acme);
        assert!(t.validate().is_err()); // no acme_cert_id
        t.acme_cert_id = Some(Uuid::new_v4());
        t.validate().unwrap();

        t.cert_source = Some(IpsecCertSource::Manual);
        assert!(t.validate().is_err()); // no PEM material
        t.local_cert_pem = "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----".into();
        t.local_key_pem = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----".into();
        t.validate().unwrap();
    }

    #[test]
    fn redacted_blanks_secrets_only() {
        let mut t = base_tunnel();
        t.local_key_pem = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----".into();
        t.local_cert_pem = "-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----".into();
        let r = t.redacted();
        assert_eq!(r.psk, "REDACTED");
        assert_eq!(r.local_key_pem, "REDACTED");
        assert_eq!(r.local_cert_pem, t.local_cert_pem);
        assert_eq!(r.remote_addr, t.remote_addr);
    }

    #[test]
    fn lifetimes_bounded() {
        let mut t = base_tunnel();
        t.ike_lifetime_secs = 10;
        assert!(t.validate().is_err());
        t.ike_lifetime_secs = DEFAULT_IKE_LIFETIME_SECS;
        t.esp_lifetime_secs = 100_000_000;
        assert!(t.validate().is_err());
    }

    #[test]
    fn start_action_roundtrip() {
        for (s, v) in [
            ("start", IpsecStartAction::Start),
            ("trap", IpsecStartAction::Trap),
            ("none", IpsecStartAction::None),
        ] {
            assert_eq!(IpsecStartAction::parse(s).unwrap(), v);
            assert_eq!(v.to_string(), s);
        }
        assert!(IpsecStartAction::parse("bogus").is_err());
    }
}
