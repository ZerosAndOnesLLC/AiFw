//! Secret handling for exported configuration (#313 / SEC-M16).
//!
//! A [`FirewallConfig`] embeds every credential the data plane needs —
//! WireGuard private and preshared keys, IPsec PSKs and private keys, CARP
//! passwords, the DHCP DDNS TSIG secret. Inside the appliance those live
//! sealed at rest (#298); the moment a config leaves the box as a backup
//! download, an S3 object or a history view, they used to travel in the
//! clear. This module gives every export path one of two safe shapes:
//!
//! * **Redacted** — every secret becomes [`REDACTED`]. The file is still a
//!   complete, diffable description of the box; on import the sentinel is
//!   resolved back against the secrets the box already holds
//!   ([`resolve_redacted`]) so a redacted backup restores cleanly onto the
//!   appliance it came from (same tunnel / VIP ids). Anything that cannot
//!   be resolved is reported by name and the import is refused.
//! * **Passphrase-wrapped** — every secret becomes
//!   `pw:v1:<base64(nonce ‖ ciphertext ‖ tag)>` under an AES-256-GCM key
//!   derived from an operator passphrase with Argon2id. The KDF salt and
//!   parameters ride along in [`FirewallConfig::secrets`] so the file is
//!   self-describing and restorable on any box that knows the passphrase.
//!
//! Cluster snapshots keep real values: the standby has to hold the keys to
//! take over, and since #317 that channel is certificate-pinned.

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde::{Deserialize, Serialize};

use crate::config::FirewallConfig;
use crate::{CoreError, Result};

/// Sentinel written in place of a secret by [`redact`].
pub const REDACTED: &str = "**REDACTED**";
/// Prefix of a passphrase-wrapped secret value.
pub const PW_PREFIX: &str = "pw:v1:";

/// Argon2id parameters used for new envelopes (OWASP 2023 baseline).
const M_COST_KIB: u32 = 64 * 1024;
const T_COST: u32 = 3;
const P_COST: u32 = 1;
const SALT_LEN: usize = 16;
const KEY_LEN: usize = 32;
/// Upper bound accepted when *opening* an envelope, so a hostile file cannot
/// make the importer allocate gigabytes.
const MAX_M_COST_KIB: u32 = 1024 * 1024;
const MAX_T_COST: u32 = 16;

/// KDF parameters stored alongside passphrase-wrapped secrets.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretsEnvelope {
    /// Always `argon2id` today; reserved for future KDFs.
    pub kdf: String,
    /// Base64 KDF salt.
    pub salt: String,
    /// Argon2 memory cost in KiB.
    pub m_cost: u32,
    /// Argon2 iterations.
    pub t_cost: u32,
    /// Argon2 parallelism.
    pub p_cost: u32,
}

/// Where the secrets of a config stand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum SecretsState {
    /// Every secret is present in the clear (or the config has none).
    Plain,
    /// `count` secrets are the [`REDACTED`] sentinel.
    Redacted {
        /// Number of redacted values.
        count: usize,
    },
    /// `count` secrets are passphrase-wrapped.
    Passphrase {
        /// Number of wrapped values.
        count: usize,
    },
}

/// Which secret a visitor is looking at — used for resolution by id and
/// for human-readable error messages.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SecretRef {
    /// Section the secret belongs to (`wireguard`, `ipsec`, `carp`, `dhcp_ddns`).
    pub section: &'static str,
    /// Owning object id (tunnel / peer / VIP id; empty for singletons).
    pub id: String,
    /// Field name inside that object.
    pub field: &'static str,
}

impl std::fmt::Display for SecretRef {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.id.is_empty() {
            write!(f, "{}.{}", self.section, self.field)
        } else {
            write!(f, "{}[{}].{}", self.section, self.id, self.field)
        }
    }
}

/// Visit every secret slot in `cfg`. `Option<String>` slots are visited as
/// `&mut Option<String>` through the same closure by temporarily taking the
/// value; `None` slots are skipped.
fn for_each_secret(cfg: &mut FirewallConfig, mut f: impl FnMut(SecretRef, &mut String)) {
    for wg in &mut cfg.vpn.wireguard {
        f(
            SecretRef {
                section: "wireguard",
                id: wg.id.clone(),
                field: "private_key",
            },
            &mut wg.private_key,
        );
        for p in &mut wg.peers {
            if let Some(psk) = p.preshared_key.as_mut() {
                f(
                    SecretRef {
                        section: "wireguard_peer",
                        id: p.id.clone(),
                        field: "preshared_key",
                    },
                    psk,
                );
            }
        }
    }
    for t in &mut cfg.vpn.ipsec_tunnels {
        let id = t.id.to_string();
        f(
            SecretRef {
                section: "ipsec",
                id: id.clone(),
                field: "psk",
            },
            &mut t.psk,
        );
        f(
            SecretRef {
                section: "ipsec",
                id,
                field: "local_key_pem",
            },
            &mut t.local_key_pem,
        );
    }
    for v in &mut cfg.ha.carp_vips {
        f(
            SecretRef {
                section: "carp",
                id: v.id.clone(),
                field: "password",
            },
            &mut v.password,
        );
    }
    f(
        SecretRef {
            section: "dhcp_ddns",
            id: String::new(),
            field: "tsig_secret",
        },
        &mut cfg.dhcp.ddns.tsig_secret,
    );
}

/// Same walk over a shared reference (read-only inspection).
fn secrets_of(cfg: &FirewallConfig) -> Vec<(SecretRef, String)> {
    let mut out = Vec::new();
    let mut c = cfg.clone();
    for_each_secret(&mut c, |r, v| out.push((r, v.clone())));
    out
}

/// Classify the secrets in `cfg`. Mixed files (some redacted, some wrapped)
/// report the wrapped state — the passphrase is needed regardless.
pub fn state(cfg: &FirewallConfig) -> SecretsState {
    let mut redacted = 0;
    let mut wrapped = 0;
    for (_, v) in secrets_of(cfg) {
        if v == REDACTED {
            redacted += 1;
        } else if v.starts_with(PW_PREFIX) {
            wrapped += 1;
        }
    }
    if wrapped > 0 || cfg.secrets.is_some() {
        SecretsState::Passphrase { count: wrapped }
    } else if redacted > 0 {
        SecretsState::Redacted { count: redacted }
    } else {
        SecretsState::Plain
    }
}

/// Replace every non-empty secret with [`REDACTED`]. Already-wrapped
/// values are redacted too (the envelope is dropped) so a redacted export
/// never carries ciphertext.
pub fn redact(cfg: &mut FirewallConfig) {
    for_each_secret(cfg, |_, v| {
        if !v.is_empty() {
            *v = REDACTED.to_string();
        }
    });
    cfg.secrets = None;
}

/// Wrap every non-empty, non-redacted secret under `passphrase`. Fails if
/// the config still holds wrapped values from another passphrase (open it
/// first) or the passphrase is empty.
pub fn seal_with_passphrase(cfg: &mut FirewallConfig, passphrase: &str) -> Result<()> {
    if passphrase.is_empty() {
        return Err(CoreError::Validation(
            "backup passphrase must not be empty".into(),
        ));
    }
    if matches!(state(cfg), SecretsState::Passphrase { .. }) {
        return Err(CoreError::Validation(
            "config already holds passphrase-wrapped secrets".into(),
        ));
    }
    let mut salt = [0u8; SALT_LEN];
    getrandom::fill(&mut salt)
        .map_err(|e| CoreError::Other(format!("backup secrets: salt generation failed: {e}")))?;
    let envelope = SecretsEnvelope {
        kdf: "argon2id".into(),
        salt: B64.encode(salt),
        m_cost: M_COST_KIB,
        t_cost: T_COST,
        p_cost: P_COST,
    };
    let key = derive_key(passphrase, &envelope)?;
    let mut err = None;
    for_each_secret(cfg, |r, v| {
        if err.is_some() || v.is_empty() || v == REDACTED {
            return;
        }
        match wrap_value(&key, v) {
            Ok(w) => *v = w,
            Err(e) => err = Some(CoreError::Other(format!("backup secrets: {r}: {e}"))),
        }
    });
    if let Some(e) = err {
        return Err(e);
    }
    cfg.secrets = Some(envelope);
    Ok(())
}

/// Unwrap every passphrase-wrapped secret in place. A wrong passphrase
/// fails on the first value (AEAD tag mismatch) and leaves `cfg` untouched.
pub fn open_with_passphrase(cfg: &mut FirewallConfig, passphrase: &str) -> Result<()> {
    let Some(envelope) = cfg.secrets.clone() else {
        if secrets_of(cfg)
            .iter()
            .any(|(_, v)| v.starts_with(PW_PREFIX))
        {
            return Err(CoreError::Validation(
                "config has passphrase-wrapped secrets but no KDF envelope".into(),
            ));
        }
        return Ok(());
    };
    let key = derive_key(passphrase, &envelope)?;
    // Decrypt into a scratch copy so a bad passphrase can't leave the config
    // half-opened.
    let mut scratch = cfg.clone();
    let mut err = None;
    for_each_secret(&mut scratch, |r, v| {
        if err.is_some() {
            return;
        }
        if let Some(b64) = v.strip_prefix(PW_PREFIX) {
            match unwrap_value(&key, b64) {
                Ok(pt) => *v = pt,
                Err(e) => err = Some(CoreError::Validation(format!("{r}: {e}"))),
            }
        }
    });
    if let Some(e) = err {
        return Err(e);
    }
    scratch.secrets = None;
    *cfg = scratch;
    Ok(())
}

/// Fill [`REDACTED`] slots from `current` (the config the box holds right
/// now), matching by section + object id. Returns the refs that could not
/// be resolved; the caller decides whether that is fatal. Wrapped values
/// are left alone.
pub fn resolve_redacted(cfg: &mut FirewallConfig, current: &FirewallConfig) -> Vec<SecretRef> {
    let known: std::collections::HashMap<SecretRef, String> = secrets_of(current)
        .into_iter()
        .filter(|(_, v)| !v.is_empty() && v != REDACTED && !v.starts_with(PW_PREFIX))
        .collect();
    let mut unresolved = Vec::new();
    for_each_secret(cfg, |r, v| {
        if v != REDACTED {
            return;
        }
        match known.get(&r) {
            Some(cur) => *v = cur.clone(),
            None => unresolved.push(r),
        }
    });
    unresolved
}

/// Names of every secret still equal to [`REDACTED`] — what an import
/// would have to resolve.
pub fn redacted_refs(cfg: &FirewallConfig) -> Vec<SecretRef> {
    secrets_of(cfg)
        .into_iter()
        .filter(|(_, v)| v == REDACTED)
        .map(|(r, _)| r)
        .collect()
}

fn derive_key(passphrase: &str, env: &SecretsEnvelope) -> Result<LessSafeKey> {
    if env.kdf != "argon2id" {
        return Err(CoreError::Validation(format!(
            "unsupported backup KDF `{}`",
            env.kdf
        )));
    }
    if env.m_cost > MAX_M_COST_KIB || env.t_cost > MAX_T_COST || env.p_cost == 0 || env.p_cost > 16
    {
        return Err(CoreError::Validation(
            "backup KDF parameters out of range".into(),
        ));
    }
    let salt = B64
        .decode(&env.salt)
        .map_err(|e| CoreError::Validation(format!("backup KDF salt malformed: {e}")))?;
    let params = argon2::Params::new(env.m_cost, env.t_cost, env.p_cost, Some(KEY_LEN))
        .map_err(|e| CoreError::Validation(format!("backup KDF parameters invalid: {e}")))?;
    let argon = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|e| CoreError::Other(format!("backup KDF failed: {e}")))?;
    let unbound = UnboundKey::new(&AES_256_GCM, &key)
        .map_err(|_| CoreError::Other("backup secrets: key setup failed".into()))?;
    Ok(LessSafeKey::new(unbound))
}

fn wrap_value(key: &LessSafeKey, plaintext: &str) -> std::result::Result<String, String> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce_bytes).map_err(|e| format!("nonce generation failed: {e}"))?;
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let mut buf = plaintext.as_bytes().to_vec();
    key.seal_in_place_append_tag(nonce, Aad::empty(), &mut buf)
        .map_err(|_| "encryption failed".to_string())?;
    let mut out = Vec::with_capacity(NONCE_LEN + buf.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&buf);
    Ok(format!("{PW_PREFIX}{}", B64.encode(out)))
}

fn unwrap_value(key: &LessSafeKey, b64: &str) -> std::result::Result<String, String> {
    let raw = B64
        .decode(b64)
        .map_err(|e| format!("malformed wrapped value: {e}"))?;
    if raw.len() < NONCE_LEN + AES_256_GCM.tag_len() {
        return Err("wrapped value too short".into());
    }
    let (nonce_bytes, ct) = raw.split_at(NONCE_LEN);
    let nonce =
        Nonce::try_assume_unique_for_key(nonce_bytes).map_err(|_| "bad nonce".to_string())?;
    let mut buf = ct.to_vec();
    let pt = key
        .open_in_place(nonce, Aad::empty(), &mut buf)
        .map_err(|_| "wrong passphrase or corrupted value".to_string())?;
    String::from_utf8(pt.to_vec()).map_err(|_| "wrapped value is not UTF-8".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{CarpVipConfig, WireguardPeerConfig, WireguardTunnelConfig};

    fn sample() -> FirewallConfig {
        let mut cfg = FirewallConfig::default();
        cfg.vpn.wireguard.push(WireguardTunnelConfig {
            id: "wg-1".into(),
            name: "wg0".into(),
            interface: "wg0".into(),
            listen_port: 51820,
            address: "10.0.0.1/24".into(),
            address6: None,
            private_key: "PRIV".into(),
            public_key: "PUB".into(),
            dns: None,
            mtu: None,
            peers: vec![WireguardPeerConfig {
                id: "peer-1".into(),
                name: "p".into(),
                public_key: "PPUB".into(),
                preshared_key: Some("PSK".into()),
                endpoint: None,
                allowed_ips: vec![],
                persistent_keepalive: None,
            }],
        });
        cfg.ha.carp_vips.push(CarpVipConfig {
            id: "vip-1".into(),
            vhid: 1,
            virtual_ip: "192.0.2.1".into(),
            prefix: 24,
            interface: "em0".into(),
            password: "carp-pw".into(),
        });
        cfg.dhcp.ddns.tsig_secret = "tsig".into();
        cfg
    }

    #[test]
    fn plain_state_and_redaction() {
        let mut cfg = sample();
        assert_eq!(state(&cfg), SecretsState::Plain);
        redact(&mut cfg);
        assert_eq!(state(&cfg), SecretsState::Redacted { count: 4 });
        assert_eq!(cfg.vpn.wireguard[0].private_key, REDACTED);
        assert_eq!(
            cfg.vpn.wireguard[0].peers[0].preshared_key.as_deref(),
            Some(REDACTED)
        );
        assert_eq!(cfg.ha.carp_vips[0].password, REDACTED);
        assert_eq!(cfg.dhcp.ddns.tsig_secret, REDACTED);
        // non-secret fields untouched
        assert_eq!(cfg.vpn.wireguard[0].public_key, "PUB");
    }

    #[test]
    fn empty_secrets_are_not_redacted() {
        let mut cfg = FirewallConfig::default();
        redact(&mut cfg);
        assert_eq!(state(&cfg), SecretsState::Plain);
        assert_eq!(cfg.dhcp.ddns.tsig_secret, "");
    }

    #[test]
    fn passphrase_round_trip() {
        let mut cfg = sample();
        seal_with_passphrase(&mut cfg, "hunter2").unwrap();
        assert_eq!(state(&cfg), SecretsState::Passphrase { count: 4 });
        assert!(cfg.vpn.wireguard[0].private_key.starts_with(PW_PREFIX));
        assert!(cfg.secrets.is_some());
        // survives JSON
        let json = cfg.to_json();
        let mut back = FirewallConfig::from_json(&json).unwrap();
        assert!(open_with_passphrase(&mut back, "wrong").is_err());
        assert!(
            back.vpn.wireguard[0].private_key.starts_with(PW_PREFIX),
            "untouched on failure"
        );
        open_with_passphrase(&mut back, "hunter2").unwrap();
        assert_eq!(state(&back), SecretsState::Plain);
        assert_eq!(back.vpn.wireguard[0].private_key, "PRIV");
        assert_eq!(
            back.vpn.wireguard[0].peers[0].preshared_key.as_deref(),
            Some("PSK")
        );
        assert_eq!(back.ha.carp_vips[0].password, "carp-pw");
        assert_eq!(back.dhcp.ddns.tsig_secret, "tsig");
        assert!(back.secrets.is_none());
    }

    #[test]
    fn empty_passphrase_rejected() {
        let mut cfg = sample();
        assert!(seal_with_passphrase(&mut cfg, "").is_err());
    }

    #[test]
    fn hostile_kdf_params_rejected() {
        let mut cfg = sample();
        seal_with_passphrase(&mut cfg, "pw").unwrap();
        cfg.secrets.as_mut().unwrap().m_cost = u32::MAX;
        assert!(open_with_passphrase(&mut cfg, "pw").is_err());
    }

    #[test]
    fn resolve_redacted_by_id() {
        let current = sample();
        let mut cfg = sample();
        redact(&mut cfg);
        // one object the box doesn't know
        cfg.ha.carp_vips[0].id = "vip-new".into();
        let unresolved = resolve_redacted(&mut cfg, &current);
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].to_string(), "carp[vip-new].password");
        assert_eq!(cfg.vpn.wireguard[0].private_key, "PRIV");
        assert_eq!(cfg.dhcp.ddns.tsig_secret, "tsig");
        assert_eq!(cfg.ha.carp_vips[0].password, REDACTED);
    }
}
