//! The certificate the AiFw API (web UI, port 8080) serves.
//!
//! Used by the ACME "local-tls-store" export target and by "use for the web
//! UI" on internal-CA certificates (#717). The pair is validated before it
//! is installed (a bad pair would leave the API unable to start), staged in
//! a private directory, and installed root-owned but readable by the `aifw`
//! user the API runs as.

use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

/// Where aifw-api reads its serving certificate chain (`--tls-cert`).
pub const API_CERT_PATH: &str = "/usr/local/etc/aifw/tls/cert.pem";
/// Where aifw-api reads its private key (`--tls-key`).
pub const API_KEY_PATH: &str = "/usr/local/etc/aifw/tls/key.pem";

/// Check that `fullchain_pem` (leaf first) and `key_pem` form a pair the
/// API's TLS server accepts: both parse and the key matches the leaf.
pub fn validate(fullchain_pem: &str, key_pem: &str) -> Result<(), String> {
    let certs: Vec<_> = rustls_pemfile::certs(&mut fullchain_pem.as_bytes())
        .collect::<Result<_, _>>()
        .map_err(|e| format!("certificate PEM: {e}"))?;
    if certs.is_empty() {
        return Err("no certificate in the PEM".into());
    }
    let key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
        .map_err(|e| format!("private key PEM: {e}"))?
        .ok_or_else(|| "no private key in the PEM".to_string())?;
    let provider = std::sync::Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|e| format!("unsupported private key: {e}"))?;
    let certified = rustls::sign::CertifiedKey::new(certs, signing_key);
    certified
        .keys_match()
        .map_err(|e| format!("the private key does not belong to the certificate: {e}"))
}

/// The install helper only accepts sources under /tmp.
const STAGING_ROOT: &str = "/tmp";

/// A private, unique staging directory under /tmp. Removed on drop.
struct Staging(PathBuf);

impl Staging {
    fn new() -> Result<Self, String> {
        let dir =
            Path::new(STAGING_ROOT).join(format!("aifw-tls-{}", uuid::Uuid::new_v4().simple()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .map_err(|e| format!("staging dir: {e}"))?;
        Ok(Self(dir))
    }

    /// Write `body` to a new 0600 file inside the staging dir.
    fn file(&self, name: &str, body: &str) -> Result<PathBuf, String> {
        let path = self.0.join(name);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| format!("staging {name}: {e}"))?;
        f.write_all(body.as_bytes())
            .map_err(|e| format!("staging {name}: {e}"))?;
        Ok(path)
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        if let Err(e) = std::fs::remove_dir_all(&self.0) {
            tracing::warn!(path = %self.0.display(), error = %e, "could not remove TLS staging dir");
        }
    }
}

/// Install `body` at `dest` as root via the `aifw-sudo-install` helper,
/// staged privately (never a predictable, world-readable /tmp file).
pub async fn install_file(
    body: &str,
    dest: &str,
    mode: &str,
    owner: Option<&str>,
) -> Result<(), String> {
    let staging = Staging::new()?;
    let name = Path::new(dest)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file");
    let src = staging.file(name, body)?;
    let src = src.to_str().ok_or("non-UTF-8 staging path")?;
    let (user, group) = match owner {
        Some(o) => {
            let mut parts = o.splitn(2, ':');
            (parts.next().filter(|s| !s.is_empty()), parts.next())
        }
        None => (None, None),
    };
    let out = crate::sudo::install(Some(mode), user, group, src, dest)
        .await
        .map_err(|e| format!("spawn sudo install: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "sudo install -> {dest}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

/// Validate and install a new serving pair for the API. The key is 0440
/// root:aifw — readable by the API's service user, not writable by it.
/// The caller restarts the API (see [`restart_api`]).
pub async fn install(fullchain_pem: &str, key_pem: &str) -> Result<(), String> {
    validate(fullchain_pem, key_pem)?;
    install_file(fullchain_pem, API_CERT_PATH, "0644", Some("root:aifw")).await?;
    install_file(key_pem, API_KEY_PATH, "0440", Some("root:aifw")).await?;
    Ok(())
}

/// Restart the API so it serves the new certificate.
pub async fn restart_api() -> Result<(), String> {
    let out = crate::sudo::service("aifw_api", "restart")
        .await
        .map_err(|e| format!("spawn service restart: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "service aifw_api restart: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(cn: &str) -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec![cn.to_string()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        (cert.pem(), key.serialize_pem())
    }

    #[test]
    fn matching_pair_is_accepted() {
        let (c, k) = pair("fw.example.test");
        validate(&c, &k).unwrap();
    }

    #[test]
    fn mismatched_or_broken_pairs_are_refused() {
        let (c, _) = pair("a.test");
        let (_, k2) = pair("b.test");
        assert!(validate(&c, &k2).unwrap_err().contains("does not belong"));
        assert!(validate("nope", &k2).is_err());
        assert!(validate(&c, "nope").is_err());
    }

    #[test]
    fn staging_is_private_and_cleaned_up() {
        use std::os::unix::fs::PermissionsExt;
        let s = Staging::new().unwrap();
        let dir = s.0.clone();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let f = s.file("key.pem", "secret").unwrap();
        assert_eq!(
            std::fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(s.file("key.pem", "again").is_err(), "never reuses a file");
        drop(s);
        assert!(!dir.exists());
    }
}
