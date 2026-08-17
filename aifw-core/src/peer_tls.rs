//! TLS trust for AiFw-to-AiFw HTTPS calls (#317 / SEC-L2).
//!
//! Cluster peers and the daemon's loopback calls used to accept any
//! certificate (`danger_accept_invalid_certs`) — the peer API key was the
//! only thing standing between an on-path attacker and the replication
//! stream (which carries the whole config, secrets included). Calls now
//! pin the leaf certificate by SHA-256 fingerprint:
//!
//! * **Peers** — the pin lives in `cluster_nodes.cert_fingerprint`. It is
//!   learned on first successful contact (trust-on-first-use, like an SSH
//!   `known_hosts` entry) and enforced from then on. Cert distribution via
//!   `cluster/cert-push` updates the pins on both sides, and an operator
//!   can clear a pin (`POST /cluster/nodes/{id}/repin`, `aifw cluster
//!   repin`) after a manual certificate change.
//! * **Loopback** (aifw-daemon → local aifw-api) — pinned to the certificate
//!   file the API serves (`/usr/local/etc/aifw/tls/cert.pem`); the client is
//!   rebuilt when that file changes, so ACME renewals and self-signed
//!   regeneration are picked up without a restart.
//!
//! A pin mismatch fails the handshake and logs both fingerprints.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};

/// Where aifw-api reads its serving certificate from (see `--tls-cert`).
pub const LOCAL_API_CERT_PATH: &str = "/usr/local/etc/aifw/tls/cert.pem";

/// Lowercase hex SHA-256 of a DER certificate — the pin format everywhere.
pub fn fingerprint_der(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

/// Fingerprint of the first certificate in a PEM file, if readable.
pub fn fingerprint_pem_file(path: &Path) -> Option<String> {
    let pem = std::fs::read(path).ok()?;
    let mut reader = std::io::Cursor::new(pem);
    let cert = rustls_pemfile::certs(&mut reader).next()?.ok()?;
    Some(fingerprint_der(cert.as_ref()))
}

/// Fingerprint of the first certificate in PEM text (cert push payloads).
pub fn fingerprint_pem_str(pem: &str) -> Option<String> {
    let mut reader = std::io::Cursor::new(pem.as_bytes());
    let cert = rustls_pemfile::certs(&mut reader).next()?.ok()?;
    Some(fingerprint_der(cert.as_ref()))
}

/// Short form for logs / UI (`ab12cd34…`).
pub fn short(fp: &str) -> String {
    fp.chars().take(16).collect::<String>() + "…"
}

/// Peer certificate fingerprint observed on a response (requires the client
/// to have been built with `tls_info`).
pub fn observed_fingerprint(resp: &reqwest::Response) -> Option<String> {
    resp.extensions()
        .get::<reqwest::tls::TlsInfo>()
        .and_then(|t| t.peer_certificate())
        .map(fingerprint_der)
}

/// Verifier that accepts exactly one leaf certificate (by fingerprint) and
/// nothing else — no chain building, no hostname check (peers are addressed
/// by IP and mostly self-signed). Handshake signatures are still verified
/// with the default provider so the pinned key must actually be in use.
#[derive(Debug)]
struct PinnedCert {
    expected: String,
    label: String,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for PinnedCert {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got = fingerprint_der(end_entity.as_ref());
        if got == self.expected {
            return Ok(ServerCertVerified::assertion());
        }
        warn!(
            peer = %self.label,
            expected = %short(&self.expected),
            observed = %short(&got),
            "TLS pin mismatch — the peer's certificate changed; re-pin it if this was expected"
        );
        Err(rustls::Error::InvalidCertificate(
            rustls::CertificateError::ApplicationVerificationFailure,
        ))
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
}

/// Build an HTTPS client for one peer.
///
/// * `pin = Some(fp)` — only that leaf certificate is accepted.
/// * `pin = None` — first contact: any certificate is accepted **and the
///   response carries `TlsInfo`** so the caller can record the observed
///   fingerprint with [`observed_fingerprint`] and pin it from then on.
pub fn client_for(
    pin: Option<&str>,
    label: &str,
    timeout: Duration,
) -> crate::Result<reqwest::Client> {
    let build = |b: reqwest::ClientBuilder| {
        b.tls_info(true)
            .timeout(timeout)
            .build()
            .map_err(|e| crate::CoreError::Other(format!("peer_tls: http client: {e}")))
    };
    match pin {
        Some(fp) => {
            let verifier = Arc::new(PinnedCert {
                expected: fp.to_ascii_lowercase(),
                label: label.to_string(),
                provider: provider(),
            });
            let cfg = rustls::ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .map_err(|e| crate::CoreError::Other(format!("peer_tls: rustls config: {e}")))?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();
            build(reqwest::Client::builder().tls_backend_preconfigured(cfg))
        }
        None => {
            debug!(
                peer = label,
                "peer_tls: no pin yet — first contact will pin the observed certificate"
            );
            build(reqwest::Client::builder().danger_accept_invalid_certs(true))
        }
    }
}

/// HTTPS client for the local aifw-api (daemon loopback), pinned to the
/// certificate file the API serves. Rebuilt transparently when the file's
/// fingerprint changes (ACME renewal, self-signed regeneration). If the
/// file cannot be read the client falls back to accept-any with a warning
/// — loopback traffic never leaves the box, but the pin is still preferred.
pub struct LocalApiClient {
    cert_path: std::path::PathBuf,
    timeout: Duration,
    state: Mutex<Option<(Option<String>, reqwest::Client)>>,
    warned: std::sync::atomic::AtomicBool,
}

impl LocalApiClient {
    /// Client pinned to [`LOCAL_API_CERT_PATH`].
    pub fn new(timeout: Duration) -> Self {
        Self::with_cert_path(std::path::PathBuf::from(LOCAL_API_CERT_PATH), timeout)
    }

    /// Client pinned to an explicit certificate file.
    pub fn with_cert_path(cert_path: std::path::PathBuf, timeout: Duration) -> Self {
        Self {
            cert_path,
            timeout,
            state: Mutex::new(None),
            warned: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Current client, rebuilt if the local certificate changed.
    pub fn get(&self) -> crate::Result<reqwest::Client> {
        let fp = fingerprint_pem_file(&self.cert_path);
        if fp.is_none() && !self.warned.swap(true, std::sync::atomic::Ordering::Relaxed) {
            warn!(
                path = %self.cert_path.display(),
                "peer_tls: local API certificate not readable — loopback calls fall back to accept-any"
            );
        }
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((cached_fp, client)) = guard.as_ref()
            && *cached_fp == fp
        {
            return Ok(client.clone());
        }
        let client = client_for(fp.as_deref(), "loopback", self.timeout)?;
        if let Some(f) = &fp {
            info!(pin = %short(f), "peer_tls: loopback client pinned to local API certificate");
        }
        *guard = Some((fp, client.clone()));
        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_sha256_hex() {
        let fp = fingerprint_der(b"hello");
        assert_eq!(fp.len(), 64);
        assert_eq!(
            fp,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(short(&fp), "2cf24dba5fb0a30e…");
    }

    #[test]
    fn pem_fingerprint_round_trip() {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["peer.test".into()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let pem = cert.pem();
        let expected = fingerprint_der(cert.der());
        assert_eq!(
            fingerprint_pem_str(&pem).as_deref(),
            Some(expected.as_str())
        );
        let dir = std::env::temp_dir().join(format!("aifw-peer-tls-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cert.pem");
        std::fs::write(&path, &pem).unwrap();
        assert_eq!(
            fingerprint_pem_file(&path).as_deref(),
            Some(expected.as_str())
        );
        assert!(fingerprint_pem_file(&dir.join("missing.pem")).is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pinned_verifier_accepts_only_the_pinned_leaf() {
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["peer.test".into()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let other_key = rcgen::KeyPair::generate().unwrap();
        let other = rcgen::CertificateParams::new(vec!["peer.test".into()])
            .unwrap()
            .self_signed(&other_key)
            .unwrap();
        let v = PinnedCert {
            expected: fingerprint_der(cert.der()),
            label: "t".into(),
            provider: provider(),
        };
        let name = ServerName::try_from("peer.test").unwrap();
        let now = UnixTime::now();
        assert!(
            v.verify_server_cert(cert.der(), &[], &name, &[], now)
                .is_ok()
        );
        assert!(
            v.verify_server_cert(other.der(), &[], &name, &[], now)
                .is_err()
        );
    }

    /// Spin up a one-shot HTTPS server on 127.0.0.1 with a fresh self-signed
    /// cert; returns (port, leaf fingerprint). Serves any number of requests
    /// with a tiny 200 response.
    async fn tls_server() -> (u16, String) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let key = rcgen::KeyPair::generate().unwrap();
        let params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        let cert = params.self_signed(&key).unwrap();
        let fp = fingerprint_der(cert.der());
        let certs = vec![CertificateDer::from(cert.der().to_vec())];
        let key_der = rustls::pki_types::PrivateKeyDer::try_from(key.serialize_der()).unwrap();
        let cfg = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(certs, key_der)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((sock, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(sock).await else {
                        return;
                    };
                    let mut buf = [0u8; 2048];
                    let _ = tls.read(&mut buf).await;
                    let _ = tls
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                    let _ = tls.shutdown().await;
                });
            }
        });
        (port, fp)
    }

    #[tokio::test]
    async fn pinned_client_end_to_end() {
        let (port, fp) = tls_server().await;
        let url = format!("https://127.0.0.1:{port}/");

        // Unpinned first contact: connects, and the observed fingerprint is exposed.
        let c = client_for(None, "t", Duration::from_secs(5)).unwrap();
        let resp = c.get(&url).send().await.expect("first contact");
        assert_eq!(resp.status(), 200);
        assert_eq!(observed_fingerprint(&resp).as_deref(), Some(fp.as_str()));

        // Correct pin: OK.
        let c = client_for(Some(&fp), "t", Duration::from_secs(5)).unwrap();
        assert_eq!(c.get(&url).send().await.expect("pinned").status(), 200);

        // Wrong pin: handshake refused.
        let wrong = "00".repeat(32);
        let c = client_for(Some(&wrong), "t", Duration::from_secs(5)).unwrap();
        let err = c.get(&url).send().await.expect_err("mismatch must fail");
        assert!(err.is_connect() || err.is_request(), "{err}");
    }

    #[test]
    fn clients_build_for_both_modes() {
        assert!(client_for(None, "x", Duration::from_secs(1)).is_ok());
        let r = client_for(Some(&"ab".repeat(32)), "x", Duration::from_secs(1));
        assert!(r.is_ok(), "{:?}", r.err());
    }
}
