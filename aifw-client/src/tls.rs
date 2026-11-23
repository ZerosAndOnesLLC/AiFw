//! TLS trust for AiFw HTTPS calls (#317 / SEC-L2): cluster peers, the
//! daemon's loopback calls, and the `aifw` CLI.
//!
//! Lives in `aifw-client` (CLI v2) so the CLI can pin without pulling in
//! `aifw-core`; `aifw_core::peer_tls` re-exports it unchanged.
//!
//! Cluster peers and the daemon's loopback calls used to accept any
//! certificate (`danger_accept_invalid_certs`) — the peer API key was the
//! only thing standing between an on-path attacker and the replication
//! stream (which carries the whole config, secrets included). Calls now
//! pin the leaf certificate by SHA-256 fingerprint:
//!
//! * **Peers** — the pin lives in `cluster_nodes.cert_fingerprint`. With no
//!   pin yet, the peer must first prove its certificate with the shared peer
//!   key ([`prove_peer_certificate`], #731): no credential is sent until it
//!   has, so first contact is not a trust-on-first-use window. The pin is
//!   enforced from then on. A cert push (`cluster/cert-push`) clears the
//!   affected pin so it is proven again, and an operator can clear or set a
//!   pin (`POST /cluster/nodes/{id}/repin`, `aifw cluster nodes repin`).
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

// ============================================================
// Certificate proof for first contact (#731)
// ============================================================

/// Public endpoint a peer answers to prove its certificate.
pub const PIN_PROOF_PATH: &str = "/api/v1/cluster/pin-proof";

/// Domain label mixed into the proof MAC so it can't be confused with any
/// other use of the peer key.
const PIN_PROOF_LABEL: &[u8] = b"aifw-pin-proof-v1";

/// Request body for [`PIN_PROOF_PATH`]: a fresh random nonce (64 hex chars).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PinProofRequest {
    pub nonce: String,
}

/// Response from [`PIN_PROOF_PATH`]: the fingerprint of the certificate the
/// peer serves, and `HMAC-SHA256(peer key, label ‖ nonce ‖ fingerprint)`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PinProof {
    pub fingerprint: String,
    pub mac: String,
}

/// A nonce is exactly 32 bytes, hex-encoded.
pub fn is_valid_nonce(nonce: &str) -> bool {
    nonce.len() == 64 && nonce.bytes().all(|b| b.is_ascii_hexdigit())
}

fn pin_proof_hmac(peer_key: &str, nonce: &str, fingerprint: &str) -> hmac::Hmac<Sha256> {
    use hmac::{KeyInit, Mac};
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(peer_key.as_bytes())
        .expect("HMAC accepts keys of any length");
    mac.update(PIN_PROOF_LABEL);
    mac.update(b"\0");
    mac.update(nonce.to_ascii_lowercase().as_bytes());
    mac.update(b"\0");
    mac.update(fingerprint.to_ascii_lowercase().as_bytes());
    mac
}

/// Proof MAC a node returns for `nonce` and its own certificate fingerprint.
pub fn pin_proof_mac(peer_key: &str, nonce: &str, fingerprint: &str) -> String {
    use hmac::Mac;
    hex::encode(
        pin_proof_hmac(peer_key, nonce, fingerprint)
            .finalize()
            .into_bytes(),
    )
}

/// Checks a peer's proof (constant-time): the MAC must have been made with
/// `peer_key` over `nonce` and `observed_fingerprint` — the certificate this
/// client actually saw on the connection, not the one the body claims.
pub fn verify_pin_proof(
    peer_key: &str,
    nonce: &str,
    observed_fingerprint: &str,
    proof: &PinProof,
) -> bool {
    use hmac::Mac;
    if !proof.fingerprint.eq_ignore_ascii_case(observed_fingerprint) {
        return false;
    }
    let Ok(mac) = hex::decode(&proof.mac) else {
        return false;
    };
    pin_proof_hmac(peer_key, nonce, observed_fingerprint)
        .verify_slice(&mac)
        .is_ok()
}

/// Fresh random nonce for a proof request (32 bytes, hex).
pub fn new_nonce() -> Result<String, TlsError> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b)
        .map_err(|e| TlsError(format!("pin proof: OS CSPRNG unavailable: {e}")))?;
    Ok(hex::encode(b))
}

/// First contact with a peer that has no pin yet (#731). Asks the peer at
/// `base_url` to prove its certificate and returns the fingerprint to pin.
///
/// The request carries only a random nonce — never the peer key or any
/// other credential — so an on-path interceptor learns nothing. The peer
/// answers `HMAC(peer key, nonce ‖ fingerprint)`; the fingerprint is
/// checked against the certificate actually seen on this connection, so a
/// relay presenting its own certificate fails even if it forwards the
/// real peer's answer. Without a valid proof nothing is pinned: callers
/// fail closed instead of trusting the first certificate they see.
pub async fn prove_peer_certificate(
    base_url: &str,
    peer_key: &str,
    label: &str,
    timeout: Duration,
) -> Result<String, TlsError> {
    let nonce = new_nonce()?;
    let url = format!("{}{PIN_PROOF_PATH}", base_url.trim_end_matches('/'));
    let resp = client_for(None, label, timeout)?
        .post(&url)
        .json(&PinProofRequest {
            nonce: nonce.clone(),
        })
        .send()
        .await
        .map_err(|e| TlsError(format!("pin proof: {label}: {e}")))?;
    let observed = observed_fingerprint(&resp)
        .ok_or_else(|| TlsError(format!("pin proof: {label} presented no certificate")))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(TlsError(format!(
            "pin proof: {label} answered {status} and can't prove its certificate — re-register this node's peer key on it (or update it), or set the pin by hand"
        )));
    }
    let proof: PinProof = resp
        .json()
        .await
        .map_err(|e| TlsError(format!("pin proof: {label}: bad response: {e}")))?;
    if !verify_pin_proof(peer_key, &nonce, &observed, &proof) {
        return Err(TlsError(format!(
            "pin proof: {label} presented certificate {} but did not prove it with the peer key — not pinning",
            short(&observed)
        )));
    }
    Ok(observed)
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
    /// When set, a certificate that doesn't match the pin is still accepted
    /// if it validates against the public web PKI for the server name — so
    /// an ACME renewal on a properly named appliance doesn't break the CLI.
    /// Never set for cluster peers (addressed by IP, mostly self-signed).
    public_ca: Option<Arc<dyn ServerCertVerifier>>,
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
        if let Some(ca) = &self.public_ca
            && ca
                .verify_server_cert(end_entity, _intermediates, _server_name, _ocsp, _now)
                .is_ok()
        {
            debug!(peer = %self.label, "pin changed but the certificate is publicly trusted for this name");
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
/// * `pin = None` — any certificate is accepted and the response carries
///   `TlsInfo` ([`observed_fingerprint`]). Never send a credential over such
///   a client: it is for [`prove_peer_certificate`], the CLI's fingerprint
///   probe (which asks the user to confirm), and the loopback fallback.
pub fn client_for(
    pin: Option<&str>,
    label: &str,
    timeout: Duration,
) -> Result<reqwest::Client, TlsError> {
    client_builder_for(pin, label)?
        .timeout(timeout)
        .build()
        .map_err(|e| TlsError(format!("peer_tls: http client: {e}")))
}

/// Error building a pinned TLS client.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct TlsError(pub String);

/// Like [`client_for`] but returns the builder so callers can add their own
/// settings (timeouts, connect timeouts, default headers) before building.
pub fn client_builder_for(
    pin: Option<&str>,
    label: &str,
) -> Result<reqwest::ClientBuilder, TlsError> {
    let build = |b: reqwest::ClientBuilder| Ok(b.tls_info(true));
    match pin {
        Some(fp) => {
            let verifier = Arc::new(PinnedCert {
                expected: fp.to_ascii_lowercase(),
                label: label.to_string(),
                provider: provider(),
                public_ca: None,
            });
            let cfg = rustls::ClientConfig::builder_with_provider(provider())
                .with_safe_default_protocol_versions()
                .map_err(|e| TlsError(format!("peer_tls: rustls config: {e}")))?
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth();
            build(reqwest::Client::builder().tls_backend_preconfigured(cfg))
        }
        None => {
            debug!(
                peer = label,
                "peer_tls: unpinned client (certificate proof / fingerprint probe)"
            );
            build(reqwest::Client::builder().danger_accept_invalid_certs(true))
        }
    }
}

/// Like [`client_builder_for`] with a pin, but a certificate that no longer
/// matches the pin is also accepted when it is publicly trusted (web PKI)
/// for the server's name. For the CLI's saved contexts: a self-signed
/// appliance stays pinned, and an appliance with a Let's Encrypt
/// certificate keeps working across renewals.
pub fn client_builder_pinned_or_public(
    pin: &str,
    label: &str,
) -> Result<reqwest::ClientBuilder, TlsError> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let public =
        rustls::client::WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider())
            .build()
            .map_err(|e| TlsError(format!("peer_tls: web PKI verifier: {e}")))?;
    let verifier = Arc::new(PinnedCert {
        expected: pin.to_ascii_lowercase(),
        label: label.to_string(),
        provider: provider(),
        public_ca: Some(public),
    });
    let cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| TlsError(format!("peer_tls: rustls config: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    Ok(reqwest::Client::builder()
        .tls_backend_preconfigured(cfg)
        .tls_info(true))
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
    pub fn get(&self) -> Result<reqwest::Client, TlsError> {
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
            public_ca: None,
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
    fn pin_proof_round_trip() {
        let key = "k".repeat(64);
        let nonce = new_nonce().unwrap();
        assert!(is_valid_nonce(&nonce));
        let fp = "ab".repeat(32);
        let proof = PinProof {
            fingerprint: fp.clone(),
            mac: pin_proof_mac(&key, &nonce, &fp),
        };
        assert!(verify_pin_proof(&key, &nonce, &fp, &proof));
        // Fingerprint compare is case-insensitive (pins are stored lowercase).
        assert!(verify_pin_proof(&key, &nonce, &fp.to_uppercase(), &proof));
    }

    #[test]
    fn pin_proof_rejects_wrong_inputs() {
        let key = "k".repeat(64);
        let nonce = new_nonce().unwrap();
        let fp = "ab".repeat(32);
        let good = PinProof {
            fingerprint: fp.clone(),
            mac: pin_proof_mac(&key, &nonce, &fp),
        };
        // Wrong key, wrong nonce (replay), garbage MAC.
        assert!(!verify_pin_proof(&"x".repeat(64), &nonce, &fp, &good));
        assert!(!verify_pin_proof(&key, &new_nonce().unwrap(), &fp, &good));
        let garbage = PinProof {
            mac: "zz".into(),
            ..good.clone()
        };
        assert!(!verify_pin_proof(&key, &nonce, &fp, &garbage));
        // A relay with its own certificate: the real peer's proof names the
        // real fingerprint, which doesn't match what the client observed.
        let relay_fp = "cd".repeat(32);
        assert!(!verify_pin_proof(&key, &nonce, &relay_fp, &good));
        // Lying about the fingerprint in the body without the key.
        let lie = PinProof {
            fingerprint: relay_fp.clone(),
            mac: good.mac.clone(),
        };
        assert!(!verify_pin_proof(&key, &nonce, &relay_fp, &lie));
    }

    #[test]
    fn nonce_shape() {
        assert!(is_valid_nonce(&"0a".repeat(32)));
        assert!(!is_valid_nonce(&"0a".repeat(31)));
        assert!(!is_valid_nonce(&"zz".repeat(32)));
        assert_ne!(new_nonce().unwrap(), new_nonce().unwrap());
    }

    /// HTTPS server answering the pin-proof endpoint like a real node:
    /// proves its certificate with `key` (or, with `key = None`, answers
    /// 404 like a peer without a stored key / an older version).
    async fn proof_server(key: Option<String>) -> (u16, String) {
        use axum::{Json, Router, routing::post};
        let rk = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
            .unwrap()
            .self_signed(&rk)
            .unwrap();
        let fp = fingerprint_der(cert.der());
        let cfg = rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                rustls::pki_types::PrivateKeyDer::try_from(rk.serialize_der()).unwrap(),
            )
            .unwrap();
        let served = fp.clone();
        let app = Router::new().route(
            PIN_PROOF_PATH,
            post(move |Json(r): Json<PinProofRequest>| {
                let key = key.clone();
                let fp = served.clone();
                async move {
                    match key {
                        Some(k) => Ok(Json(PinProof {
                            mac: pin_proof_mac(&k, &r.nonce, &fp),
                            fingerprint: fp,
                        })),
                        None => Err(axum::http::StatusCode::NOT_FOUND),
                    }
                }
            }),
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let tls = axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(cfg));
        let server = axum_server::tls_rustls::from_tcp_rustls(listener, tls).unwrap();
        tokio::spawn(async move {
            let _ = server.serve(app.into_make_service()).await;
        });
        (port, fp)
    }

    #[tokio::test]
    async fn prove_peer_certificate_pins_only_a_proven_cert() {
        let key = "k".repeat(64);
        let (port, fp) = proof_server(Some(key.clone())).await;
        let base = format!("https://127.0.0.1:{port}");
        let got = prove_peer_certificate(&base, &key, "t", Duration::from_secs(5))
            .await
            .expect("valid proof");
        assert_eq!(got, fp);

        // Same server, but we hold a different key: an impostor can't prove.
        let err = prove_peer_certificate(&base, &"x".repeat(64), "t", Duration::from_secs(5))
            .await
            .expect_err("wrong key must not pin");
        assert!(err.0.contains("did not prove"), "{err}");
    }

    #[tokio::test]
    async fn prove_peer_certificate_fails_closed_without_proof() {
        let (port, _fp) = proof_server(None).await;
        let base = format!("https://127.0.0.1:{port}");
        let err = prove_peer_certificate(&base, &"k".repeat(64), "t", Duration::from_secs(5))
            .await
            .expect_err("no proof must not pin");
        assert!(err.0.contains("can't prove"), "{err}");
    }

    #[test]
    fn clients_build_for_both_modes() {
        assert!(client_for(None, "x", Duration::from_secs(1)).is_ok());
        let r = client_for(Some(&"ab".repeat(32)), "x", Duration::from_secs(1));
        assert!(r.is_ok(), "{:?}", r.err());
    }
}
