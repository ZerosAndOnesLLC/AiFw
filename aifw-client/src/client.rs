//! The API client: base URL + pinned HTTP client + credential.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use reqwest::{Method, StatusCode};
use serde_json::Value;
use tokio::sync::Mutex;
use url::Url;

use crate::auth::{Auth, Session, SessionStore, TokenPair};
use crate::error::{ClientError, Result};
use crate::tls;

/// Path prefix every API route lives under.
const API_PREFIX: &str = "/api/v1";

/// Default per-request timeout. Slow synchronous endpoints (installs,
/// renewals) pass their own via [`Client::request_with_timeout`].
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// How the server certificate is trusted.
#[derive(Debug, Clone, Default)]
enum Trust {
    /// Plain http:// — nothing to verify.
    #[default]
    Default,
    /// Accept exactly this leaf (SHA-256 hex).
    Pin(String),
    /// Pin to the certificate in this PEM file (the API's own cert on-box).
    PinFile(PathBuf),
    /// Accept any certificate but record it (trust-on-first-use probe).
    AcceptAny,
}

/// Builder for [`Client`].
#[derive(Default)]
pub struct ClientBuilder {
    base: String,
    trust: Trust,
    timeout: Option<Duration>,
    auth: Auth,
    store: Option<Arc<dyn SessionStore>>,
    label: String,
}

impl ClientBuilder {
    /// Pin the server's leaf certificate (SHA-256 hex, `:` separators allowed).
    pub fn pin(mut self, fp: impl Into<String>) -> Self {
        let fp: String = fp.into();
        self.trust = Trust::Pin(fp.replace(':', "").to_ascii_lowercase());
        self
    }

    /// Pin to the certificate in a PEM file (on-box: the API's own cert).
    pub fn pin_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.trust = Trust::PinFile(path.into());
        self
    }

    /// Accept any certificate (only for a first-contact fingerprint probe).
    pub fn accept_any_cert(mut self) -> Self {
        self.trust = Trust::AcceptAny;
        self
    }

    pub fn timeout(mut self, t: Duration) -> Self {
        self.timeout = Some(t);
        self
    }

    pub fn auth(mut self, auth: Auth) -> Self {
        self.auth = auth;
        self
    }

    /// Where refreshed session tokens are saved.
    pub fn session_store(mut self, store: Arc<dyn SessionStore>) -> Self {
        self.store = Some(store);
        self
    }

    /// Name used in TLS pin-mismatch logs (e.g. the context name).
    pub fn label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self
    }

    pub fn build(self) -> Result<Client> {
        let base = Url::parse(self.base.trim_end_matches('/'))
            .map_err(|e| ClientError::Local(format!("invalid API URL '{}': {e}", self.base)))?;
        if !matches!(base.scheme(), "http" | "https") {
            return Err(ClientError::Local(format!(
                "invalid API URL '{base}': scheme must be http or https"
            )));
        }
        let label = if self.label.is_empty() {
            base.host_str().unwrap_or("aifw").to_string()
        } else {
            self.label
        };
        let builder = if base.scheme() == "http" {
            reqwest::Client::builder()
        } else {
            let pin = match &self.trust {
                Trust::Pin(fp) => Some(fp.clone()),
                Trust::PinFile(p) => match tls::fingerprint_pem_file(p) {
                    Some(fp) => Some(fp),
                    None => {
                        tracing::warn!(
                            path = %p.display(),
                            "API certificate not readable — not pinning this connection"
                        );
                        None
                    }
                },
                Trust::AcceptAny | Trust::Default => None,
            };
            if pin.is_none() && matches!(self.trust, Trust::Default) {
                // https with no pin configured: use normal WebPKI validation
                // (e.g. an ACME certificate on a proper hostname).
                reqwest::Client::builder().tls_info(true)
            } else {
                tls::client_builder_for(pin.as_deref(), &label)
                    .map_err(|e| ClientError::Local(e.to_string()))?
            }
        };
        let http = builder
            .connect_timeout(Duration::from_secs(10))
            .timeout(self.timeout.unwrap_or(DEFAULT_TIMEOUT))
            .user_agent(concat!("aifw-cli/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| ClientError::Local(format!("http client: {e}")))?;
        Ok(Client {
            base,
            http,
            auth: Mutex::new(self.auth),
            store: self.store,
        })
    }
}

/// Result of `POST /auth/login`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginOutcome {
    Tokens(TokenPair),
    /// Password accepted; a TOTP or recovery code is required next.
    TotpRequired,
}

/// One file part of a multipart upload.
pub struct UploadFile {
    pub field: String,
    pub file_name: String,
    pub bytes: Vec<u8>,
}

/// A multipart upload: one or more files plus text fields.
pub struct Upload {
    pub files: Vec<UploadFile>,
    pub fields: Vec<(String, String)>,
}

/// Request body.
#[derive(Clone)]
enum Body {
    None,
    Json(Value),
}

/// Async client for `/api/v1`.
pub struct Client {
    base: Url,
    http: reqwest::Client,
    auth: Mutex<Auth>,
    store: Option<Arc<dyn SessionStore>>,
}

impl Client {
    /// Start building a client for `base` (e.g. `https://fw.example:8080`).
    pub fn builder(base: impl Into<String>) -> ClientBuilder {
        ClientBuilder {
            base: base.into(),
            ..Default::default()
        }
    }

    pub fn base(&self) -> &Url {
        &self.base
    }

    /// Full URL for an API path (`/rules` → `<base>/api/v1/rules`). Paths
    /// already starting with `/api/` are used as-is.
    pub fn url(&self, path: &str) -> String {
        let base = self.base.as_str().trim_end_matches('/');
        if path.starts_with("/api/") {
            format!("{base}{path}")
        } else if path.starts_with('/') {
            format!("{base}{API_PREFIX}{path}")
        } else {
            format!("{base}{API_PREFIX}/{path}")
        }
    }

    /// Kind of credential in use (`none`, `api-key`, `bearer`, `session`).
    pub async fn auth_kind(&self) -> &'static str {
        self.auth.lock().await.kind()
    }

    /// Replace the credential (after login).
    pub async fn set_auth(&self, auth: Auth) {
        *self.auth.lock().await = auth;
    }

    // ---------------------------------------------------------------
    // JSON verbs
    // ---------------------------------------------------------------

    pub async fn get(&self, path: &str) -> Result<Value> {
        self.json(Method::GET, path, Body::None, None).await
    }

    pub async fn post(&self, path: &str, body: &Value) -> Result<Value> {
        self.json(Method::POST, path, Body::Json(body.clone()), None)
            .await
    }

    /// POST with no body.
    pub async fn post_empty(&self, path: &str) -> Result<Value> {
        self.json(Method::POST, path, Body::None, None).await
    }

    pub async fn put(&self, path: &str, body: &Value) -> Result<Value> {
        self.json(Method::PUT, path, Body::Json(body.clone()), None)
            .await
    }

    pub async fn patch(&self, path: &str, body: &Value) -> Result<Value> {
        self.json(Method::PATCH, path, Body::Json(body.clone()), None)
            .await
    }

    pub async fn delete(&self, path: &str) -> Result<Value> {
        self.json(Method::DELETE, path, Body::None, None).await
    }

    /// Any verb, optional JSON body, explicit timeout (slow endpoints).
    pub async fn request_with_timeout(
        &self,
        method: Method,
        path: &str,
        body: Option<&Value>,
        timeout: Duration,
    ) -> Result<Value> {
        let body = body.map_or(Body::None, |b| Body::Json(b.clone()));
        self.json(method, path, body, Some(timeout)).await
    }

    /// GET a non-JSON body (PEM, YAML, config downloads) as bytes.
    pub async fn get_bytes(&self, path: &str) -> Result<Vec<u8>> {
        let resp = self.send(Method::GET, path, Body::None, None).await?;
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| ClientError::Decode(format!("reading body: {e}")))?;
        Ok(bytes.to_vec())
    }

    /// POST with a JSON body, returning the raw response bytes (encrypted
    /// config export).
    pub async fn post_for_bytes(&self, path: &str, body: &Value) -> Result<Vec<u8>> {
        let resp = self
            .send(Method::POST, path, Body::Json(body.clone()), None)
            .await?;
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| ClientError::Decode(format!("reading body: {e}")))?;
        Ok(bytes.to_vec())
    }

    /// Multipart upload. Not retried on 401 (the body is consumed), so the
    /// session is refreshed pre-emptively instead.
    pub async fn upload(&self, path: &str, upload: Upload, timeout: Duration) -> Result<Value> {
        self.refresh_if_due().await?;
        let url = self.url(path);
        let mut form = reqwest::multipart::Form::new();
        for (k, v) in upload.fields {
            form = form.text(k, v);
        }
        for f in upload.files {
            form = form.part(
                f.field,
                reqwest::multipart::Part::bytes(f.bytes).file_name(f.file_name),
            );
        }
        let mut req = self.http.post(&url).multipart(form).timeout(timeout);
        if let Some(h) = self.auth.lock().await.header() {
            req = req.header(reqwest::header::AUTHORIZATION, h);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ClientError::from_transport(&url, &e))?;
        let resp = check(resp, &format!("POST {path}")).await?;
        decode_json(resp).await
    }

    /// Open a streaming GET (Server-Sent Events). Returns the response so
    /// the caller can read `bytes_stream()`; the request has no timeout.
    pub async fn stream(&self, path: &str) -> Result<reqwest::Response> {
        self.refresh_if_due().await?;
        let url = self.url(path);
        let mut req = self
            .http
            .get(&url)
            .header(reqwest::header::ACCEPT, "text/event-stream")
            .timeout(Duration::from_secs(60 * 60 * 24 * 365));
        if let Some(h) = self.auth.lock().await.header() {
            req = req.header(reqwest::header::AUTHORIZATION, h);
        }
        let resp = req
            .send()
            .await
            .map_err(|e| ClientError::from_transport(&url, &e))?;
        check(resp, &format!("GET {path}")).await
    }

    // ---------------------------------------------------------------
    // Login / session
    // ---------------------------------------------------------------

    /// Step 1 of login. Does not change this client's credential.
    pub async fn login(&self, username: &str, password: &str) -> Result<LoginOutcome> {
        let v = self
            .unauthenticated(
                "/auth/login",
                &serde_json::json!({ "username": username, "password": password }),
            )
            .await?;
        if v.get("totp_required").and_then(Value::as_bool) == Some(true) {
            return Ok(LoginOutcome::TotpRequired);
        }
        let tokens = v
            .get("tokens")
            .cloned()
            .ok_or_else(|| ClientError::Decode("login response had no tokens".into()))?;
        Ok(LoginOutcome::Tokens(
            serde_json::from_value(tokens)
                .map_err(|e| ClientError::Decode(format!("login tokens: {e}")))?,
        ))
    }

    /// Step 2 of login when TOTP is required (`code` may be a recovery code).
    pub async fn totp_login(
        &self,
        username: &str,
        password: &str,
        code: &str,
    ) -> Result<TokenPair> {
        let v = self
            .unauthenticated(
                "/auth/totp/login",
                &serde_json::json!({ "username": username, "password": password, "totp_code": code }),
            )
            .await?;
        serde_json::from_value(v).map_err(|e| ClientError::Decode(format!("totp tokens: {e}")))
    }

    /// Revoke the current session server-side (best effort for API keys:
    /// there is nothing to revoke, so this is a no-op).
    pub async fn logout(&self) -> Result<()> {
        let refresh = match &*self.auth.lock().await {
            Auth::Session(s) => Some(s.refresh_token.clone()),
            Auth::Bearer(_) => None,
            Auth::ApiKey(_) | Auth::None => return Ok(()),
        };
        let body = refresh.map_or(Value::Null, |r| serde_json::json!({ "refresh_token": r }));
        let body = if body.is_null() {
            Body::None
        } else {
            Body::Json(body)
        };
        self.json(Method::POST, "/auth/logout", body, None)
            .await
            .map(|_| ())
    }

    /// Fingerprint of the certificate the server presents (TLS only). Uses
    /// a public endpoint, so it works before any credential exists. Build
    /// the client with [`ClientBuilder::accept_any_cert`] for a first probe.
    pub async fn probe_fingerprint(&self) -> Result<Option<String>> {
        let url = self.url("/auth/oauth/login-options");
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| ClientError::from_transport(&url, &e))?;
        Ok(tls::observed_fingerprint(&resp))
    }

    // ---------------------------------------------------------------
    // Internals
    // ---------------------------------------------------------------

    async fn unauthenticated(&self, path: &str, body: &Value) -> Result<Value> {
        let url = self.url(path);
        let resp = self
            .http
            .post(&url)
            .json(body)
            .send()
            .await
            .map_err(|e| ClientError::from_transport(&url, &e))?;
        let resp = check(resp, &format!("POST {path}")).await?;
        decode_json(resp).await
    }

    async fn json(
        &self,
        method: Method,
        path: &str,
        body: Body,
        timeout: Option<Duration>,
    ) -> Result<Value> {
        let resp = self.send(method, path, body, timeout).await?;
        decode_json(resp).await
    }

    /// Send with auth; refresh a session before expiry and once on 401.
    async fn send(
        &self,
        method: Method,
        path: &str,
        body: Body,
        timeout: Option<Duration>,
    ) -> Result<reqwest::Response> {
        self.refresh_if_due().await?;
        let resp = self.send_once(&method, path, &body, timeout).await?;
        if resp.status() == StatusCode::UNAUTHORIZED && self.is_session().await {
            self.refresh().await?;
            let resp = self.send_once(&method, path, &body, timeout).await?;
            return check(resp, &format!("{method} {path}")).await;
        }
        check(resp, &format!("{method} {path}")).await
    }

    async fn send_once(
        &self,
        method: &Method,
        path: &str,
        body: &Body,
        timeout: Option<Duration>,
    ) -> Result<reqwest::Response> {
        let url = self.url(path);
        let mut req = self.http.request(method.clone(), &url);
        if let Some(t) = timeout {
            req = req.timeout(t);
        }
        if let Some(h) = self.auth.lock().await.header() {
            req = req.header(reqwest::header::AUTHORIZATION, h);
        }
        if let Body::Json(v) = body {
            req = req.json(v);
        }
        req.send()
            .await
            .map_err(|e| ClientError::from_transport(&url, &e))
    }

    async fn is_session(&self) -> bool {
        matches!(&*self.auth.lock().await, Auth::Session(_))
    }

    async fn refresh_if_due(&self) -> Result<()> {
        let due = match &*self.auth.lock().await {
            Auth::Session(s) => s.needs_refresh(chrono::Utc::now()),
            _ => false,
        };
        if due { self.refresh().await } else { Ok(()) }
    }

    /// Rotate the session's tokens and persist the new pair before using it.
    pub async fn refresh(&self) -> Result<()> {
        let mut guard = self.auth.lock().await;
        let Auth::Session(s) = &*guard else {
            return Ok(());
        };
        let url = self.url("/auth/refresh");
        let resp = self
            .http
            .post(&url)
            .json(&serde_json::json!({ "refresh_token": s.refresh_token }))
            .send()
            .await
            .map_err(|e| ClientError::from_transport(&url, &e))?;
        if resp.status() == StatusCode::UNAUTHORIZED || resp.status() == StatusCode::BAD_REQUEST {
            return Err(ClientError::Unauthorized(
                "session expired or was revoked".into(),
            ));
        }
        let resp = check(resp, "POST /auth/refresh").await?;
        let pair: TokenPair = serde_json::from_value(decode_json(resp).await?)
            .map_err(|e| ClientError::Decode(format!("refresh tokens: {e}")))?;
        if let Some(store) = &self.store {
            store
                .save(&pair)
                .map_err(|e| ClientError::Local(format!("saving refreshed session: {e}")))?;
        }
        *guard = Auth::Session(Session::from_tokens(&pair));
        Ok(())
    }
}

/// Turn a non-2xx response into a [`ClientError`].
async fn check(resp: reqwest::Response, what: &str) -> Result<reqwest::Response> {
    if resp.status().is_success() {
        return Ok(resp);
    }
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    Err(ClientError::from_status(status, &body, what))
}

/// Decode a JSON body; an empty body is `Value::Null`.
async fn decode_json(resp: reqwest::Response) -> Result<Value> {
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| ClientError::Decode(format!("reading body: {e}")))?;
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Null);
    }
    serde_json::from_slice(&bytes).map_err(|e| ClientError::Decode(format!("invalid JSON: {e}")))
}

#[cfg(test)]
#[path = "client_tests.rs"]
mod tests;
