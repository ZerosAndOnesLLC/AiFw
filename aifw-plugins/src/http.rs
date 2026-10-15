//! Outbound HTTP for plugins. Every request goes through
//! [`check_destination`] (SSRF guard), which resolves the host once and
//! pins the connection to the addresses it checked, so a DNS answer can't
//! change between check and connect. Redirects are never followed by
//! reqwest: [`Client`] follows them itself, re-checking every hop, and
//! refuses them outright for POST (a webhook that moves should be
//! reconfigured, not silently re-targeted). Response bodies are size-capped
//! while streaming so a hostile or broken server can't exhaust memory.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use crate::error::{PluginError, Result};

const MAX_REDIRECTS: usize = 3;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// User agent sent by plugin requests.
pub fn user_agent(plugin: &str) -> String {
    format!("AiFw/{} ({plugin})", env!("CARGO_PKG_VERSION"))
}

/// Refuse destinations a plugin must not reach, and return the addresses
/// the host resolved to so the caller can pin the connection to them
/// (empty when the host is an IP literal).
///
/// By default only https URLs resolving to public addresses are allowed;
/// `allow_private` (an explicit operator opt-in, e.g. a self-hosted ntfy
/// on the LAN) permits http and private addresses but still refuses
/// non-http schemes.
pub async fn check_destination(url: &str, allow_private: bool) -> Result<Vec<SocketAddr>> {
    let refuse = |why: String| PluginError::Validation(format!("{url}: {why}"));
    let parsed = url::Url::parse(url).map_err(|e| refuse(format!("invalid URL: {e}")))?;
    match parsed.scheme() {
        "https" => {}
        "http" if allow_private => {}
        "http" => return Err(refuse("only https:// URLs are allowed".into())),
        other => return Err(refuse(format!("scheme '{other}' is not allowed"))),
    }
    let host = parsed
        .host_str()
        .ok_or_else(|| refuse("URL has no host".into()))?;
    let bare = host.trim_matches(['[', ']']);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        if !allow_private && !aifw_common::net_safety::is_public(ip) {
            return Err(refuse(format!("{ip} is not a public address")));
        }
        return Ok(Vec::new());
    }
    let port = parsed.port_or_known_default().unwrap_or(443);
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((bare, port))
        .await
        .map_err(|e| refuse(format!("DNS lookup {bare}: {e}")))?
        .collect();
    if addrs.is_empty() {
        return Err(refuse(format!("{bare} did not resolve")));
    }
    if !allow_private
        && let Some(bad) = addrs
            .iter()
            .find(|a| !aifw_common::net_safety::is_public(a.ip()))
    {
        return Err(refuse(format!(
            "{bare} resolves to {}, which is not a public address",
            bad.ip()
        )));
    }
    Ok(addrs)
}

/// Error text safe to show: never echoes the URL, since webhook URLs and
/// bot tokens are secrets.
pub fn redact(e: reqwest::Error) -> String {
    if e.is_timeout() {
        "timed out".into()
    } else if e.is_connect() {
        "could not connect".into()
    } else {
        e.without_url().to_string()
    }
}

/// Result of a conditional GET.
#[derive(Debug)]
pub enum Fetched {
    /// Server answered 304 to our `If-None-Match`
    NotModified,
    /// New content
    Body {
        /// Response body (lossy UTF-8)
        text: String,
        /// `ETag` to send next time
        etag: Option<String>,
    },
}

/// HTTP client for plugin use. Cheap to clone; a connection is built per
/// request so it can be pinned to the checked addresses.
#[derive(Debug, Clone)]
pub struct Client {
    plugin: String,
    timeout: Duration,
    allow_private: bool,
}

impl Client {
    /// Client for `plugin`. `allow_private` is the operator's opt-in for
    /// LAN / http destinations.
    pub fn new(plugin: &str, timeout: Duration, allow_private: bool) -> Self {
        Self {
            plugin: plugin.to_string(),
            timeout,
            allow_private,
        }
    }

    /// The same client restricted to public https destinations, for
    /// services that are always on the public internet (Telegram's Bot
    /// API) even when the operator allowed LAN destinations elsewhere.
    pub fn public_only(&self) -> Self {
        Self {
            allow_private: false,
            ..self.clone()
        }
    }

    /// Whether private / http destinations are allowed.
    pub fn allows_private(&self) -> bool {
        self.allow_private
    }

    /// Conditional GET of `url`, following at most three redirects (each
    /// re-checked), failing if the body exceeds `max_bytes`.
    pub async fn get_text(
        &self,
        url: &str,
        etag: Option<&str>,
        max_bytes: usize,
    ) -> Result<Fetched> {
        let etag = etag.map(str::to_string);
        let mut resp = self
            .send(reqwest::Method::GET, url, move |req| match &etag {
                Some(tag) => req.header(reqwest::header::IF_NONE_MATCH, tag),
                None => req,
            })
            .await?;
        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(Fetched::NotModified);
        }
        if !resp.status().is_success() {
            return Err(PluginError::Plugin(format!("HTTP {}", resp.status())));
        }
        let too_large = || {
            PluginError::Plugin(format!(
                "response larger than {} MB",
                max_bytes / (1024 * 1024)
            ))
        };
        if resp
            .content_length()
            .is_some_and(|len| len > max_bytes as u64)
        {
            return Err(too_large());
        }
        let etag = resp
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let mut body: Vec<u8> = Vec::new();
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| PluginError::Plugin(format!("reading response: {}", redact(e))))?
        {
            if body.len() + chunk.len() > max_bytes {
                return Err(too_large());
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Fetched::Body {
            text: String::from_utf8_lossy(&body).into_owned(),
            etag,
        })
    }

    /// POST `body` to `url`. Redirects are refused. The response is
    /// returned whatever its status; the caller decides about retries.
    pub async fn post(
        &self,
        url: &str,
        headers: &[(String, String)],
        content_type: &'static str,
        body: String,
    ) -> Result<reqwest::Response> {
        let headers = headers.to_vec();
        self.send(reqwest::Method::POST, url, move |mut req| {
            req = req
                .header(reqwest::header::CONTENT_TYPE, content_type)
                .body(body.clone());
            for (k, v) in &headers {
                req = req.header(k, v);
            }
            req
        })
        .await
    }

    async fn send(
        &self,
        method: reqwest::Method,
        url: &str,
        build: impl Fn(reqwest::RequestBuilder) -> reqwest::RequestBuilder,
    ) -> Result<reqwest::Response> {
        let mut url = url.to_string();
        for hop in 0..=MAX_REDIRECTS {
            let addrs = check_destination(&url, self.allow_private).await?;
            let parsed = url::Url::parse(&url)
                .map_err(|e| PluginError::Validation(format!("invalid URL: {e}")))?;
            let mut builder = reqwest::Client::builder()
                .timeout(self.timeout)
                .connect_timeout(CONNECT_TIMEOUT)
                .user_agent(user_agent(&self.plugin))
                .redirect(reqwest::redirect::Policy::none());
            if let Some(host) = parsed.host_str()
                && !addrs.is_empty()
            {
                builder = builder.resolve_to_addrs(host, &addrs);
            }
            let client = builder
                .build()
                .map_err(|e| PluginError::Plugin(format!("http client: {e}")))?;
            let resp = build(client.request(method.clone(), &url))
                .send()
                .await
                .map_err(|e| PluginError::Plugin(format!("request failed: {}", redact(e))))?;
            if !resp.status().is_redirection() || resp.status() == reqwest::StatusCode::NOT_MODIFIED
            {
                return Ok(resp);
            }
            if method != reqwest::Method::GET {
                return Err(PluginError::Plugin(
                    "endpoint redirected; use its final URL".into(),
                ));
            }
            if hop == MAX_REDIRECTS {
                return Err(PluginError::Plugin("too many redirects".into()));
            }
            let location = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| PluginError::Plugin("redirect without a Location".into()))?;
            let next = parsed
                .join(location)
                .map_err(|e| PluginError::Plugin(format!("bad redirect target: {e}")))?;
            if !self.allow_private && next.scheme() != "https" {
                return Err(PluginError::Plugin(
                    "redirect to a non-https URL refused".into(),
                ));
            }
            url = next.to_string();
        }
        Err(PluginError::Plugin("too many redirects".into()))
    }
}

/// A throwaway local HTTP/1.1 server for tests: answers each connection
/// with the next scripted reply and records what it received.
#[cfg(test)]
pub(crate) mod testing {
    use std::sync::Arc;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::sync::Mutex;

    /// One scripted response.
    #[derive(Debug, Clone)]
    pub(crate) struct Reply {
        pub status: u16,
        pub headers: Vec<(String, String)>,
        pub body: String,
    }

    impl Reply {
        pub(crate) fn status(status: u16) -> Self {
            Self {
                status,
                headers: Vec::new(),
                body: String::new(),
            }
        }

        pub(crate) fn body(status: u16, body: &str) -> Self {
            Self {
                status,
                headers: Vec::new(),
                body: body.to_string(),
            }
        }

        pub(crate) fn redirect(location: &str) -> Self {
            Self {
                status: 302,
                headers: vec![("Location".into(), location.into())],
                body: String::new(),
            }
        }

        pub(crate) fn header(mut self, k: &str, v: &str) -> Self {
            self.headers.push((k.into(), v.into()));
            self
        }
    }

    /// A bound server; `run` scripts its replies.
    pub(crate) struct TestServer {
        listener: tokio::net::TcpListener,
        base: String,
    }

    /// (request head, request body) pairs the server saw.
    pub(crate) type Seen = Arc<Mutex<Vec<(String, String)>>>;

    impl TestServer {
        pub(crate) async fn bind() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            Self { listener, base }
        }

        /// `http://127.0.0.1:<port>`
        pub(crate) fn url(&self, path: &str) -> String {
            format!("{}{path}", self.base)
        }

        pub(crate) fn run(self, replies: Vec<Reply>) -> Seen {
            let seen: Seen = Arc::new(Mutex::new(Vec::new()));
            let log = seen.clone();
            let listener = self.listener;
            tokio::spawn(async move {
                for reply in replies {
                    let (mut sock, _) = listener.accept().await.unwrap();
                    let mut buf = Vec::new();
                    let mut chunk = [0u8; 4096];
                    let (head, body) = loop {
                        let n = sock.read(&mut chunk).await.unwrap();
                        if n == 0 {
                            return;
                        }
                        buf.extend_from_slice(&chunk[..n]);
                        let text = String::from_utf8_lossy(&buf).to_string();
                        if let Some(i) = text.find("\r\n\r\n") {
                            let head = text[..i].to_string();
                            let len: usize = head
                                .lines()
                                .find_map(|l| {
                                    l.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .map(|v| v.trim().parse().unwrap())
                                })
                                .unwrap_or(0);
                            if buf.len() >= i + 4 + len {
                                break (head, text[i + 4..i + 4 + len].to_string());
                            }
                        }
                    };
                    log.lock().await.push((head, body));
                    let mut resp = format!("HTTP/1.1 {} X\r\n", reply.status);
                    for (k, v) in &reply.headers {
                        resp.push_str(&format!("{k}: {v}\r\n"));
                    }
                    resp.push_str(&format!(
                        "Content-Length: {}\r\nConnection: close\r\n\r\n{}",
                        reply.body.len(),
                        reply.body
                    ));
                    sock.write_all(resp.as_bytes()).await.unwrap();
                }
            });
            seen
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::{Reply, TestServer};
    use super::*;

    fn lan_client() -> Client {
        Client::new("test", Duration::from_secs(5), true)
    }

    #[tokio::test]
    async fn private_and_non_https_destinations_are_refused_by_default() {
        let public = Client::new("test", Duration::from_secs(5), false);
        // localhost resolves to a loopback address: refused after DNS.
        let err = check_destination("https://localhost/x", false)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a public address"), "{err}");
        assert!(
            check_destination("http://example.com/x", false)
                .await
                .is_err()
        );
        assert!(
            check_destination("ftp://example.com/x", true)
                .await
                .is_err()
        );
        assert!(
            check_destination("https://10.0.0.1/x", false)
                .await
                .is_err()
        );
        let srv = TestServer::bind().await;
        let url = srv.url("/x");
        let seen = srv.run(vec![Reply::body(200, "hi")]);
        assert!(public.get_text(&url, None, 1024).await.is_err());
        assert!(seen.lock().await.is_empty(), "nothing may be sent");
    }

    #[tokio::test]
    async fn opt_in_allows_lan_and_pins_resolved_addresses() {
        // "localhost" goes through DNS and is pinned to what it resolved to.
        let addrs = check_destination("http://localhost:8080/x", true)
            .await
            .unwrap();
        assert!(addrs.iter().all(|a| a.port() == 8080));
        assert!(!addrs.is_empty());
        // IP literals need no pinning.
        assert!(
            check_destination("http://127.0.0.1:8080/x", true)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn get_follows_checked_redirects_and_returns_body() {
        let srv = TestServer::bind().await;
        let first = srv.url("/first");
        let second = srv.url("/second");
        let seen = srv.run(vec![
            Reply::redirect(&second),
            Reply::body(200, "payload").header("ETag", "\"v1\""),
        ]);
        let Fetched::Body { text, etag } = lan_client().get_text(&first, None, 1024).await.unwrap()
        else {
            panic!("expected a body");
        };
        assert_eq!(text, "payload");
        assert_eq!(etag.as_deref(), Some("\"v1\""));
        let reqs = seen.lock().await;
        assert_eq!(reqs.len(), 2);
        assert!(reqs[1].0.starts_with("GET /second "), "{}", reqs[1].0);
    }

    #[tokio::test]
    async fn redirects_to_refused_destinations_stop_the_request() {
        let srv = TestServer::bind().await;
        let url = srv.url("/x");
        srv.run(vec![Reply::redirect("ftp://example.com/evil")]);
        let err = lan_client()
            .get_text(&url, None, 1024)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("not allowed"), "{err}");

        // Without the opt-in, even a redirect to a private name is refused.
        let srv = TestServer::bind().await;
        let url = srv.url("/x");
        srv.run(vec![Reply::redirect("https://localhost/private")]);
        let strict = Client::new("test", Duration::from_secs(5), false);
        // The first hop itself is private here, so it fails before any
        // request; the redirect check is covered by the loop above.
        assert!(strict.get_text(&url, None, 1024).await.is_err());
    }

    #[tokio::test]
    async fn redirect_loops_are_bounded() {
        let srv = TestServer::bind().await;
        let url = srv.url("/loop");
        let seen = srv.run(vec![Reply::redirect(&url); 5]);
        let err = lan_client()
            .get_text(&url, None, 1024)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("too many redirects"), "{err}");
        assert_eq!(seen.lock().await.len(), MAX_REDIRECTS + 1);
    }

    #[tokio::test]
    async fn post_never_follows_redirects() {
        let srv = TestServer::bind().await;
        let url = srv.url("/hook");
        let elsewhere = srv.url("/elsewhere");
        let seen = srv.run(vec![Reply::redirect(&elsewhere), Reply::status(200)]);
        let err = lan_client()
            .post(&url, &[], "text/plain", "x".into())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("redirected"), "{err}");
        assert_eq!(seen.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn bodies_are_capped_and_not_modified_is_reported() {
        let srv = TestServer::bind().await;
        let url = srv.url("/big");
        srv.run(vec![
            Reply::body(200, &"x".repeat(2048)),
            Reply::status(304),
        ]);
        let err = lan_client()
            .get_text(&url, None, 1024)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("larger than"), "{err}");
        assert!(matches!(
            lan_client()
                .get_text(&url, Some("\"v1\""), 1024)
                .await
                .unwrap(),
            Fetched::NotModified
        ));
    }
}
