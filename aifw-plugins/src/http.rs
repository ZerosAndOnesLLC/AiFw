//! Outbound HTTP for plugins. Every request goes through
//! [`check_destination`] (SSRF guard), redirects are limited and re-checked,
//! and response bodies are size-capped while streaming so a hostile or
//! broken server can't exhaust memory.

use std::net::IpAddr;
use std::time::Duration;

use crate::error::{PluginError, Result};

const MAX_REDIRECTS: usize = 3;

/// User agent sent by plugin requests.
pub fn user_agent(plugin: &str) -> String {
    format!("AiFw/{} ({plugin})", env!("CARGO_PKG_VERSION"))
}

/// Refuse destinations a plugin must not reach. By default only https
/// URLs resolving to public addresses are allowed; `allow_private` (an
/// explicit operator opt-in, e.g. a self-hosted ntfy on the LAN) permits
/// http and private addresses but still refuses non-http schemes.
pub async fn check_destination(url: &str, allow_private: bool) -> Result<()> {
    if allow_private {
        let parsed = url::Url::parse(url)
            .map_err(|e| PluginError::Validation(format!("invalid URL: {e}")))?;
        return match parsed.scheme() {
            "http" | "https" if parsed.host_str().is_some() => Ok(()),
            _ => Err(PluginError::Validation(format!(
                "only http(s) URLs are allowed: {url}"
            ))),
        };
    }
    aifw_common::net_safety::validate_outbound_url(url)
        .await
        .map_err(|e| PluginError::Validation(format!("{url}: {e}")))
}

/// HTTP client for plugin use: timeout, user agent, and a redirect policy
/// that follows at most three hops, never downgrades to http (unless
/// `allow_private`), and never lands on a literal private address.
pub fn client(plugin: &str, timeout: Duration, allow_private: bool) -> Result<reqwest::Client> {
    let policy = reqwest::redirect::Policy::custom(move |attempt| {
        if attempt.previous().len() >= MAX_REDIRECTS {
            return attempt.error("too many redirects");
        }
        let url = attempt.url();
        if !allow_private {
            if url.scheme() != "https" {
                return attempt.error("redirect to a non-https URL refused");
            }
            if let Some(ip) = url
                .host_str()
                .and_then(|h| h.trim_matches(['[', ']']).parse::<IpAddr>().ok())
                && !aifw_common::net_safety::is_public(ip)
            {
                return attempt.error("redirect to a private address refused");
            }
        }
        attempt.follow()
    });
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        .user_agent(user_agent(plugin))
        .redirect(policy)
        .build()
        .map_err(|e| PluginError::Plugin(format!("http client: {e}")))
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

/// Conditional GET of `url`, failing if the body exceeds `max_bytes`.
pub async fn fetch_text(
    client: &reqwest::Client,
    url: &str,
    etag: Option<&str>,
    max_bytes: usize,
) -> Result<Fetched> {
    check_destination(url, false).await?;
    let mut req = client.get(url);
    if let Some(tag) = etag {
        req = req.header(reqwest::header::IF_NONE_MATCH, tag);
    }
    let mut resp = req
        .send()
        .await
        .map_err(|e| PluginError::Plugin(format!("request failed: {e}")))?;
    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(Fetched::NotModified);
    }
    if !resp.status().is_success() {
        return Err(PluginError::Plugin(format!("HTTP {}", resp.status())));
    }
    if resp
        .content_length()
        .is_some_and(|len| len > max_bytes as u64)
    {
        return Err(PluginError::Plugin(format!(
            "response larger than {} MB",
            max_bytes / (1024 * 1024)
        )));
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
        .map_err(|e| PluginError::Plugin(format!("reading response: {e}")))?
    {
        if body.len() + chunk.len() > max_bytes {
            return Err(PluginError::Plugin(format!(
                "response larger than {} MB",
                max_bytes / (1024 * 1024)
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Fetched::Body {
        text: String::from_utf8_lossy(&body).into_owned(),
        etag,
    })
}
