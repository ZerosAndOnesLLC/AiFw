//! Delivery channels. Payload construction is pure (unit-tested); sending
//! goes through the SSRF-checked plugin HTTP client with retries.

use std::time::Duration;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::message::{Level, Notification};
use crate::error::{PluginError, Result};
use crate::http::check_destination;

const ATTEMPTS: u32 = 3;
const MAX_RETRY_AFTER: Duration = Duration::from_secs(30);

/// A configured destination.
#[derive(Debug, Clone, PartialEq)]
pub enum Channel {
    /// ntfy topic URL (`https://ntfy.sh/<topic>`) + optional access token
    Ntfy {
        /// Topic URL
        url: String,
        /// Bearer token
        token: Option<String>,
    },
    /// Discord incoming webhook
    Discord {
        /// Webhook URL
        url: String,
    },
    /// Slack incoming webhook
    Slack {
        /// Webhook URL
        url: String,
    },
    /// Telegram bot
    Telegram {
        /// Bot token from @BotFather
        token: String,
        /// Chat / channel id
        chat_id: String,
    },
    /// Generic JSON webhook, optionally HMAC-signed
    Webhook {
        /// Endpoint
        url: String,
        /// Shared secret for `X-AiFw-Signature`
        secret: Option<String>,
    },
}

impl Channel {
    /// Stable id used in settings, status and the test action.
    pub fn id(&self) -> &'static str {
        match self {
            Channel::Ntfy { .. } => "ntfy",
            Channel::Discord { .. } => "discord",
            Channel::Slack { .. } => "slack",
            Channel::Telegram { .. } => "telegram",
            Channel::Webhook { .. } => "webhook",
        }
    }
}

/// One outgoing HTTP request.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    /// Destination
    pub url: String,
    /// Extra headers
    pub headers: Vec<(String, String)>,
    /// Body bytes (UTF-8)
    pub body: String,
    /// Content type of `body`
    pub content_type: &'static str,
}

fn emoji(level: Level) -> &'static str {
    match level {
        Level::Critical => "🚨",
        Level::Warning => "⚠️",
        Level::Info => "ℹ️",
        Level::Resolved => "✅",
    }
}

fn text(n: &Notification, host: &str) -> String {
    let mut s = format!("{} [{host}] {}", emoji(n.level), n.title);
    if !n.body.is_empty() {
        s.push('\n');
        s.push_str(&n.body);
    }
    s
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    const BLOCK: usize = 64;
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for i in 0..BLOCK {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let inner = Sha256::new()
        .chain_update(ipad)
        .chain_update(msg)
        .finalize();
    let outer = Sha256::new()
        .chain_update(opad)
        .chain_update(inner)
        .finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer);
    out
}

/// Build the request `channel` needs for `n`.
pub fn build(channel: &Channel, n: &Notification, host: &str) -> Request {
    match channel {
        Channel::Ntfy { url, token } => {
            let (priority, tag) = match n.level {
                Level::Critical => ("5", "rotating_light"),
                Level::Warning => ("4", "warning"),
                Level::Info => ("3", "information_source"),
                Level::Resolved => ("3", "white_check_mark"),
            };
            let mut headers = vec![
                ("Title".to_string(), format!("[{host}] {}", n.title)),
                ("Priority".to_string(), priority.to_string()),
                ("Tags".to_string(), tag.to_string()),
            ];
            if let Some(t) = token {
                headers.push(("Authorization".to_string(), format!("Bearer {t}")));
            }
            Request {
                url: url.clone(),
                headers,
                body: if n.body.is_empty() {
                    n.title.clone()
                } else {
                    n.body.clone()
                },
                content_type: "text/plain; charset=utf-8",
            }
        }
        Channel::Discord { url } => {
            let color = match n.level {
                Level::Critical => 0xd9_3025,
                Level::Warning => 0xe0_8a00,
                Level::Info => 0x2f_6fed,
                Level::Resolved => 0x1f_a85a,
            };
            let fields: Vec<Value> = n
                .fields
                .iter()
                .map(|(k, v)| json!({"name": k, "value": v, "inline": true}))
                .collect();
            let body = json!({
                "username": "AiFw",
                "embeds": [{
                    "title": format!("{} {}", emoji(n.level), n.title),
                    "description": n.body,
                    "color": color,
                    "fields": fields,
                    "footer": {"text": host},
                    "timestamp": n.at.to_rfc3339(),
                }],
            });
            Request {
                url: url.clone(),
                headers: Vec::new(),
                body: body.to_string(),
                content_type: "application/json",
            }
        }
        Channel::Slack { url } => {
            let mut t = text(n, host);
            for (k, v) in &n.fields {
                t.push_str(&format!("\n• {k}: {v}"));
            }
            Request {
                url: url.clone(),
                headers: Vec::new(),
                body: json!({"text": t}).to_string(),
                content_type: "application/json",
            }
        }
        Channel::Telegram { token, chat_id } => Request {
            url: format!("https://api.telegram.org/bot{token}/sendMessage"),
            headers: Vec::new(),
            body: json!({
                "chat_id": chat_id,
                "text": text(n, host),
                "disable_web_page_preview": true,
            })
            .to_string(),
            content_type: "application/json",
        },
        Channel::Webhook { url, secret } => {
            let fields: serde_json::Map<String, Value> = n
                .fields
                .iter()
                .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                .collect();
            let body = json!({
                "source": "aifw",
                "host": host,
                "kind": n.kind,
                "level": n.level,
                "title": n.title,
                "body": n.body,
                "fields": fields,
                "timestamp": n.at.to_rfc3339(),
            })
            .to_string();
            let mut headers = vec![("X-AiFw-Event".to_string(), format!("{:?}", n.kind))];
            if let Some(s) = secret {
                let sig = hex::encode(hmac_sha256(s.as_bytes(), body.as_bytes()));
                headers.push(("X-AiFw-Signature".to_string(), format!("sha256={sig}")));
            }
            Request {
                url: url.clone(),
                headers,
                body,
                content_type: "application/json",
            }
        }
    }
}

/// Error text safe to show: never echo a URL, since webhook URLs and the
/// Telegram bot token are secrets.
fn redact(e: reqwest::Error) -> String {
    if e.is_timeout() {
        "timed out".into()
    } else if e.is_connect() {
        "could not connect".into()
    } else {
        e.without_url().to_string()
    }
}

/// Deliver `n` through `channel`, retrying transient failures.
pub async fn send(
    client: &reqwest::Client,
    channel: &Channel,
    n: &Notification,
    host: &str,
    allow_private: bool,
) -> Result<()> {
    let req = build(channel, n, host);
    // Telegram is always the public Bot API.
    let private_ok = allow_private && !matches!(channel, Channel::Telegram { .. });
    check_destination(&req.url, private_ok)
        .await
        .map_err(|_| PluginError::Validation(format!("{} destination refused", channel.id())))?;

    let mut last_err = String::new();
    for attempt in 1..=ATTEMPTS {
        let mut rb = client
            .post(&req.url)
            .header(reqwest::header::CONTENT_TYPE, req.content_type)
            .body(req.body.clone());
        for (k, v) in &req.headers {
            rb = rb.header(k, v);
        }
        let backoff = Duration::from_secs(1 << (attempt - 1));
        match rb.send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            Ok(resp) => {
                let status = resp.status();
                last_err = format!("HTTP {status}");
                let retryable =
                    status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error();
                if !retryable || attempt == ATTEMPTS {
                    break;
                }
                let wait = resp
                    .headers()
                    .get(reqwest::header::RETRY_AFTER)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.trim().parse::<u64>().ok())
                    .map(Duration::from_secs)
                    .unwrap_or(backoff)
                    .min(MAX_RETRY_AFTER);
                tokio::time::sleep(wait).await;
            }
            Err(e) => {
                last_err = redact(e);
                if attempt == ATTEMPTS {
                    break;
                }
                tokio::time::sleep(backoff).await;
            }
        }
    }
    Err(PluginError::Plugin(format!("{}: {last_err}", channel.id())))
}

#[cfg(test)]
mod tests {
    use super::super::message::{Kind, test_notification};
    use super::*;

    #[test]
    fn hmac_matches_rfc4231() {
        // RFC 4231 test case 2.
        let mac = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(mac),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        // Test case 6: key longer than the block size.
        let mac = hmac_sha256(
            &[0xaa; 131],
            b"Test Using Larger Than Block-Size Key - Hash Key First",
        );
        assert_eq!(
            hex::encode(mac),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
    }

    #[test]
    fn webhook_is_signed() {
        let n = test_notification();
        let r = build(
            &Channel::Webhook {
                url: "https://example.com/hook".into(),
                secret: Some("s3cret".into()),
            },
            &n,
            "fw1",
        );
        let sig = r
            .headers
            .iter()
            .find(|(k, _)| k == "X-AiFw-Signature")
            .map(|(_, v)| v.clone())
            .unwrap();
        let expected = hex::encode(hmac_sha256(b"s3cret", r.body.as_bytes()));
        assert_eq!(sig, format!("sha256={expected}"));
        let v: Value = serde_json::from_str(&r.body).unwrap();
        assert_eq!(v["kind"], "test");
        assert_eq!(v["host"], "fw1");
    }

    #[test]
    fn ntfy_priority_and_auth() {
        let mut n = test_notification();
        n.level = Level::Critical;
        n.kind = Kind::Gateway;
        let r = build(
            &Channel::Ntfy {
                url: "https://ntfy.sh/t".into(),
                token: Some("tk".into()),
            },
            &n,
            "fw1",
        );
        let h = |name: &str| {
            r.headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(h("Priority"), Some("5"));
        assert_eq!(h("Authorization"), Some("Bearer tk"));
        assert!(h("Title").unwrap().starts_with("[fw1]"));
    }

    #[test]
    fn discord_and_slack_payloads_are_json() {
        let n = test_notification();
        for ch in [
            Channel::Discord {
                url: "https://discord.com/api/webhooks/x".into(),
            },
            Channel::Slack {
                url: "https://hooks.slack.com/services/x".into(),
            },
            Channel::Telegram {
                token: "123:abc".into(),
                chat_id: "42".into(),
            },
        ] {
            let r = build(&ch, &n, "fw1");
            let v: Value = serde_json::from_str(&r.body).unwrap();
            assert!(v.is_object(), "{}", ch.id());
        }
        let tg = build(
            &Channel::Telegram {
                token: "123:abc".into(),
                chat_id: "42".into(),
            },
            &n,
            "fw1",
        );
        assert_eq!(tg.url, "https://api.telegram.org/bot123:abc/sendMessage");
    }

    /// Minimal HTTP/1.1 server: answers each request with the next status
    /// from `statuses` and records (headers, body).
    async fn serve(
        statuses: Vec<u16>,
    ) -> (
        String,
        std::sync::Arc<tokio::sync::Mutex<Vec<(String, String)>>>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let log = seen.clone();
        tokio::spawn(async move {
            for status in statuses {
                let (mut sock, _) = listener.accept().await.unwrap();
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let (head, body) = loop {
                    let n = sock.read(&mut chunk).await.unwrap();
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
                let resp = format!(
                    "HTTP/1.1 {status} X\r\nRetry-After: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                sock.write_all(resp.as_bytes()).await.unwrap();
            }
        });
        (format!("http://{addr}/hook"), seen)
    }

    #[tokio::test]
    async fn delivers_signed_webhook_and_retries_server_errors() {
        let (url, seen) = serve(vec![503, 200]).await;
        let client = crate::http::client("notifier", Duration::from_secs(5), true).unwrap();
        let ch = Channel::Webhook {
            url: url.clone(),
            secret: Some("k".into()),
        };
        send(&client, &ch, &test_notification(), "fw1", true)
            .await
            .unwrap();
        let reqs = seen.lock().await;
        assert_eq!(reqs.len(), 2, "503 must be retried");
        let (head, body) = &reqs[1];
        let sig = hex::encode(hmac_sha256(b"k", body.as_bytes()));
        assert!(
            head.to_ascii_lowercase()
                .contains(&format!("x-aifw-signature: sha256={sig}")),
            "{head}"
        );
        assert!(body.contains("\"title\":\"AiFw test notification\""));
    }

    #[tokio::test]
    async fn private_destinations_need_opt_in() {
        let (url, seen) = serve(vec![200]).await;
        let client = crate::http::client("notifier", Duration::from_secs(5), false).unwrap();
        let ch = Channel::Slack { url };
        let err = send(&client, &ch, &test_notification(), "fw1", false)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("destination refused"));
        assert!(seen.lock().await.is_empty());
    }

    #[tokio::test]
    async fn client_errors_are_not_retried() {
        let (url, seen) = serve(vec![404, 200]).await;
        let client = crate::http::client("notifier", Duration::from_secs(5), true).unwrap();
        let err = send(
            &client,
            &Channel::Discord { url },
            &test_notification(),
            "fw1",
            true,
        )
        .await
        .unwrap_err();
        assert!(err.to_string().contains("404"));
        assert_eq!(seen.lock().await.len(), 1);
    }
}
