//! Error type for API calls: one variant per failure class the CLI maps to
//! an exit code.

use reqwest::StatusCode;

pub type Result<T> = std::result::Result<T, ClientError>;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    /// Couldn't reach the API (connection refused, DNS, timeout).
    #[error("cannot reach the AiFw API at {url}: {reason}")]
    Unreachable { url: String, reason: String },
    /// The request timed out; the server may still be working on it.
    #[error(
        "timed out waiting for {url} (the server may still finish the operation; raise --request-timeout for slow ones)"
    )]
    Timeout { url: String },
    /// TLS handshake failed — most often a certificate pin mismatch.
    #[error(
        "TLS error talking to {url}: {reason} (if the appliance certificate changed, re-pin with `aifw login` or `aifw context set-pin`)"
    )]
    Tls { url: String, reason: String },
    /// 401 — no credential, a bad/expired one, or a revoked key.
    #[error("not authenticated: {0} (run `aifw login`, or set AIFW_TOKEN)")]
    Unauthorized(String),
    /// 403 — authenticated but lacking the permission.
    #[error("permission denied: {0}")]
    Forbidden(String),
    /// 404
    #[error("not found: {0}")]
    NotFound(String),
    /// 400 / 422 — the request was rejected by validation.
    #[error("rejected: {0}")]
    Validation(String),
    /// 409
    #[error("conflict: {0}")]
    Conflict(String),
    /// 429
    #[error("rate limited: {0}")]
    RateLimited(String),
    /// Any other non-2xx status.
    #[error("server error ({status}): {message}")]
    Server { status: u16, message: String },
    /// The response body wasn't what we expected.
    #[error("unexpected response: {0}")]
    Decode(String),
    /// Local problem (bad URL, unreadable file, credential store write).
    #[error("{0}")]
    Local(String),
}

impl ClientError {
    /// Map a non-success status + body onto a variant. The API's error
    /// bodies are `{"error": ".."}` or `{"message": ".."}`; many handlers
    /// return a bare status, in which case the request line is the message.
    pub fn from_status(status: StatusCode, body: &str, what: &str) -> Self {
        let detail = extract_message(body)
            .or_else(|| plain_text_message(body))
            .unwrap_or_else(|| what.to_string());
        match status.as_u16() {
            400 | 422 => Self::Validation(detail),
            401 => Self::Unauthorized(detail),
            403 => Self::Forbidden(detail),
            404 => Self::NotFound(detail),
            409 => Self::Conflict(detail),
            429 => Self::RateLimited(detail),
            s => Self::Server {
                status: s,
                message: detail,
            },
        }
    }

    /// Classify a transport error. TLS failures surface as connect errors
    /// whose source chain mentions the certificate.
    pub fn from_transport(url: &str, e: &reqwest::Error) -> Self {
        if e.is_timeout() {
            return Self::Timeout {
                url: url.to_string(),
            };
        }
        // The top-level message repeats the URL ("error sending request for
        // url (…)"); the source chain carries the actual cause.
        let mut parts = Vec::new();
        let mut src = std::error::Error::source(e);
        while let Some(s) = src {
            parts.push(s.to_string());
            src = s.source();
        }
        let chain = if parts.is_empty() {
            e.to_string()
        } else {
            parts.join(": ")
        };
        let lower = chain.to_ascii_lowercase();
        if lower.contains("certificate") || lower.contains("tls") || lower.contains("handshake") {
            Self::Tls {
                url: url.to_string(),
                reason: chain,
            }
        } else {
            Self::Unreachable {
                url: url.to_string(),
                reason: chain,
            }
        }
    }

    /// HTTP status this error came from, if any.
    pub fn status(&self) -> Option<u16> {
        match self {
            Self::Validation(_) => Some(400),
            Self::Unauthorized(_) => Some(401),
            Self::Forbidden(_) => Some(403),
            Self::NotFound(_) => Some(404),
            Self::Conflict(_) => Some(409),
            Self::RateLimited(_) => Some(429),
            Self::Server { status, .. } => Some(*status),
            _ => None,
        }
    }
}

/// Some handlers answer errors with a short plain-text body (e.g. "an OS
/// upgrade is in progress"); use it when it looks like a sentence, not an
/// HTML page or a JSON document.
fn plain_text_message(body: &str) -> Option<String> {
    let t = body.trim();
    (!t.is_empty() && t.len() <= 500 && !t.starts_with(['<', '{', '['])).then(|| t.to_string())
}

/// Pull a human message out of a JSON error body.
pub fn extract_message(body: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(body).ok()?;
    for key in ["error", "message", "detail"] {
        if let Some(s) = v.get(key).and_then(|m| m.as_str())
            && !s.is_empty()
        {
            return Some(s.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_classes() {
        let e = |s: u16| ClientError::from_status(StatusCode::from_u16(s).unwrap(), "", "GET /x");
        assert!(matches!(e(400), ClientError::Validation(_)));
        assert!(matches!(e(422), ClientError::Validation(_)));
        assert!(matches!(e(401), ClientError::Unauthorized(_)));
        assert!(matches!(e(403), ClientError::Forbidden(_)));
        assert!(matches!(e(404), ClientError::NotFound(_)));
        assert!(matches!(e(409), ClientError::Conflict(_)));
        assert!(matches!(e(429), ClientError::RateLimited(_)));
        assert!(matches!(e(500), ClientError::Server { status: 500, .. }));
        assert_eq!(e(503).status(), Some(503));
    }

    #[test]
    fn message_from_body_or_request_line() {
        let e = ClientError::from_status(
            StatusCode::BAD_REQUEST,
            r#"{"error":"bad cidr"}"#,
            "POST /rules",
        );
        assert_eq!(e.to_string(), "rejected: bad cidr");
        let e = ClientError::from_status(
            StatusCode::BAD_REQUEST,
            r#"{"message":"nope"}"#,
            "POST /rules",
        );
        assert_eq!(e.to_string(), "rejected: nope");
        let e = ClientError::from_status(StatusCode::NOT_FOUND, "", "GET /rules/9");
        assert_eq!(e.to_string(), "not found: GET /rules/9");
        assert_eq!(extract_message("not json"), None);
        let e = ClientError::from_status(
            StatusCode::CONFLICT,
            "an OS upgrade is in progress",
            "POST /x",
        );
        assert_eq!(e.to_string(), "conflict: an OS upgrade is in progress");
        let e = ClientError::from_status(StatusCode::BAD_GATEWAY, "<html>bad</html>", "GET /x");
        assert_eq!(e.to_string(), "server error (502): GET /x");
        assert_eq!(extract_message(r#"{"error":""}"#), None);
    }
}
