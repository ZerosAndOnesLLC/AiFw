//! Client-IP resolution with a trusted-proxy allowlist (#308 / SEC-M11).
//!
//! `X-Forwarded-For` used to be believed unconditionally, so anyone could
//! dodge login / refresh rate limiting by rotating the header. Now the
//! peer address (from `ConnectInfo`) is the client unless that peer is in
//! the operator's trusted-proxy list — only then is XFF consulted, and
//! walked from the right so that hops appended by *our* proxies are
//! skipped and the first address a trusted proxy saw wins.
//!
//! Sources of the allowlist, merged: `--trusted-proxies` /
//! `AIFW_TRUSTED_PROXIES` (comma-separated IPs or CIDRs) and the
//! `api_server_trusted_proxies` key in `auth_config` (Settings → API
//! Server), read at startup.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::HeaderMap;
use axum::middleware::Next;
use axum::response::Response;
use ip_network::IpNetwork;

/// Parsed trusted-proxy allowlist.
#[derive(Debug, Default, Clone)]
pub struct TrustedProxies {
    nets: Vec<IpNetwork>,
}

impl TrustedProxies {
    /// Parse a comma/space-separated list of IPs and CIDRs. Bad entries are
    /// returned so the caller can log them; good ones are kept.
    pub fn parse(spec: &str) -> (Self, Vec<String>) {
        let mut nets = Vec::new();
        let mut bad = Vec::new();
        for raw in spec.split([',', ' ', '\n']) {
            let item = raw.trim();
            if item.is_empty() {
                continue;
            }
            match parse_entry(item) {
                Some(n) => nets.push(n),
                None => bad.push(item.to_string()),
            }
        }
        (Self { nets }, bad)
    }

    /// Merge another list into this one.
    pub fn extend(&mut self, other: TrustedProxies) {
        self.nets.extend(other.nets);
    }

    /// True if `ip` belongs to a trusted proxy.
    pub fn contains(&self, ip: IpAddr) -> bool {
        // Compare v4-mapped v6 peers (::ffff:a.b.c.d) as their v4 form so an
        // allowlist written in v4 works on a dual-stack listener.
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            v4 => v4,
        };
        self.nets.iter().any(|n| n.contains(ip))
    }

    /// True if no proxies are configured (XFF is never trusted).
    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }
}

fn parse_entry(item: &str) -> Option<IpNetwork> {
    if let Ok(n) = item.parse::<IpNetwork>() {
        return Some(n);
    }
    let ip: IpAddr = item.parse().ok()?;
    let bits = if ip.is_ipv4() { 32 } else { 128 };
    IpNetwork::new(ip, bits).ok()
}

/// The resolved client address for a request, as a request extension.
/// `None` when the server has no `ConnectInfo` (in-process test servers).
#[derive(Debug, Clone, Copy)]
pub struct ClientIp(pub Option<IpAddr>);

impl ClientIp {
    /// String form for rate-limiter keys and logs.
    pub fn key(&self) -> Option<String> {
        self.0.map(|ip| ip.to_string())
    }
}

/// Pure resolution: `peer` is the TCP peer; XFF is honoured only when the
/// peer is a trusted proxy, walking right-to-left past trusted hops.
pub fn resolve(
    peer: Option<IpAddr>,
    headers: &HeaderMap,
    trusted: &TrustedProxies,
) -> Option<IpAddr> {
    let peer = peer?;
    if trusted.is_empty() || !trusted.contains(peer) {
        return Some(peer);
    }
    let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) else {
        return Some(peer);
    };
    // Rightmost entry not itself a trusted proxy = the real client. All
    // entries left of it were supplied by untrusted parties (or the client)
    // and are ignored.
    for hop in xff.rsplit(',') {
        let hop = hop.trim();
        // Tolerate "ip:port" and bracketed v6 forms some proxies emit.
        let candidate = hop
            .parse::<IpAddr>()
            .ok()
            .or_else(|| hop.parse::<SocketAddr>().ok().map(|s| s.ip()))
            .or_else(|| hop.trim_matches(['[', ']']).parse::<IpAddr>().ok());
        match candidate {
            Some(ip) if trusted.contains(ip) => continue,
            Some(ip) => return Some(ip),
            None => return Some(peer), // garbage header — fall back to the peer
        }
    }
    // Every hop was one of our proxies: the connection originated inside
    // the proxy tier; attribute to the peer.
    Some(peer)
}

/// Middleware: attach [`ClientIp`] to every request.
pub async fn attach_client_ip(
    State(trusted): State<Arc<TrustedProxies>>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip());
    let ip = resolve(peer, request.headers(), &trusted);
    request.extensions_mut().insert(ClientIp(ip));
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn hdrs(xff: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_str(xff).unwrap());
        h
    }
    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn parses_ips_and_cidrs_and_reports_bad() {
        let (t, bad) = TrustedProxies::parse("10.0.0.5, 192.168.0.0/16 fd00::/8,nope");
        assert_eq!(bad, vec!["nope"]);
        assert!(t.contains(ip("10.0.0.5")));
        assert!(t.contains(ip("192.168.44.1")));
        assert!(t.contains(ip("fd00::1")));
        assert!(!t.contains(ip("10.0.0.6")));
        // v4-mapped v6 peer matches a v4 allowlist entry
        assert!(t.contains(ip("::ffff:10.0.0.5")));
    }

    #[test]
    fn untrusted_peer_ignores_xff() {
        let (t, _) = TrustedProxies::parse("10.0.0.5");
        let r = resolve(Some(ip("203.0.113.9")), &hdrs("1.2.3.4"), &t);
        assert_eq!(r, Some(ip("203.0.113.9")));
        // and with no allowlist at all
        let r = resolve(
            Some(ip("203.0.113.9")),
            &hdrs("1.2.3.4"),
            &TrustedProxies::default(),
        );
        assert_eq!(r, Some(ip("203.0.113.9")));
    }

    #[test]
    fn trusted_peer_uses_rightmost_untrusted_hop() {
        let (t, _) = TrustedProxies::parse("10.0.0.0/8");
        // client -> proxy A (10.0.0.5) -> proxy B (10.0.0.6, our peer)
        let r = resolve(Some(ip("10.0.0.6")), &hdrs("198.51.100.7, 10.0.0.5"), &t);
        assert_eq!(r, Some(ip("198.51.100.7")));
        // Attacker prepends junk: only the entry the trusted proxy appended counts.
        let r = resolve(Some(ip("10.0.0.6")), &hdrs("1.1.1.1, 198.51.100.7"), &t);
        assert_eq!(r, Some(ip("198.51.100.7")));
        // ip:port form
        let r = resolve(Some(ip("10.0.0.6")), &hdrs("198.51.100.7:5555"), &t);
        assert_eq!(r, Some(ip("198.51.100.7")));
        // All hops trusted / header missing / garbage → peer
        assert_eq!(
            resolve(Some(ip("10.0.0.6")), &hdrs("10.0.0.5"), &t),
            Some(ip("10.0.0.6"))
        );
        assert_eq!(
            resolve(Some(ip("10.0.0.6")), &HeaderMap::new(), &t),
            Some(ip("10.0.0.6"))
        );
        assert_eq!(
            resolve(Some(ip("10.0.0.6")), &hdrs("what"), &t),
            Some(ip("10.0.0.6"))
        );
    }

    /// The middleware end to end: peer from ConnectInfo, XFF honoured only
    /// behind a trusted proxy, handlers read `Extension<ClientIp>`.
    #[tokio::test]
    async fn middleware_attaches_resolved_ip() {
        use axum::{Router, body::Body, routing::get};
        use tower::ServiceExt;

        async fn who(axum::Extension(c): axum::Extension<ClientIp>) -> String {
            c.key().unwrap_or_else(|| "none".into())
        }
        let (trusted, _) = TrustedProxies::parse("10.0.0.0/8");
        let app = Router::new()
            .route("/", get(who))
            .layer(axum::middleware::from_fn_with_state(
                Arc::new(trusted),
                attach_client_ip,
            ));

        let call = |peer: Option<&str>, xff: Option<&str>| {
            let app = app.clone();
            let peer = peer.map(|p| p.parse::<SocketAddr>().unwrap());
            let xff = xff.map(str::to_string);
            async move {
                let mut req = axum::http::Request::builder().uri("/");
                if let Some(x) = &xff {
                    req = req.header("x-forwarded-for", x);
                }
                let mut req = req.body(Body::empty()).unwrap();
                if let Some(p) = peer {
                    req.extensions_mut().insert(ConnectInfo(p));
                }
                let resp = app.oneshot(req).await.unwrap();
                let bytes = axum::body::to_bytes(resp.into_body(), 1024).await.unwrap();
                String::from_utf8(bytes.to_vec()).unwrap()
            }
        };

        assert_eq!(
            call(Some("203.0.113.9:4000"), Some("1.2.3.4")).await,
            "203.0.113.9"
        );
        assert_eq!(
            call(Some("10.0.0.6:4000"), Some("198.51.100.7")).await,
            "198.51.100.7"
        );
        assert_eq!(call(Some("10.0.0.6:4000"), None).await, "10.0.0.6");
        assert_eq!(call(None, Some("1.2.3.4")).await, "none");
    }

    #[test]
    fn no_peer_means_unknown() {
        let (t, _) = TrustedProxies::parse("10.0.0.0/8");
        assert_eq!(resolve(None, &hdrs("1.2.3.4"), &t), None);
    }
}
