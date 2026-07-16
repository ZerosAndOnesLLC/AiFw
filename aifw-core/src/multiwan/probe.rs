//! Probe implementations for gateway health monitoring.
//!
//! All probe kinds share a common interface returning `ProbeOutcome`.
//! PERF-H16 (#360): probes fire at `interval_ms` (default 500 ms) per
//! gateway, so subprocess spawns add up fast. TCP is pure tokio, HTTP goes
//! through a shared `reqwest` client (already a workspace dep for
//! ddns/acme), and DNS is a minimal hand-rolled UDP query — `host` can't be
//! replaced by `tokio::net::lookup_host` because SLA probes must query a
//! *specific* server, not the system resolver. Only ICMP still shells out:
//! raw ICMP sockets need privileges the service (uid 470 `aifw`) doesn't
//! have, and FreeBSD has no Linux-style unprivileged ping sockets — setuid
//! `/sbin/ping` *is* the privilege boundary.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::net::{TcpStream, UdpSocket};
use tokio::process::Command;

#[derive(Debug, Clone)]
pub struct ProbeOutcome {
    pub success: bool,
    pub rtt_ms: Option<f64>,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProbeSpec {
    pub kind: ProbeKind,
    pub target: String,
    pub port: Option<u16>,
    pub expect: Option<String>,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeKind {
    Icmp,
    Tcp,
    Http,
    Dns,
}

impl ProbeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Icmp => "icmp",
            Self::Tcp => "tcp",
            Self::Http => "http",
            Self::Dns => "dns",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "icmp" => Some(Self::Icmp),
            "tcp" => Some(Self::Tcp),
            "http" => Some(Self::Http),
            "dns" => Some(Self::Dns),
            _ => None,
        }
    }
}

pub async fn run_probe(spec: &ProbeSpec) -> ProbeOutcome {
    match spec.kind {
        ProbeKind::Icmp => icmp_probe(spec).await,
        ProbeKind::Tcp => tcp_probe(spec).await,
        ProbeKind::Http => http_probe(spec).await,
        ProbeKind::Dns => dns_probe(spec).await,
    }
}

async fn icmp_probe(spec: &ProbeSpec) -> ProbeOutcome {
    let timeout_secs = spec.timeout_ms.div_ceil(1000).max(1);
    let start = Instant::now();
    let result = Command::new("/sbin/ping")
        .args([
            "-c",
            "1",
            "-W",
            &timeout_secs.to_string(),
            "-q",
            &spec.target,
        ])
        .output()
        .await;
    match result {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let rtt = parse_ping_rtt(&stdout).or(Some(start.elapsed().as_secs_f64() * 1000.0));
            ProbeOutcome {
                success: true,
                rtt_ms: rtt,
                error: None,
            }
        }
        Ok(out) => ProbeOutcome {
            success: false,
            rtt_ms: None,
            error: Some(String::from_utf8_lossy(&out.stderr).into_owned()),
        },
        Err(e) => ProbeOutcome {
            success: false,
            rtt_ms: None,
            error: Some(e.to_string()),
        },
    }
}

fn parse_ping_rtt(s: &str) -> Option<f64> {
    // "round-trip min/avg/max/stddev = 0.123/0.456/0.789/0.001 ms"
    let line = s.lines().find(|l| l.contains("min/avg/max"))?;
    let stats = line.split('=').nth(1)?.trim();
    let avg = stats.split('/').nth(1)?;
    avg.trim().parse().ok()
}

async fn tcp_probe(spec: &ProbeSpec) -> ProbeOutcome {
    let port = spec.port.unwrap_or(443);
    let addr = format!("{}:{port}", spec.target);
    let start = Instant::now();
    match tokio::time::timeout(
        Duration::from_millis(spec.timeout_ms),
        TcpStream::connect(&addr),
    )
    .await
    {
        Ok(Ok(_)) => ProbeOutcome {
            success: true,
            rtt_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
            error: None,
        },
        Ok(Err(e)) => ProbeOutcome {
            success: false,
            rtt_ms: None,
            error: Some(e.to_string()),
        },
        Err(_) => ProbeOutcome {
            success: false,
            rtt_ms: None,
            error: Some("timeout".into()),
        },
    }
}

/// Shared probe HTTP client. Redirects are NOT followed, matching the old
/// `curl` (no `-L`) behaviour where `%{http_code}` was the first response's
/// status.
fn http_client() -> Result<&'static reqwest::Client, String> {
    static CLIENT: std::sync::OnceLock<Result<reqwest::Client, String>> =
        std::sync::OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|e| format!("probe http client init: {e}"))
        })
        .as_ref()
        .map_err(Clone::clone)
}

async fn http_probe(spec: &ProbeSpec) -> ProbeOutcome {
    let url = if spec.target.starts_with("http") {
        spec.target.clone()
    } else {
        format!("http://{}", spec.target)
    };
    let client = match http_client() {
        Ok(c) => c,
        Err(e) => {
            return ProbeOutcome {
                success: false,
                rtt_ms: None,
                error: Some(e),
            };
        }
    };
    let start = Instant::now();
    match client
        .get(&url)
        .timeout(Duration::from_millis(spec.timeout_ms.max(1)))
        .send()
        .await
    {
        Ok(resp) => {
            let code = resp.status().as_u16();
            let want = spec
                .expect
                .as_deref()
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(200);
            let success = code == want || (want == 0 && (200..400).contains(&code));
            ProbeOutcome {
                success,
                rtt_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
                error: if success {
                    None
                } else {
                    Some(format!("got {code}, want {want}"))
                },
            }
        }
        Err(e) => ProbeOutcome {
            success: false,
            rtt_ms: None,
            error: Some(e.to_string()),
        },
    }
}

/// Build a minimal DNS query packet: one A-record question, recursion
/// desired. Returns None if the domain has an empty or >63-byte label.
fn build_dns_query(id: u16, domain: &str) -> Option<Vec<u8>> {
    let mut pkt = Vec::with_capacity(18 + domain.len());
    pkt.extend_from_slice(&id.to_be_bytes());
    pkt.extend_from_slice(&[0x01, 0x00]); // flags: RD
    pkt.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QDCOUNT=1
    for label in domain.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0);
    pkt.extend_from_slice(&[0, 1, 0, 1]); // QTYPE=A, QCLASS=IN
    Some(pkt)
}

/// Validate a DNS response against the query id: long enough for a header,
/// matching id, QR bit set, RCODE 0 (NOERROR). NXDOMAIN/SERVFAIL count as
/// probe failure, matching the old `host` exit-status semantics.
fn dns_response_ok(resp: &[u8], id: u16) -> Result<(), String> {
    if resp.len() < 12 {
        return Err(format!("short DNS response ({} bytes)", resp.len()));
    }
    if resp[0..2] != id.to_be_bytes() {
        return Err("DNS response id mismatch".into());
    }
    if resp[2] & 0x80 == 0 {
        return Err("DNS response missing QR bit".into());
    }
    let rcode = resp[3] & 0x0F;
    if rcode != 0 {
        return Err(format!("DNS rcode {rcode}"));
    }
    Ok(())
}

async fn dns_probe(spec: &ProbeSpec) -> ProbeOutcome {
    let fail = |error: String| ProbeOutcome {
        success: false,
        rtt_ms: None,
        error: Some(error),
    };

    let port = spec.port.unwrap_or(53);
    let domain = spec.expect.clone().unwrap_or_else(|| "example.com".into());
    // The target is the DNS *server* to probe. IP literal is the normal
    // case; fall back to the system resolver for hostname targets.
    let server: SocketAddr = match spec.target.parse::<IpAddr>() {
        Ok(ip) => SocketAddr::new(ip, port),
        Err(_) => {
            match tokio::net::lookup_host((spec.target.as_str(), port))
                .await
                .ok()
                .and_then(|mut addrs| addrs.next())
            {
                Some(addr) => addr,
                None => return fail(format!("cannot resolve DNS server '{}'", spec.target)),
            }
        }
    };

    // Pseudo-random query id — only needs to disambiguate our own probes.
    let id = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u16)
        .unwrap_or(0x1dee)
        ^ port;
    let Some(query) = build_dns_query(id, &domain) else {
        return fail(format!("invalid probe domain '{domain}'"));
    };

    let bind_addr = if server.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let start = Instant::now();
    let attempt = async {
        let sock = UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| format!("udp bind: {e}"))?;
        // connect() filters out datagrams from other peers.
        sock.connect(server)
            .await
            .map_err(|e| format!("udp connect: {e}"))?;
        sock.send(&query).await.map_err(|e| format!("send: {e}"))?;
        let mut buf = [0u8; 512];
        let n = sock
            .recv(&mut buf)
            .await
            .map_err(|e| format!("recv: {e}"))?;
        dns_response_ok(&buf[..n], id)
    };
    match tokio::time::timeout(Duration::from_millis(spec.timeout_ms.max(1)), attempt).await {
        Ok(Ok(())) => ProbeOutcome {
            success: true,
            rtt_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
            error: None,
        },
        Ok(Err(e)) => fail(e),
        Err(_) => fail("timeout".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn tcp_probe_loopback() {
        // Bind a listener so the connect succeeds
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let outcome = tcp_probe(&ProbeSpec {
            kind: ProbeKind::Tcp,
            target: "127.0.0.1".into(),
            port: Some(port),
            expect: None,
            timeout_ms: 1000,
        })
        .await;
        assert!(outcome.success);
        assert!(outcome.rtt_ms.unwrap() >= 0.0);
    }

    #[tokio::test]
    async fn tcp_probe_timeout() {
        // 192.0.2.x is TEST-NET-1, guaranteed unrouteable
        let outcome = tcp_probe(&ProbeSpec {
            kind: ProbeKind::Tcp,
            target: "192.0.2.1".into(),
            port: Some(1),
            expect: None,
            timeout_ms: 200,
        })
        .await;
        assert!(!outcome.success);
        assert!(outcome.error.is_some());
    }

    #[test]
    fn parse_ping_rtt_works() {
        let sample = "round-trip min/avg/max/stddev = 0.123/0.456/0.789/0.001 ms";
        assert_eq!(parse_ping_rtt(sample), Some(0.456));
    }

    // --- PERF-H16 (#360): native HTTP/DNS probes ---

    #[test]
    fn dns_query_shape() {
        let pkt = build_dns_query(0xabcd, "example.com").unwrap();
        assert_eq!(&pkt[0..2], &[0xab, 0xcd]); // id
        assert_eq!(pkt[2], 0x01); // RD
        assert_eq!(&pkt[4..6], &[0, 1]); // QDCOUNT
        // 7"example" 3"com" 0 + QTYPE/QCLASS
        assert_eq!(pkt[12], 7);
        assert_eq!(&pkt[13..20], b"example");
        assert_eq!(pkt[20], 3);
        assert_eq!(&pkt[pkt.len() - 4..], &[0, 1, 0, 1]);

        assert!(build_dns_query(1, "bad..label").is_none());
        assert!(build_dns_query(1, &"x".repeat(64)).is_none());
    }

    #[test]
    fn dns_response_validation() {
        let mut resp = vec![0u8; 12];
        resp[0] = 0xab;
        resp[1] = 0xcd;
        resp[2] = 0x80; // QR
        assert!(dns_response_ok(&resp, 0xabcd).is_ok());

        assert!(dns_response_ok(&resp[..8], 0xabcd).is_err()); // short
        assert!(dns_response_ok(&resp, 0x1111).is_err()); // id mismatch
        resp[3] = 0x03; // NXDOMAIN
        assert!(dns_response_ok(&resp, 0xabcd).is_err());
        resp[3] = 0;
        resp[2] = 0; // QR unset (a query, not a response)
        assert!(dns_response_ok(&resp, 0xabcd).is_err());
    }

    #[tokio::test]
    async fn dns_probe_against_local_server() {
        // Fake DNS server: echo the query id back with QR set, NOERROR.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            if let Ok((n, peer)) = server.recv_from(&mut buf).await {
                let mut resp = vec![0u8; 12];
                resp[0] = buf[0];
                resp[1] = buf[1];
                resp[2] = 0x80;
                resp.extend_from_slice(&buf[12..n]); // echo the question
                let _ = server.send_to(&resp, peer).await;
            }
        });
        let outcome = dns_probe(&ProbeSpec {
            kind: ProbeKind::Dns,
            target: "127.0.0.1".into(),
            port: Some(addr.port()),
            expect: Some("example.com".into()),
            timeout_ms: 1000,
        })
        .await;
        assert!(outcome.success, "error: {:?}", outcome.error);
        assert!(outcome.rtt_ms.unwrap() >= 0.0);
    }

    #[tokio::test]
    async fn dns_probe_timeout_on_silent_server() {
        // Bound socket that never answers.
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        let outcome = dns_probe(&ProbeSpec {
            kind: ProbeKind::Dns,
            target: "127.0.0.1".into(),
            port: Some(port),
            expect: None,
            timeout_ms: 200,
        })
        .await;
        assert!(!outcome.success);
        assert_eq!(outcome.error.as_deref(), Some("timeout"));
    }

    async fn spawn_http_server(status_line: &'static str) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let resp = format!("HTTP/1.1 {status_line}\r\ncontent-length: 0\r\n\r\n");
                let _ = sock.write_all(resp.as_bytes()).await;
            }
        });
        port
    }

    #[tokio::test]
    async fn http_probe_matches_expected_code() {
        let port = spawn_http_server("200 OK").await;
        let outcome = http_probe(&ProbeSpec {
            kind: ProbeKind::Http,
            target: format!("127.0.0.1:{port}"),
            port: None,
            expect: None,
            timeout_ms: 2000,
        })
        .await;
        assert!(outcome.success, "error: {:?}", outcome.error);
        assert!(outcome.rtt_ms.unwrap() >= 0.0);
    }

    #[tokio::test]
    async fn http_probe_rejects_unexpected_code() {
        let port = spawn_http_server("500 Internal Server Error").await;
        let outcome = http_probe(&ProbeSpec {
            kind: ProbeKind::Http,
            target: format!("127.0.0.1:{port}"),
            port: None,
            expect: None,
            timeout_ms: 2000,
        })
        .await;
        assert!(!outcome.success);
        assert_eq!(outcome.error.as_deref(), Some("got 500, want 200"));
    }
}
