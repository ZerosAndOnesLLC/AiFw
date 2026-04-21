//! Probe implementations for gateway health monitoring.
//!
//! All probe kinds share a common interface returning `ProbeOutcome`. To keep
//! workspace dependencies minimal we shell out to system tools (`ping`, `host`,
//! `curl`) instead of pulling in reqwest/hickory. TCP probes are pure tokio.

use std::time::{Duration, Instant};
use tokio::net::TcpStream;
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

async fn http_probe(spec: &ProbeSpec) -> ProbeOutcome {
    let url = if spec.target.starts_with("http") {
        spec.target.clone()
    } else {
        format!("http://{}", spec.target)
    };
    let timeout_secs = spec.timeout_ms.div_ceil(1000).max(1);
    let start = Instant::now();
    let result = Command::new("/usr/local/bin/curl")
        .args([
            "-sS",
            "-o",
            "/dev/null",
            "-w",
            "%{http_code}",
            "--max-time",
            &timeout_secs.to_string(),
            &url,
        ])
        .output()
        .await;
    match result {
        Ok(out) if out.status.success() => {
            let code_str = String::from_utf8_lossy(&out.stdout);
            let code = code_str.trim().parse::<u16>().unwrap_or(0);
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

async fn dns_probe(spec: &ProbeSpec) -> ProbeOutcome {
    let timeout_secs = spec.timeout_ms.div_ceil(1000).max(1);
    let start = Instant::now();
    let mut args = vec!["-W".to_string(), timeout_secs.to_string()];
    if let Some(p) = spec.port {
        args.push("-p".to_string());
        args.push(p.to_string());
    }
    args.push(spec.expect.clone().unwrap_or_else(|| "example.com".into()));
    args.push(spec.target.clone());
    let result = Command::new("/usr/bin/host").args(&args).output().await;
    match result {
        Ok(out) if out.status.success() => ProbeOutcome {
            success: true,
            rtt_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
            error: None,
        },
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
}
