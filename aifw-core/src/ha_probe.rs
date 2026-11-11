//! HA health-check probes (ping / TCP / HTTP / pf / process), shared by the
//! daemon's HealthProber and the API's on-demand `POST /cluster/health/run`.

use aifw_common::{HealthCheck, HealthCheckType};
use std::time::Duration;

/// Run one probe for `c`; `client` is used for HTTP checks.
pub async fn run_probe(c: &HealthCheck, client: &reqwest::Client) -> bool {
    match c.check_type {
        HealthCheckType::Ping => probe_ping(&c.target).await,
        HealthCheckType::TcpPort => probe_tcp(&c.target, c.timeout_secs).await,
        HealthCheckType::HttpGet => probe_http(client, &c.target, c.timeout_secs).await,
        HealthCheckType::PfStatus => probe_pf().await,
        HealthCheckType::ProcessRunning => probe_process(&c.target).await,
    }
}

async fn probe_ping(target: &str) -> bool {
    tokio::process::Command::new("ping")
        .args(["-c", "1", "-W", "1000", target])
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

async fn probe_tcp(target: &str, timeout_secs: u32) -> bool {
    use tokio::net::TcpStream;
    use tokio::time::timeout;
    timeout(
        Duration::from_secs(timeout_secs as u64),
        TcpStream::connect(target),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false)
}

async fn probe_http(client: &reqwest::Client, target: &str, timeout_secs: u32) -> bool {
    // Use per-request timeout so the shared client's pool settings don't interfere.
    match client
        .get(target)
        .timeout(Duration::from_secs(timeout_secs as u64))
        .send()
        .await
    {
        Ok(r) => r.status().is_success(),
        Err(_) => false,
    }
}

async fn probe_pf() -> bool {
    tokio::process::Command::new("pfctl")
        .arg("-si")
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Check that a named process is running via `pgrep -x <name>`.
/// `pgrep -x` matches against the exact process name (not the full command line).
async fn probe_process(process_name: &str) -> bool {
    tokio::process::Command::new("pgrep")
        .arg("-x")
        .arg(process_name)
        .output()
        .await
        .map(|o| o.status.success())
        .unwrap_or(false)
}
