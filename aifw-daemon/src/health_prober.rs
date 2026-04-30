//! Schedules health-check rows; on local failure, demotes CARP to trigger
//! failover. On recovery (after a hold-down window), re-enables election.

use aifw_common::{HealthCheck, HealthCheckType};
use aifw_core::ClusterEngine;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use uuid::Uuid;

const RECOVERY_HOLD_DOWN_SECS: u64 = 30;

pub struct HealthProber {
    engine: Arc<ClusterEngine>,
    api_base: String,
    api_key: String,
    auth_warned: AtomicBool,
}

impl HealthProber {
    pub fn new(engine: Arc<ClusterEngine>, api_base: String, api_key: String) -> Self {
        Self {
            engine,
            api_base,
            api_key,
            auth_warned: AtomicBool::new(false),
        }
    }

    pub async fn run(self) {
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut state: HashMap<Uuid, ProbeState> = HashMap::new();
        let mut demoted = false;
        let mut recovery_started: Option<Instant> = None;

        let client = match reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(5))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "ha: health_prober failed to build http client; aborting"
                );
                return;
            }
        };

        loop {
            tick.tick().await;

            let checks = match self.engine.list_health_checks().await {
                Ok(c) => c,
                Err(e) => {
                    tracing::debug!(error = %e, "ha: list_health_checks failed");
                    continue;
                }
            };

            let mut any_failing_local = false;

            for c in checks.iter().filter(|c| c.enabled) {
                let st = state.entry(c.id).or_insert_with(ProbeState::new);
                let ready = match st.last_run {
                    None => true,
                    Some(t) => t.elapsed() >= Duration::from_secs(c.interval_secs as u64),
                };
                if !ready {
                    if !st.healthy {
                        any_failing_local = true;
                    }
                    continue;
                }
                st.last_run = Some(Instant::now());

                let ok = run_probe(c).await;
                if ok {
                    if !st.healthy {
                        st.healthy = true;
                        let _ = self.notify_health(&client, &c.name, true, None).await;
                    }
                    st.failures = 0; // always reset so accumulated partial failures
                                     // don't carry over and reduce the effective threshold
                } else {
                    st.failures += 1;
                    if st.failures >= c.failures_before_down && st.healthy {
                        st.healthy = false;
                        let _ = self
                            .notify_health(
                                &client,
                                &c.name,
                                false,
                                Some(format!("{} consecutive failures", st.failures)),
                            )
                            .await;
                    }
                    if !st.healthy {
                        any_failing_local = true;
                    }
                }
            }

            if any_failing_local && !demoted {
                let demote_ok = tokio::process::Command::new("sysctl")
                    .arg("net.inet.carp.demotion=240")
                    .status()
                    .await
                    .map(|s| s.success())
                    .unwrap_or(false);
                if demote_ok {
                    demoted = true;
                    recovery_started = None;
                    tracing::warn!("ha: demoting CARP due to local health failure");
                } else {
                    tracing::warn!(
                        "ha: failed to set net.inet.carp.demotion=240 on health failure"
                    );
                }
            } else if any_failing_local && demoted {
                // re-failed during hold-down: restart the recovery clock so a single-tick
                // flap near the end of the window cannot prematurely restore CARP demotion
                if recovery_started.is_some() {
                    recovery_started = None;
                    tracing::debug!(
                        "ha: probe re-failed during hold-down; resetting recovery timer"
                    );
                }
            } else if !any_failing_local && demoted {
                let now = Instant::now();
                match recovery_started {
                    None => recovery_started = Some(now),
                    Some(started)
                        if now.duration_since(started)
                            >= Duration::from_secs(RECOVERY_HOLD_DOWN_SECS) =>
                    {
                        let restore_ok = tokio::process::Command::new("sysctl")
                            .arg("net.inet.carp.demotion=0")
                            .status()
                            .await
                            .map(|s| s.success())
                            .unwrap_or(false);
                        if restore_ok {
                            demoted = false;
                            recovery_started = None;
                            tracing::info!("ha: clearing CARP demotion after hold-down");
                        } else {
                            tracing::warn!(
                                "ha: failed to clear CARP demotion during recovery"
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    async fn notify_health(
        &self,
        client: &reqwest::Client,
        name: &str,
        healthy: bool,
        detail: Option<String>,
    ) -> anyhow::Result<()> {
        let body =
            serde_json::json!({"check": name, "healthy": healthy, "detail": detail});
        let url = format!(
            "{}/api/v1/cluster/internal/health-changed",
            self.api_base
        );
        let resp = client
            .post(&url)
            .header(
                "Authorization",
                format!("ApiKey {}", self.api_key),
            )
            .json(&body)
            .send()
            .await?;
        if resp.status().as_u16() == 401
            && !self.auth_warned.swap(true, Ordering::Relaxed)
        {
            tracing::warn!(
                "ha: health_prober loopback auth failed \
                 (AIFW_LOOPBACK_API_KEY set but not registered)"
            );
        }
        Ok(())
    }
}

struct ProbeState {
    healthy: bool,
    failures: u32,
    last_run: Option<Instant>,
}

impl ProbeState {
    fn new() -> Self {
        Self {
            healthy: true,
            failures: 0,
            last_run: None,
        }
    }
}

async fn run_probe(c: &HealthCheck) -> bool {
    match c.check_type {
        HealthCheckType::Ping => probe_ping(&c.target).await,
        HealthCheckType::TcpPort => probe_tcp(&c.target, c.timeout_secs).await,
        HealthCheckType::HttpGet => probe_http(&c.target, c.timeout_secs).await,
        HealthCheckType::PfStatus => probe_pf().await,
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

async fn probe_http(target: &str, timeout_secs: u32) -> bool {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs as u64))
        .danger_accept_invalid_certs(true)
        .build();
    match client {
        Ok(c) => c
            .get(target)
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false),
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
