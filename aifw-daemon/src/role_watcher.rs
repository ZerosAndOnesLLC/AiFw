//! Polls `ifconfig` every 1s for CARP role transitions and notifies the API
//! to emit a ClusterEvent::RoleChanged so WS subscribers (and any future
//! in-process consumers) react promptly.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

pub struct RoleWatcher {
    api_base: String,
    api_key: String,
    auth_warned: AtomicBool,
}

impl RoleWatcher {
    pub fn new(api_base: String, api_key: String) -> Self {
        Self {
            api_base,
            api_key,
            auth_warned: AtomicBool::new(false),
        }
    }

    pub async fn run(self) {
        let mut last_role: Option<String> = None;
        let mut tick = tokio::time::interval(Duration::from_secs(1));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        let client = match reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .timeout(Duration::from_secs(5))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(error = %e, "ha: role_watcher failed to build http client; aborting");
                return;
            }
        };

        loop {
            tick.tick().await;
            let role = current_carp_role().await;
            if last_role.as_deref() != Some(&role) {
                if let Some(prev) = &last_role {
                    // Convert raw ifconfig role strings ("master"/"backup") to
                    // canonical ClusterRole vocabulary ("primary"/"secondary") so
                    // audit history and WS event consumers see one vocabulary.
                    let from_canon = aifw_common::ClusterRole::parse(prev)
                        .map(|r| r.to_string())
                        .unwrap_or_else(|_| prev.clone());
                    let to_canon = aifw_common::ClusterRole::parse(&role)
                        .map(|r| r.to_string())
                        .unwrap_or_else(|_| role.clone());
                    let body =
                        serde_json::json!({"from": from_canon, "to": to_canon, "vhid": 0u8});
                    let url =
                        format!("{}/api/v1/cluster/internal/role-changed", self.api_base);
                    match client
                        .post(&url)
                        .header(
                            "Authorization",
                            format!("ApiKey {}", self.api_key),
                        )
                        .json(&body)
                        .send()
                        .await
                    {
                        Ok(r) if r.status().is_success() => {}
                        Ok(r) if r.status().as_u16() == 401 => {
                            if !self.auth_warned.swap(true, Ordering::Relaxed) {
                                tracing::warn!(
                                    "ha: role_watcher loopback auth failed \
                                     (AIFW_LOOPBACK_API_KEY set but not registered)"
                                );
                            }
                        }
                        Ok(r) => {
                            tracing::debug!(
                                status = ?r.status(),
                                "ha: role_watcher post non-success"
                            );
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "ha: role_watcher post failed");
                        }
                    }
                }
                last_role = Some(role);
            }
        }
    }
}

/// Look for "carp: MASTER" or "carp: BACKUP" in `ifconfig`. Returns
/// lowercase "master" / "backup" (matching what cluster_status etc. surface)
/// or "unknown" if neither is observed (e.g. on Linux, or before pfsync
/// initializes).
pub(crate) async fn current_carp_role() -> String {
    let out = tokio::process::Command::new("sh")
        .arg("-c")
        .arg("ifconfig 2>/dev/null | awk '/carp:/ {print tolower($2); exit}'")
        .output()
        .await;
    match out {
        Ok(o) if o.status.success() => {
            let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if s.is_empty() {
                "unknown".into()
            } else {
                s
            }
        }
        _ => "unknown".into(),
    }
}
