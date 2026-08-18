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

        // #317: loopback calls are pinned to the local API certificate.
        let loopback = aifw_core::peer_tls::LocalApiClient::new(Duration::from_secs(5));

        loop {
            tick.tick().await;
            let role = current_carp_role().await;
            if last_role.as_deref() != Some(&role) {
                if let Some(prev) = &last_role {
                    // Convert raw ifconfig role strings ("master"/"backup") to
                    // canonical ClusterRole vocabulary ("primary"/"secondary") so
                    // audit history and WS event consumers see one vocabulary.
                    let from_canon = canonical_role(prev);
                    let to_canon = canonical_role(&role);
                    let body = serde_json::json!({"from": from_canon, "to": to_canon, "vhid": 0u8});
                    let url = format!("{}/api/v1/cluster/internal/role-changed", self.api_base);
                    let client = match loopback.get() {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!(error = %e, "ha: role_watcher http client");
                            continue;
                        }
                    };
                    match client
                        .post(&url)
                        .header("Authorization", format!("ApiKey {}", self.api_key))
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
    let out = tokio::process::Command::new("ifconfig").output().await;
    match out {
        Ok(o) if o.status.success() => carp_role_from_ifconfig(&String::from_utf8_lossy(&o.stdout)),
        _ => "unknown".into(),
    }
}

/// Pure parse of `ifconfig` output: the state of the first `carp:` line
/// (`carp: MASTER vhid 1 advbase 1 advskew 0`), lower-cased; "unknown"
/// when no CARP interface is present.
pub(crate) fn carp_role_from_ifconfig(out: &str) -> String {
    out.lines()
        .find_map(|l| {
            let t = l.trim_start();
            t.strip_prefix("carp:")
                .and_then(|rest| rest.split_whitespace().next())
                .map(|s| s.to_ascii_lowercase())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Canonical (`primary`/`secondary`) form of a raw ifconfig role, falling
/// back to the raw string when it isn't a known CARP state — this is what
/// the role-changed event carries so audit history uses one vocabulary.
pub(crate) fn canonical_role(raw: &str) -> String {
    aifw_common::ClusterRole::parse(raw)
        .map(|r| r.to_string())
        .unwrap_or_else(|_| raw.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_first_carp_state_from_ifconfig() {
        let out = "em0: flags=8863<UP> metric 0 mtu 1500\n\
                   \tinet 192.0.2.2 netmask 0xffffff00\n\
                   \tinet 192.0.2.1 netmask 0xffffffff vhid 1\n\
                   \tcarp: MASTER vhid 1 advbase 1 advskew 0\n\
                   em1: flags=8863<UP>\n\
                   \tcarp: BACKUP vhid 2 advbase 1 advskew 100\n";
        assert_eq!(carp_role_from_ifconfig(out), "master");
        assert_eq!(
            carp_role_from_ifconfig("lo0: flags=8049<UP,LOOPBACK>\n"),
            "unknown"
        );
        assert_eq!(carp_role_from_ifconfig(""), "unknown");
        assert_eq!(carp_role_from_ifconfig("\tcarp: INIT vhid 3\n"), "init");
    }

    #[test]
    fn role_change_events_use_canonical_vocabulary() {
        assert_eq!(canonical_role("master"), "primary");
        assert_eq!(canonical_role("backup"), "secondary");
        // Unknown states pass through untouched rather than being guessed.
        assert_eq!(canonical_role("init"), "init");
        assert_eq!(canonical_role("unknown"), "unknown");
    }
}
