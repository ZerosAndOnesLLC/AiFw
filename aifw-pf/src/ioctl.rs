// FreeBSD pf backend using pfctl CLI commands
// Bridges to pfctl until raw /dev/pf ioctl is implemented

use crate::backend::PfBackend;
use crate::error::PfError;
use crate::types::{PfState, PfStats, PfTableEntry};
use async_trait::async_trait;
use std::net::IpAddr;
use tokio::process::Command;

pub struct PfIoctl;

impl PfIoctl {
    pub fn new() -> Result<Self, PfError> {
        Ok(Self)
    }
}

impl Drop for PfIoctl {
    fn drop(&mut self) {}
}

async fn pfctl(args: &[&str]) -> Result<String, PfError> {
    let output = Command::new("pfctl")
        .args(args)
        .output()
        .await
        .map_err(|e| PfError::DeviceOpen(format!("pfctl exec failed: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // pfctl often writes info to stderr even on success, only error on real failures
        if stderr.contains("ERROR") || stderr.contains("syntax error") {
            return Err(PfError::RuleLoad(stderr.to_string()));
        }
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

#[async_trait]
impl PfBackend for PfIoctl {
    async fn add_rule(&self, anchor: &str, rule: &str) -> Result<(), PfError> {
        let anchor_arg = format!("-a {anchor}");
        let output = Command::new("sh")
            .arg("-c")
            .arg(format!("echo '{}' | pfctl {anchor_arg} -f -", rule))
            .output()
            .await
            .map_err(|e| PfError::RuleLoad(format!("pfctl add_rule failed: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("syntax error") {
                return Err(PfError::RuleLoad(stderr.to_string()));
            }
        }
        Ok(())
    }

    async fn flush_rules(&self, anchor: &str) -> Result<(), PfError> {
        pfctl(&["-a", anchor, "-Fr"]).await?;
        Ok(())
    }

    async fn load_rules(&self, anchor: &str, rules: &[String]) -> Result<(), PfError> {
        if rules.is_empty() {
            return self.flush_rules(anchor).await;
        }
        let ruleset = rules.join("\n");
        let output = Command::new("sh")
            .arg("-c")
            .arg(format!("echo '{}' | pfctl -a {} -f -", ruleset, anchor))
            .output()
            .await
            .map_err(|e| PfError::RuleLoad(format!("pfctl load_rules failed: {e}")))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("syntax error") {
                return Err(PfError::RuleLoad(stderr.to_string()));
            }
        }
        Ok(())
    }

    async fn get_rules(&self, anchor: &str) -> Result<Vec<String>, PfError> {
        let out = pfctl(&["-a", anchor, "-sr"]).await?;
        Ok(out.lines().filter(|l| !l.is_empty()).map(String::from).collect())
    }

    async fn get_states(&self) -> Result<Vec<PfState>, PfError> {
        let out = pfctl(&["-ss"]).await?;
        let states: Vec<PfState> = out
            .lines()
            .filter(|l| !l.is_empty() && !l.starts_with("No "))
            .map(|line| PfState {
                id: 0,
                direction: String::new(),
                protocol: String::new(),
                src: line.to_string(),
                dst: String::new(),
                state: String::new(),
                age: 0,
                packets: 0,
                bytes: 0,
            })
            .collect();
        Ok(states)
    }

    async fn get_stats(&self) -> Result<PfStats, PfError> {
        let out = pfctl(&["-si"]).await.unwrap_or_default();
        let mut stats = PfStats::default();

        for line in out.lines() {
            let line = line.trim();
            if line.starts_with("Status:") {
                stats.running = line.contains("Enabled");
            }
            // Parse "current entries" for state count
            if line.contains("current entries") {
                if let Some(n) = line.split_whitespace().next() {
                    stats.states_count = n.parse().unwrap_or(0);
                }
            }
        }

        // Get rule count from anchor
        let rules_out = pfctl(&["-sr"]).await.unwrap_or_default();
        stats.rules_count = rules_out.lines().filter(|l| !l.is_empty()).count() as u64;

        Ok(stats)
    }

    async fn add_table_entry(&self, table: &str, addr: IpAddr) -> Result<(), PfError> {
        pfctl(&["-t", table, "-T", "add", &addr.to_string()]).await?;
        Ok(())
    }

    async fn remove_table_entry(&self, table: &str, addr: IpAddr) -> Result<(), PfError> {
        pfctl(&["-t", table, "-T", "delete", &addr.to_string()]).await?;
        Ok(())
    }

    async fn flush_table(&self, table: &str) -> Result<(), PfError> {
        pfctl(&["-t", table, "-T", "flush"]).await?;
        Ok(())
    }

    async fn get_table_entries(&self, table: &str) -> Result<Vec<PfTableEntry>, PfError> {
        let out = pfctl(&["-t", table, "-T", "show"]).await?;
        let entries: Vec<PfTableEntry> = out
            .lines()
            .filter_map(|line| {
                let line = line.trim();
                if line.is_empty() { return None; }
                let addr: IpAddr = line.split('/').next()?.parse().ok()?;
                let prefix: u8 = line.split('/').nth(1).and_then(|p| p.parse().ok())
                    .unwrap_or(if addr.is_ipv4() { 32 } else { 128 });
                Some(PfTableEntry { addr, prefix, packets: 0, bytes: 0 })
            })
            .collect();
        Ok(entries)
    }

    async fn is_running(&self) -> Result<bool, PfError> {
        let out = pfctl(&["-si"]).await.unwrap_or_default();
        Ok(out.contains("Status: Enabled"))
    }

    async fn load_nat_rules(&self, anchor: &str, rules: &[String]) -> Result<(), PfError> {
        if rules.is_empty() {
            return self.flush_nat_rules(anchor).await;
        }
        let ruleset = rules.join("\n");
        let _ = Command::new("sh")
            .arg("-c")
            .arg(format!("echo '{}' | pfctl -a {} -N -f -", ruleset, anchor))
            .output()
            .await
            .map_err(|e| PfError::RuleLoad(format!("pfctl load_nat failed: {e}")))?;
        Ok(())
    }

    async fn get_nat_rules(&self, anchor: &str) -> Result<Vec<String>, PfError> {
        let out = pfctl(&["-a", anchor, "-sn"]).await?;
        Ok(out.lines().filter(|l| !l.is_empty()).map(String::from).collect())
    }

    async fn flush_nat_rules(&self, anchor: &str) -> Result<(), PfError> {
        pfctl(&["-a", anchor, "-Fn"]).await?;
        Ok(())
    }

    async fn load_queues(&self, anchor: &str, queues: &[String]) -> Result<(), PfError> {
        if queues.is_empty() {
            return self.flush_queues(anchor).await;
        }
        let ruleset = queues.join("\n");
        let _ = Command::new("sh")
            .arg("-c")
            .arg(format!("echo '{}' | pfctl -a {} -f -", ruleset, anchor))
            .output()
            .await
            .map_err(|e| PfError::RuleLoad(format!("pfctl load_queues failed: {e}")))?;
        Ok(())
    }

    async fn get_queues(&self, anchor: &str) -> Result<Vec<String>, PfError> {
        let out = pfctl(&["-a", anchor, "-sq"]).await?;
        Ok(out.lines().filter(|l| !l.is_empty()).map(String::from).collect())
    }

    async fn flush_queues(&self, anchor: &str) -> Result<(), PfError> {
        pfctl(&["-a", anchor, "-Fq"]).await?;
        Ok(())
    }
}
