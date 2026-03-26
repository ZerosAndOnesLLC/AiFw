use async_trait::async_trait;
use std::collections::HashSet;
use std::net::IpAddr;
use tokio::sync::RwLock;

use crate::context::PluginContext;
use crate::hooks::{HookAction, HookEvent, HookEventData, HookPoint};
use crate::plugin::{Plugin, PluginConfig, PluginInfo};

/// IP Reputation plugin — maintains a blocklist of known-bad IPs
/// and blocks connections from them at the PreRule hook.
pub struct IpReputationPlugin {
    blocklist: RwLock<HashSet<IpAddr>>,
    table_name: String,
}

impl IpReputationPlugin {
    pub fn new() -> Self {
        Self {
            blocklist: RwLock::new(HashSet::new()),
            table_name: "ip_reputation".to_string(),
        }
    }

    /// Add an IP to the reputation blocklist
    pub async fn add_bad_ip(&self, ip: IpAddr) {
        self.blocklist.write().await.insert(ip);
    }

    /// Check if an IP is in the blocklist
    pub async fn is_blocked(&self, ip: IpAddr) -> bool {
        self.blocklist.read().await.contains(&ip)
    }

    pub async fn blocklist_size(&self) -> usize {
        self.blocklist.read().await.len()
    }
}

impl Default for IpReputationPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for IpReputationPlugin {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            name: "ip-reputation".to_string(),
            version: "1.0.0".to_string(),
            description: "Blocks connections from known-bad IP addresses".to_string(),
            author: "AiFw".to_string(),
            hooks: vec![HookPoint::PreRule, HookPoint::ConnectionNew],
        }
    }

    async fn init(&mut self, config: &PluginConfig, _ctx: &PluginContext) -> Result<(), String> {
        if let Some(table) = config.get_str("table_name") {
            self.table_name = table.to_string();
        }

        // Load any pre-configured blocked IPs from config
        if let Some(ips) = config.settings.get("blocklist") {
            if let Some(arr) = ips.as_array() {
                let mut blocklist = self.blocklist.write().await;
                for v in arr {
                    if let Some(s) = v.as_str() {
                        if let Ok(ip) = s.parse::<IpAddr>() {
                            blocklist.insert(ip);
                        }
                    }
                }
            }
        }

        let bl_size = self.blocklist.read().await.len();
        tracing::info!(
            table = %self.table_name,
            blocklist_size = bl_size,
            "IP reputation plugin initialized"
        );
        Ok(())
    }

    async fn on_hook(&self, event: &HookEvent, ctx: &PluginContext) -> HookAction {
        match &event.data {
            HookEventData::Rule { src_ip: Some(ip), .. }
            | HookEventData::Connection { src_ip: ip, .. } => {
                if self.is_blocked(*ip).await {
                    tracing::warn!(%ip, "blocked by IP reputation");
                    // Also add to pf table for kernel-level blocking
                    let _ = ctx.add_to_table(&self.table_name, *ip).await;
                    return HookAction::Block;
                }
            }
            _ => {}
        }
        HookAction::Continue
    }

    async fn shutdown(&mut self) -> Result<(), String> {
        let size = self.blocklist.read().await.len();
        tracing::info!(blocklist_size = size, "IP reputation plugin shutting down");
        Ok(())
    }
}
