use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::context::PluginContext;
use crate::hooks::{HookAction, HookEvent, HookEventData, HookPoint};
use crate::plugin::{Plugin, PluginConfig, PluginInfo};

/// Custom logging plugin — captures all hook events and stores them
/// in an in-memory buffer for inspection.
pub struct LoggingPlugin {
    log_buffer: RwLock<Vec<LogEntry>>,
    max_entries: usize,
}

#[derive(Debug, Clone)]
pub struct LogEntry {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub hook: HookPoint,
    pub message: String,
}

impl LoggingPlugin {
    pub fn new() -> Self {
        Self {
            log_buffer: RwLock::new(Vec::new()),
            max_entries: 10000,
        }
    }

    pub async fn get_entries(&self) -> Vec<LogEntry> {
        self.log_buffer.read().await.clone()
    }

    pub async fn entry_count(&self) -> usize {
        self.log_buffer.read().await.len()
    }

    async fn append(&self, hook: HookPoint, message: String) {
        let mut buf = self.log_buffer.write().await;
        if buf.len() >= self.max_entries {
            buf.remove(0);
        }
        buf.push(LogEntry {
            timestamp: chrono::Utc::now(),
            hook,
            message,
        });
    }
}

impl Default for LoggingPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for LoggingPlugin {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            name: "custom-logger".to_string(),
            version: "1.0.0".to_string(),
            description: "Captures all hook events to an in-memory log buffer".to_string(),
            author: "AiFw".to_string(),
            hooks: vec![
                HookPoint::PreRule,
                HookPoint::PostRule,
                HookPoint::ConnectionNew,
                HookPoint::ConnectionClosed,
                HookPoint::LogEvent,
            ],
        }
    }

    async fn init(&mut self, config: &PluginConfig, _ctx: &PluginContext) -> Result<(), String> {
        if let Some(max) = config.get_u64("max_entries") {
            self.max_entries = max as usize;
        }
        tracing::info!(max_entries = self.max_entries, "logging plugin initialized");
        Ok(())
    }

    async fn on_hook(&self, event: &HookEvent, _ctx: &PluginContext) -> HookAction {
        let msg = match &event.data {
            HookEventData::Rule {
                src_ip, dst_ip, protocol, action, ..
            } => {
                format!(
                    "rule: {} {:?} -> {:?} proto={}",
                    action,
                    src_ip,
                    dst_ip,
                    protocol
                )
            }
            HookEventData::Connection {
                src_ip, dst_ip, src_port, dst_port, protocol, state,
            } => {
                format!(
                    "conn: {}:{} -> {}:{} proto={} state={}",
                    src_ip, src_port, dst_ip, dst_port, protocol, state
                )
            }
            HookEventData::Log { action, details, source } => {
                format!("log: {} - {} ({})", action, details, source)
            }
            HookEventData::Api { method, path, .. } => {
                format!("api: {} {}", method, path)
            }
        };

        self.append(event.hook, msg).await;
        HookAction::Continue
    }

    async fn shutdown(&mut self) -> Result<(), String> {
        let count = self.log_buffer.read().await.len();
        tracing::info!(entries = count, "logging plugin shutting down");
        Ok(())
    }
}
