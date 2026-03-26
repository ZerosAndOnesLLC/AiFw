use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::context::PluginContext;
use crate::hooks::{HookAction, HookEvent, HookEventData, HookPoint};
use crate::plugin::{Plugin, PluginConfig, PluginInfo};

/// Webhook notifier plugin — queues notifications for external delivery
/// when security-relevant events occur (blocks, new connections, etc.).
///
/// In production this would POST to an HTTP endpoint. For now it queues
/// the payloads in memory for testing/inspection.
pub struct WebhookPlugin {
    url: String,
    notifications: RwLock<Vec<WebhookNotification>>,
    notify_on_block: bool,
    notify_on_connection: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct WebhookNotification {
    pub timestamp: String,
    pub event_type: String,
    pub message: String,
    pub data: serde_json::Value,
}

impl WebhookPlugin {
    pub fn new() -> Self {
        Self {
            url: String::new(),
            notifications: RwLock::new(Vec::new()),
            notify_on_block: true,
            notify_on_connection: false,
        }
    }

    pub async fn get_notifications(&self) -> Vec<WebhookNotification> {
        self.notifications.read().await.clone()
    }

    pub async fn notification_count(&self) -> usize {
        self.notifications.read().await.len()
    }

    async fn queue_notification(&self, event_type: &str, message: &str, data: serde_json::Value) {
        let notif = WebhookNotification {
            timestamp: chrono::Utc::now().to_rfc3339(),
            event_type: event_type.to_string(),
            message: message.to_string(),
            data,
        };

        tracing::debug!(url = %self.url, event = %event_type, "webhook notification queued");
        self.notifications.write().await.push(notif);
    }
}

impl Default for WebhookPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for WebhookPlugin {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            name: "webhook-notifier".to_string(),
            version: "1.0.0".to_string(),
            description: "Sends webhook notifications for security events".to_string(),
            author: "AiFw".to_string(),
            hooks: vec![
                HookPoint::PostRule,
                HookPoint::ConnectionNew,
                HookPoint::LogEvent,
            ],
        }
    }

    async fn init(&mut self, config: &PluginConfig, _ctx: &PluginContext) -> Result<(), String> {
        self.url = config
            .get_str("url")
            .unwrap_or("http://localhost:9999/webhook")
            .to_string();
        self.notify_on_block = config.get_bool("notify_on_block").unwrap_or(true);
        self.notify_on_connection = config.get_bool("notify_on_connection").unwrap_or(false);

        tracing::info!(url = %self.url, "webhook plugin initialized");
        Ok(())
    }

    async fn on_hook(&self, event: &HookEvent, _ctx: &PluginContext) -> HookAction {
        match &event.data {
            HookEventData::Rule {
                action, src_ip, dst_ip, protocol, ..
            } => {
                if self.notify_on_block && action == "block" {
                    self.queue_notification(
                        "rule_block",
                        &format!("Blocked {:?} -> {:?} ({})", src_ip, dst_ip, protocol),
                        serde_json::json!({
                            "src_ip": src_ip,
                            "dst_ip": dst_ip,
                            "protocol": protocol,
                        }),
                    )
                    .await;
                }
            }
            HookEventData::Connection {
                src_ip, dst_ip, src_port, dst_port, protocol, ..
            } => {
                if self.notify_on_connection {
                    self.queue_notification(
                        "new_connection",
                        &format!("{}:{} -> {}:{} ({})", src_ip, src_port, dst_ip, dst_port, protocol),
                        serde_json::json!({
                            "src_ip": src_ip.to_string(),
                            "dst_ip": dst_ip.to_string(),
                            "src_port": src_port,
                            "dst_port": dst_port,
                            "protocol": protocol,
                        }),
                    )
                    .await;
                }
            }
            HookEventData::Log { action, details, .. } => {
                self.queue_notification(
                    "audit",
                    &format!("{}: {}", action, details),
                    serde_json::json!({
                        "action": action,
                        "details": details,
                    }),
                )
                .await;
            }
            _ => {}
        }

        HookAction::Continue
    }

    async fn shutdown(&mut self) -> Result<(), String> {
        let pending = self.notifications.read().await.len();
        tracing::info!(pending, "webhook plugin shutting down");
        Ok(())
    }
}
