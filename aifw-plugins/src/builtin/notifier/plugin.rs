use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use tokio::task::JoinSet;

use super::channels::{self, Channel};
use super::limiter::{Limiter, Verdict};
use super::message::{Filter, Notification, classify, test_notification};
use crate::context::PluginContext;
use crate::error::{PluginError, Result};
use crate::hooks::{HookAction, HookEvent, HookPoint};
use crate::http;
use crate::plugin::{ActionInfo, Plugin, PluginInfo};
use crate::schema::{PluginSettings, SelectOption, SettingField};

const NAME: &str = "notifier";
const QUEUE: usize = 256;
const SEND_TIMEOUT: Duration = Duration::from_secs(15);

/// Audit actions an operator can choose to be notified about.
const AUDIT_ACTIONS: &[(&str, &str)] = &[
    ("rules_applied", "Rules applied"),
    ("rules_flushed", "Rules flushed"),
    ("rule_added", "Rule added"),
    ("rule_updated", "Rule updated"),
    ("rule_removed", "Rule removed"),
    ("config_changed", "Other configuration change"),
    ("daemon_started", "Firewall daemon started"),
    ("daemon_stopped", "Firewall daemon stopped"),
];

#[derive(Debug, Clone, Default, Serialize)]
struct ChannelStats {
    sent: u64,
    failed: u64,
    last_error: Option<String>,
    last_sent_at: Option<DateTime<Utc>>,
}

#[derive(Default)]
struct Stats {
    channels: BTreeMap<&'static str, ChannelStats>,
    dropped_queue_full: u64,
    duplicates: u64,
    rate_limited: u64,
    last: Option<(String, DateTime<Utc>)>,
}

struct Shared {
    tx: mpsc::Sender<Notification>,
    stats: Mutex<Stats>,
    filter: Filter,
    channels: Vec<Channel>,
    client: reqwest::Client,
    host: String,
    allow_private: bool,
}

impl Shared {
    fn stats(&self) -> MutexGuard<'_, Stats> {
        self.stats.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Send `n` to `targets` concurrently; record per-channel outcomes.
    /// Returns the failures.
    async fn deliver(self: &Arc<Self>, n: &Notification, targets: &[Channel]) -> Vec<String> {
        let mut set = JoinSet::new();
        for ch in targets {
            let ch = ch.clone();
            let me = self.clone();
            let n = n.clone();
            set.spawn(async move {
                let r = channels::send(&me.client, &ch, &n, &me.host, me.allow_private).await;
                (ch.id(), r)
            });
        }
        let mut failures = Vec::new();
        while let Some(joined) = set.join_next().await {
            let Ok((id, r)) = joined else { continue };
            let mut stats = self.stats();
            let s = stats.channels.entry(id).or_default();
            match r {
                Ok(()) => {
                    s.sent += 1;
                    s.last_sent_at = Some(Utc::now());
                    s.last_error = None;
                }
                Err(e) => {
                    s.failed += 1;
                    s.last_error = Some(e.to_string());
                    failures.push(e.to_string());
                }
            }
        }
        self.stats().last = Some((n.title.clone(), n.at));
        failures
    }
}

/// The Notifier plugin: pushes IDS alerts, gateway and VPN changes, and
/// selected configuration changes to ntfy, Discord, Slack, Telegram, or a
/// signed JSON webhook.
#[derive(Default)]
pub struct Notifier {
    shared: Option<Arc<Shared>>,
}

impl Notifier {
    /// A fresh, un-initialized instance (registry factory).
    pub fn boxed() -> Box<dyn Plugin> {
        Box::new(Self::default())
    }

    fn shared(&self) -> Result<&Arc<Shared>> {
        self.shared
            .as_ref()
            .ok_or_else(|| PluginError::Plugin("not initialized".into()))
    }
}

/// Channels the operator configured.
fn configured_channels(s: &PluginSettings) -> Vec<Channel> {
    let mut out = Vec::new();
    if let Some(url) = s.str("ntfy_url") {
        out.push(Channel::Ntfy {
            url: url.to_string(),
            token: s.str("ntfy_token").map(str::to_string),
        });
    }
    if let Some(url) = s.str("discord_webhook") {
        out.push(Channel::Discord {
            url: url.to_string(),
        });
    }
    if let Some(url) = s.str("slack_webhook") {
        out.push(Channel::Slack {
            url: url.to_string(),
        });
    }
    if let (Some(token), Some(chat_id)) = (s.str("telegram_bot_token"), s.str("telegram_chat_id")) {
        out.push(Channel::Telegram {
            token: token.to_string(),
            chat_id: chat_id.to_string(),
        });
    }
    if let Some(url) = s.str("webhook_url") {
        out.push(Channel::Webhook {
            url: url.to_string(),
            secret: s.str("webhook_secret").map(str::to_string),
        });
    }
    out
}

fn filter(s: &PluginSettings) -> Filter {
    Filter {
        ids: s.bool("notify_ids"),
        ids_max_severity: s
            .str("ids_min_severity")
            .and_then(|v| v.parse().ok())
            .unwrap_or(2),
        gateway: s.bool("notify_gateway"),
        vpn: s.bool("notify_vpn"),
        config: s.bool("notify_config"),
        config_actions: s.strings("config_actions"),
    }
}

async fn hostname() -> String {
    let out = tokio::time::timeout(
        Duration::from_secs(2),
        tokio::process::Command::new("hostname").output(),
    )
    .await;
    match out {
        Ok(Ok(o)) if o.status.success() => {
            let h = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if h.is_empty() { "aifw".into() } else { h }
        }
        _ => "aifw".into(),
    }
}

/// Drain the queue: dedupe, rate-limit, deliver.
async fn worker(
    shared: Arc<Shared>,
    mut rx: mpsc::Receiver<Notification>,
    mut limiter: Limiter,
    ctx: PluginContext,
) {
    let mut last_limit_warning: Option<Instant> = None;
    while let Some(n) = rx.recv().await {
        match limiter.check(&n.dedupe_key, Instant::now()) {
            Verdict::Send => {
                for failure in shared.deliver(&n, &shared.channels).await {
                    ctx.warn(format!("delivery failed: {failure}"));
                }
            }
            Verdict::Duplicate => shared.stats().duplicates += 1,
            Verdict::RateLimited => {
                shared.stats().rate_limited += 1;
                if last_limit_warning.is_none_or(|t| t.elapsed() > Duration::from_secs(60)) {
                    ctx.warn("rate limit reached; dropping notifications for now");
                    last_limit_warning = Some(Instant::now());
                }
            }
        }
    }
}

#[async_trait]
impl Plugin for Notifier {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            name: NAME.to_string(),
            title: "Notifier".to_string(),
            version: "1.0.0".to_string(),
            description: "Sends IDS alerts, gateway and VPN outages, and configuration changes \
                          to ntfy, Discord, Slack, Telegram, or your own webhook."
                .to_string(),
            author: "AiFw".to_string(),
            hooks: vec![
                HookPoint::IdsAlert,
                HookPoint::GatewayEvent,
                HookPoint::VpnEvent,
                HookPoint::LogEvent,
            ],
        }
    }

    fn settings_schema(&self) -> Vec<SettingField> {
        let severities = vec![
            SelectOption::new("1", "Critical only"),
            SelectOption::new("2", "High and above"),
            SelectOption::new("3", "Medium and above"),
            SelectOption::new("4", "Everything"),
        ];
        let audit = AUDIT_ACTIONS
            .iter()
            .map(|(v, l)| SelectOption::new(v, l))
            .collect();
        vec![
            // Channels
            SettingField::url("ntfy_url", "ntfy topic URL", false)
                .secret()
                .help("For example https://ntfy.sh/your-random-topic — the topic name works like a password.")
                .group("ntfy"),
            SettingField::text("ntfy_token", "ntfy access token", 256)
                .secret()
                .help("Only for protected topics or self-hosted servers.")
                .group("ntfy"),
            SettingField::url("discord_webhook", "Discord webhook URL", true)
                .secret()
                .help("Server Settings → Integrations → Webhooks → Copy Webhook URL.")
                .group("Discord"),
            SettingField::url("slack_webhook", "Slack webhook URL", true)
                .secret()
                .help("An Incoming Webhook URL from your Slack app.")
                .group("Slack"),
            SettingField::text("telegram_bot_token", "Telegram bot token", 128)
                .secret()
                .help("From @BotFather.")
                .group("Telegram"),
            SettingField::text("telegram_chat_id", "Telegram chat ID", 64)
                .help("The chat, group or channel to post to.")
                .group("Telegram"),
            SettingField::url("webhook_url", "Webhook URL", false)
                .secret()
                .help("Receives a JSON POST for every notification.")
                .group("Webhook"),
            SettingField::text("webhook_secret", "Signing secret", 256)
                .secret()
                .help("When set, requests carry X-AiFw-Signature: sha256=<HMAC-SHA256 of the body>.")
                .group("Webhook"),
            // Events
            SettingField::bool("notify_ids", "IDS alerts", true).group("Events"),
            SettingField::select("ids_min_severity", "IDS severity", severities, "2")
                .visible_if("notify_ids", true)
                .group("Events"),
            SettingField::bool("notify_gateway", "Gateway down / degraded / recovered", true)
                .group("Events"),
            SettingField::bool("notify_vpn", "VPN tunnel or peer up / down", true)
                .help("WireGuard peers count as down after 3 minutes without a handshake.")
                .group("Events"),
            SettingField::bool("notify_config", "Configuration changes", false)
                .group("Events"),
            SettingField::multi_select(
                "config_actions",
                "Which changes",
                audit,
                &["rules_applied", "rules_flushed", "daemon_stopped"],
            )
            .visible_if("notify_config", true)
            .group("Events"),
            // Delivery
            SettingField::integer("rate_limit_per_minute", "Max notifications per minute", 1, 120, 10)
                .help("Extra notifications in a burst are dropped and counted.")
                .group("Delivery"),
            SettingField::integer("dedupe_minutes", "Suppress repeats for (minutes)", 0, 1440, 10)
                .help("The same alert from the same source is sent once per window. 0 turns this off.")
                .group("Delivery"),
            SettingField::bool("allow_private_destinations", "Allow LAN / http destinations", false)
                .help("Needed for a self-hosted ntfy or webhook on your network. Leave off otherwise.")
                .group("Delivery"),
        ]
    }

    fn validate_settings(&self, s: &PluginSettings) -> Result<()> {
        if s.str("telegram_bot_token").is_some() != s.str("telegram_chat_id").is_some() {
            return Err(PluginError::Validation(
                "Telegram needs both a bot token and a chat ID.".into(),
            ));
        }
        if configured_channels(s).is_empty() {
            return Err(PluginError::Validation(
                "Configure at least one channel (ntfy, Discord, Slack, Telegram or webhook)."
                    .into(),
            ));
        }
        let f = filter(s);
        if !(f.ids || f.gateway || f.vpn || f.config) {
            return Err(PluginError::Validation(
                "Turn on at least one kind of event.".into(),
            ));
        }
        Ok(())
    }

    fn actions(&self) -> Vec<ActionInfo> {
        let options = vec![
            SelectOption::new("all", "All configured channels"),
            SelectOption::new("ntfy", "ntfy"),
            SelectOption::new("discord", "Discord"),
            SelectOption::new("slack", "Slack"),
            SelectOption::new("telegram", "Telegram"),
            SelectOption::new("webhook", "Webhook"),
        ];
        vec![
            ActionInfo::new(
                "test",
                "Send test",
                "Send a test notification right away (ignores rate limits).",
            )
            .arg(SettingField::select("channel", "Channel", options, "all")),
        ]
    }

    async fn init(&mut self, s: &PluginSettings, ctx: &PluginContext) -> Result<()> {
        let allow_private = s.bool("allow_private_destinations");
        let (tx, rx) = mpsc::channel(QUEUE);
        let channels = configured_channels(s);
        let shared = Arc::new(Shared {
            tx,
            stats: Mutex::new(Stats::default()),
            filter: filter(s),
            client: http::client(NAME, SEND_TIMEOUT, allow_private)?,
            host: hostname().await,
            allow_private,
            channels: channels.clone(),
        });
        let limiter = Limiter::new(
            s.i64("rate_limit_per_minute")
                .and_then(|v| u32::try_from(v).ok())
                .unwrap_or(10),
            Duration::from_secs(60 * s.i64("dedupe_minutes").unwrap_or(10).max(0) as u64),
            Instant::now(),
        );
        ctx.spawn(worker(shared.clone(), rx, limiter, ctx.clone()));
        let names: Vec<&str> = channels.iter().map(Channel::id).collect();
        ctx.info(format!("delivering to {}", names.join(", ")));
        self.shared = Some(shared);
        Ok(())
    }

    async fn on_hook(&self, event: &HookEvent, _ctx: &PluginContext) -> HookAction {
        let Ok(shared) = self.shared() else {
            return HookAction::Continue;
        };
        if let Some(n) = classify(event, &shared.filter)
            && shared.tx.try_send(n).is_err()
        {
            shared.stats().dropped_queue_full += 1;
        }
        HookAction::Continue
    }

    async fn run_action(&self, action: &str, args: Value, _ctx: &PluginContext) -> Result<Value> {
        if action != "test" {
            return Err(PluginError::NotFound(format!("action '{action}'")));
        }
        let shared = self.shared()?;
        let which = args["channel"].as_str().unwrap_or("all");
        let targets: Vec<Channel> = shared
            .channels
            .iter()
            .filter(|c| which == "all" || c.id() == which)
            .cloned()
            .collect();
        if targets.is_empty() {
            return Err(PluginError::Validation(format!(
                "{which} is not configured"
            )));
        }
        let failures = shared.deliver(&test_notification(), &targets).await;
        if failures.is_empty() {
            let sent: Vec<&str> = targets.iter().map(Channel::id).collect();
            Ok(json!({"sent": sent}))
        } else {
            Err(PluginError::Plugin(failures.join("; ")))
        }
    }

    async fn status(&self, _ctx: &PluginContext) -> Value {
        let Ok(shared) = self.shared() else {
            return Value::Null;
        };
        let stats = shared.stats();
        let channels: Vec<Value> = shared
            .channels
            .iter()
            .map(|c| {
                let s = stats.channels.get(c.id()).cloned().unwrap_or_default();
                json!({
                    "id": c.id(),
                    "sent": s.sent,
                    "failed": s.failed,
                    "last_error": s.last_error,
                    "last_sent_at": s.last_sent_at,
                })
            })
            .collect();
        json!({
            "channels": channels,
            "queue_depth": QUEUE - shared.tx.capacity(),
            "dropped_queue_full": stats.dropped_queue_full,
            "duplicates": stats.duplicates,
            "rate_limited": stats.rate_limited,
            "last_notification": stats.last.as_ref().map(|(t, at)| json!({"title": t, "at": at})),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema;

    fn settings(values: Value, secrets: Value) -> std::result::Result<PluginSettings, PluginError> {
        let schema = Notifier::default().settings_schema();
        let (v, s) = schema::normalize(
            &schema,
            values.as_object().unwrap(),
            secrets.as_object().unwrap(),
        )?;
        Ok(schema::effective(&schema, &v, &s))
    }

    #[test]
    fn requires_a_channel_and_complete_telegram() {
        let p = Notifier::default();
        let none = settings(json!({}), json!({})).unwrap();
        assert!(p.validate_settings(&none).is_err());

        let half_tg = settings(json!({}), json!({"telegram_bot_token": "1:a"})).unwrap();
        assert!(
            p.validate_settings(&half_tg)
                .unwrap_err()
                .to_string()
                .contains("Telegram")
        );

        let ok = settings(json!({}), json!({"ntfy_url": "https://ntfy.sh/x"})).unwrap();
        p.validate_settings(&ok).unwrap();
        assert_eq!(configured_channels(&ok).len(), 1);
    }

    #[test]
    fn channel_urls_must_be_secrets() {
        assert!(
            settings(
                json!({"discord_webhook": "https://discord.com/api/webhooks/x"}),
                json!({})
            )
            .is_err()
        );
        assert!(settings(json!({}), json!({"discord_webhook": "http://insecure"})).is_err());
    }

    #[test]
    fn needs_some_event() {
        let p = Notifier::default();
        let s = settings(
            json!({"notify_ids": false, "notify_gateway": false, "notify_vpn": false}),
            json!({"slack_webhook": "https://hooks.slack.com/services/x"}),
        )
        .unwrap();
        assert!(p.validate_settings(&s).is_err());
    }

    #[tokio::test]
    async fn test_action_reports_unconfigured_channel() {
        let db = aifw_core::Database::new_in_memory().await.unwrap();
        let pf: Arc<dyn aifw_pf::PfBackend> = Arc::new(aifw_pf::PfMock::new());
        let sink = Arc::new(crate::rules::RuleSink::new(pf.clone(), "aifw-plugins"));
        let ctx = PluginContext::new(NAME, pf, db.pool().clone(), sink);
        let s = settings(json!({}), json!({"ntfy_url": "https://ntfy.sh/x"})).unwrap();
        let mut p = Notifier::default();
        p.init(&s, &ctx).await.unwrap();
        let err = p
            .run_action("test", json!({"channel": "discord"}), &ctx)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("discord is not configured"));
        assert_eq!(p.status(&ctx).await["channels"][0]["id"], "ntfy");
    }
}
