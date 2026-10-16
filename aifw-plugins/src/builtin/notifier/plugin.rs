use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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
use crate::plugin::{ActionInfo, Plugin, PluginInfo, PluginInstance};
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

/// The settings exactly as the schema declares them. `effective` fills
/// every key, so defaults live only in [`Notifier::settings_schema`].
#[derive(Debug, Deserialize)]
struct Settings {
    ntfy_url: Option<String>,
    ntfy_token: Option<String>,
    discord_webhook: Option<String>,
    slack_webhook: Option<String>,
    telegram_bot_token: Option<String>,
    telegram_chat_id: Option<String>,
    webhook_url: Option<String>,
    webhook_secret: Option<String>,
    notify_ids: bool,
    ids_min_severity: String,
    notify_gateway: bool,
    notify_vpn: bool,
    notify_vpn_peers: bool,
    notify_config: bool,
    config_actions: Vec<String>,
    rate_limit_per_minute: u32,
    dedupe_minutes: u64,
    allow_private_destinations: bool,
}

/// Text settings come back as `""` when cleared; treat that as unset.
fn present(s: &Option<String>) -> Option<String> {
    s.as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

impl Settings {
    fn parse(s: &PluginSettings) -> Result<Self> {
        s.deserialize()
    }

    /// Channels the operator configured.
    fn channels(&self) -> Vec<Channel> {
        let mut out = Vec::new();
        if let Some(url) = present(&self.ntfy_url) {
            out.push(Channel::Ntfy {
                url,
                token: present(&self.ntfy_token),
            });
        }
        if let Some(url) = present(&self.discord_webhook) {
            out.push(Channel::Discord { url });
        }
        if let Some(url) = present(&self.slack_webhook) {
            out.push(Channel::Slack { url });
        }
        if let (Some(token), Some(chat_id)) = (
            present(&self.telegram_bot_token),
            present(&self.telegram_chat_id),
        ) {
            out.push(Channel::Telegram { token, chat_id });
        }
        if let Some(url) = present(&self.webhook_url) {
            out.push(Channel::Webhook {
                url,
                secret: present(&self.webhook_secret),
            });
        }
        out
    }

    fn filter(&self) -> Filter {
        Filter {
            ids: self.notify_ids,
            ids_max_severity: self.ids_min_severity.parse().unwrap_or(2),
            gateway: self.notify_gateway,
            vpn: self.notify_vpn,
            vpn_peers: self.notify_vpn_peers,
            config: self.notify_config,
            config_actions: self.config_actions.clone(),
        }
    }

    /// Only the hooks whose events the operator wants, so the other event
    /// sources (IDS tail, VPN poller, …) stay idle.
    fn hooks(&self) -> Vec<HookPoint> {
        let mut h = Vec::new();
        if self.notify_ids {
            h.push(HookPoint::IdsAlert);
        }
        if self.notify_gateway {
            h.push(HookPoint::GatewayEvent);
        }
        if self.notify_vpn {
            h.push(HookPoint::VpnEvent);
        }
        if self.notify_config {
            h.push(HookPoint::LogEvent);
        }
        h
    }
}

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
    client: http::Client,
    host: String,
}

/// One channel's failure from a delivery round.
#[derive(Debug, Serialize)]
struct Failure {
    channel: &'static str,
    error: String,
}

impl Shared {
    fn stats(&self) -> MutexGuard<'_, Stats> {
        self.stats.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Send `n` to `targets` concurrently; record per-channel outcomes.
    /// Returns the failures.
    async fn deliver(self: &Arc<Self>, n: &Notification, targets: &[Channel]) -> Vec<Failure> {
        let mut set = JoinSet::new();
        for ch in targets {
            let ch = ch.clone();
            let me = self.clone();
            let n = n.clone();
            set.spawn(async move {
                let r = channels::send(&me.client, &ch, &n, &me.host).await;
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
                    failures.push(Failure {
                        channel: id,
                        error: e.to_string(),
                    });
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
pub struct Notifier;

/// A running Notifier.
struct Running {
    shared: Arc<Shared>,
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
                for f in shared.deliver(&n, &shared.channels).await {
                    ctx.warn(format!("delivery failed: {}: {}", f.channel, f.error));
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
            version: "1.1.0".to_string(),
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
            SettingField::bool("notify_vpn", "VPN tunnel up / down", true)
                .help("WireGuard interfaces and IPsec tunnels.")
                .group("Events"),
            SettingField::bool("notify_vpn_peers", "Individual WireGuard peers", false)
                .help(
                    "Also notify when a single peer connects or drops. A peer counts as down \
                     3 minutes after its last handshake, so this is noisy on road-warrior \
                     tunnels where laptops and phones come and go.",
                )
                .visible_if("notify_vpn", true)
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
        let s = Settings::parse(s)?;
        if present(&s.telegram_bot_token).is_some() != present(&s.telegram_chat_id).is_some() {
            return Err(PluginError::Validation(
                "Telegram needs both a bot token and a chat ID.".into(),
            ));
        }
        if s.channels().is_empty() {
            return Err(PluginError::Validation(
                "Configure at least one channel (ntfy, Discord, Slack, Telegram or webhook)."
                    .into(),
            ));
        }
        if s.hooks().is_empty() {
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

    fn hooks(&self, s: &PluginSettings) -> Vec<HookPoint> {
        Settings::parse(s)
            .map(|s| s.hooks())
            .unwrap_or_else(|_| self.info().hooks)
    }

    async fn start(
        &self,
        s: &PluginSettings,
        ctx: &PluginContext,
    ) -> Result<Box<dyn PluginInstance>> {
        let s = Settings::parse(s)?;
        let (tx, rx) = mpsc::channel(QUEUE);
        let channels = s.channels();
        let shared = Arc::new(Shared {
            tx,
            stats: Mutex::new(Stats::default()),
            filter: s.filter(),
            client: http::Client::new(NAME, SEND_TIMEOUT, s.allow_private_destinations),
            host: hostname().await,
            channels: channels.clone(),
        });
        let limiter = Limiter::new(
            s.rate_limit_per_minute,
            Duration::from_secs(60 * s.dedupe_minutes),
            Instant::now(),
        );
        ctx.spawn(worker(shared.clone(), rx, limiter, ctx.clone()));
        let names: Vec<&str> = channels.iter().map(Channel::id).collect();
        ctx.info(format!("delivering to {}", names.join(", ")));
        Ok(Box::new(Running { shared }))
    }
}

#[async_trait]
impl PluginInstance for Running {
    async fn on_hook(&self, event: &HookEvent, _ctx: &PluginContext) -> HookAction {
        if let Some(n) = classify(event, &self.shared.filter)
            && self.shared.tx.try_send(n).is_err()
        {
            self.shared.stats().dropped_queue_full += 1;
        }
        HookAction::Continue
    }

    async fn run_action(&self, action: &str, args: Value, _ctx: &PluginContext) -> Result<Value> {
        if action != "test" {
            return Err(PluginError::NotFound(format!("action '{action}'")));
        }
        let which = args["channel"].as_str().unwrap_or("all");
        let targets: Vec<Channel> = self
            .shared
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
        let failed = self.shared.deliver(&test_notification(), &targets).await;
        let sent: Vec<&str> = targets
            .iter()
            .map(Channel::id)
            .filter(|id| !failed.iter().any(|f| f.channel == *id))
            .collect();
        if sent.is_empty() {
            let why: Vec<String> = failed
                .iter()
                .map(|f| format!("{}: {}", f.channel, f.error))
                .collect();
            return Err(PluginError::Plugin(why.join("; ")));
        }
        Ok(json!({"sent": sent, "failed": failed}))
    }

    async fn status(&self, _ctx: &PluginContext) -> Value {
        let stats = self.shared.stats();
        let channels: Vec<Value> = self
            .shared
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
            "queue_depth": QUEUE - self.shared.tx.capacity(),
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
        let schema = Notifier.settings_schema();
        let (v, s) = schema::normalize(
            &schema,
            values.as_object().unwrap(),
            secrets.as_object().unwrap(),
        )?;
        Ok(schema::effective(&schema, &v, &s))
    }

    #[test]
    fn requires_a_channel_and_complete_telegram() {
        let none = settings(json!({}), json!({})).unwrap();
        assert!(Notifier.validate_settings(&none).is_err());

        let half_tg = settings(json!({}), json!({"telegram_bot_token": "1:a"})).unwrap();
        assert!(
            Notifier
                .validate_settings(&half_tg)
                .unwrap_err()
                .to_string()
                .contains("Telegram")
        );

        let ok = settings(json!({}), json!({"ntfy_url": "https://ntfy.sh/x"})).unwrap();
        Notifier.validate_settings(&ok).unwrap();
        assert_eq!(Settings::parse(&ok).unwrap().channels().len(), 1);
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
    fn needs_some_event_and_hooks_follow_the_settings() {
        let s = settings(
            json!({"notify_ids": false, "notify_gateway": false, "notify_vpn": false}),
            json!({"slack_webhook": "https://hooks.slack.com/services/x"}),
        )
        .unwrap();
        assert!(Notifier.validate_settings(&s).is_err());

        let s = settings(
            json!({"notify_ids": false, "notify_config": true}),
            json!({"slack_webhook": "https://hooks.slack.com/services/x"}),
        )
        .unwrap();
        assert_eq!(
            Notifier.hooks(&s),
            [
                HookPoint::GatewayEvent,
                HookPoint::VpnEvent,
                HookPoint::LogEvent
            ]
        );
        // Defaults: peers off, tunnels on.
        let d = Settings::parse(&settings(json!({}), json!({})).unwrap()).unwrap();
        assert!(d.notify_vpn && !d.notify_vpn_peers);
        assert_eq!(d.rate_limit_per_minute, 10);
        assert_eq!(d.dedupe_minutes, 10);
    }

    #[tokio::test]
    async fn test_action_reports_unconfigured_channel() {
        let t = PluginContext::for_tests(NAME).await;
        let s = settings(json!({}), json!({"ntfy_url": "https://ntfy.sh/x"})).unwrap();
        let p = Notifier.start(&s, &t.ctx).await.unwrap();
        let err = p
            .run_action("test", json!({"channel": "discord"}), &t.ctx)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("discord is not configured"));
        assert_eq!(p.status(&t.ctx).await["channels"][0]["id"], "ntfy");
    }

    #[tokio::test]
    async fn test_action_reports_partial_success() {
        use crate::http::testing::{Reply, TestServer};
        let good = TestServer::bind().await;
        let good_url = good.url("/ok");
        good.run(vec![Reply::status(200)]);
        let bad = TestServer::bind().await;
        let bad_url = bad.url("/gone");
        bad.run(vec![Reply::status(404)]);

        let t = PluginContext::for_tests(NAME).await;
        let s = settings(
            json!({"allow_private_destinations": true}),
            json!({"webhook_url": good_url, "ntfy_url": bad_url}),
        )
        .unwrap();
        let p = Notifier.start(&s, &t.ctx).await.unwrap();
        let v = p
            .run_action("test", json!({"channel": "all"}), &t.ctx)
            .await
            .unwrap();
        assert_eq!(v["sent"], json!(["webhook"]));
        assert_eq!(v["failed"][0]["channel"], "ntfy");
        assert!(v["failed"][0]["error"].as_str().unwrap().contains("404"));
    }
}
