use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::Mutex;

use super::feeds::{self, CATALOG, Format};
use super::parse::{network, parse};
use super::sanitize::{Dropped, sanitize};
use crate::context::PluginContext;
use crate::error::{PluginError, Result};
use crate::hooks::{HookAction, HookEvent, HookPoint};
use crate::http::{self, Fetched};
use crate::plugin::{ActionInfo, Plugin, PluginInfo, PluginInstance};
use crate::schema::{ListItem, PluginSettings, SelectOption, SettingField, parse_cidr};

const NAME: &str = "threat-feeds";
/// The pf table holding every blocked network.
pub const TABLE: &str = "plugin_threat_feeds";
const MAX_BODY: usize = 20 * 1024 * 1024;
const FETCH_TIMEOUT: Duration = Duration::from_secs(60);
/// After a failed download, try again this soon (or at the normal
/// interval, if shorter).
const RETRY_AFTER_FAILURE: chrono::Duration = chrono::Duration::hours(1);
/// pf's default `table-entries` limit is 200k across all tables.
const MAX_ENTRIES_LIMIT: i64 = 190_000;

/// The settings exactly as the schema declares them (see
/// [`PluginSettings::deserialize`]).
#[derive(Debug, Deserialize)]
struct Settings {
    feeds: Vec<String>,
    custom_urls: Vec<String>,
    refresh_hours: i64,
    mode: String,
    direction: String,
    log_matches: bool,
    allowlist: Vec<String>,
    max_entries: i64,
}

/// A feed to download: a catalog entry or an operator URL.
#[derive(Debug, Clone)]
struct Source {
    id: String,
    name: String,
    url: String,
    format: Format,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Block,
    LogOnly,
}

#[derive(Debug, Clone)]
struct Config {
    sources: Vec<Source>,
    mode: Mode,
    both_directions: bool,
    log_matches: bool,
    refresh: chrono::Duration,
    allowlist: Vec<(IpAddr, u8)>,
    max_entries: usize,
}

/// Download bookkeeping for one feed, persisted in the KV store.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct FeedMeta {
    etag: Option<String>,
    last_attempt: Option<DateTime<Utc>>,
    last_success: Option<DateTime<Utc>>,
    last_error: Option<String>,
    entries: usize,
    skipped_lines: usize,
}

impl FeedMeta {
    fn next_due(&self, refresh: chrono::Duration) -> Option<DateTime<Utc>> {
        match (
            self.last_error.is_some(),
            self.last_attempt,
            self.last_success,
        ) {
            (true, Some(attempt), _) => Some(attempt + refresh.min(RETRY_AFTER_FAILURE)),
            (_, _, Some(ok)) => Some(ok + refresh),
            _ => None, // never fetched: due now
        }
    }

    fn is_due(&self, refresh: chrono::Duration, now: DateTime<Utc>) -> bool {
        self.next_due(refresh).is_none_or(|due| due <= now)
    }
}

#[derive(Default)]
struct State {
    lists: BTreeMap<String, Vec<(IpAddr, u8)>>,
    meta: BTreeMap<String, FeedMeta>,
    table_entries: usize,
    dropped: Dropped,
    last_applied: Option<DateTime<Utc>>,
}

struct Inner {
    cfg: Config,
    state: Mutex<State>,
    refreshing: AtomicBool,
    client: http::Client,
}

/// Clears the "refresh running" flag however the refresh ends.
struct RefreshGuard<'a>(&'a AtomicBool);

impl Drop for RefreshGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// The Threat Intel Feeds plugin. See the module docs.
pub struct ThreatFeeds;

/// A running Threat Intel Feeds plugin.
struct Running {
    inner: Arc<Inner>,
}

/// Stable id for an operator-supplied URL (FNV-1a), so its KV state
/// survives reordering the list.
fn custom_id(url: &str) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in url.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    format!("custom-{h:016x}")
}

fn config(s: &PluginSettings) -> Result<Config> {
    let s: Settings = s.deserialize()?;
    let mut sources: Vec<Source> = s
        .feeds
        .iter()
        .filter_map(|id| feeds::find(id))
        .map(|f| Source {
            id: f.id.to_string(),
            name: f.name.to_string(),
            url: f.url.to_string(),
            format: f.format,
        })
        .collect();
    for url in s.custom_urls {
        sources.push(Source {
            id: custom_id(&url),
            name: url.clone(),
            url,
            format: Format::Lines,
        });
    }
    Ok(Config {
        sources,
        mode: if s.mode == "log" {
            Mode::LogOnly
        } else {
            Mode::Block
        },
        both_directions: s.direction == "both",
        log_matches: s.log_matches,
        refresh: chrono::Duration::hours(s.refresh_hours),
        allowlist: s.allowlist.iter().filter_map(|c| parse_cidr(c)).collect(),
        max_entries: usize::try_from(s.max_entries).unwrap_or(1).max(1),
    })
}

/// The pf rules for the current mode. They only reference the plugin's own
/// table, so pf drops (or logs) exactly what the feeds list.
fn rules(cfg: &Config) -> Vec<String> {
    let t = format!("<{TABLE}>");
    match cfg.mode {
        Mode::Block => {
            let log = if cfg.log_matches { " log" } else { "" };
            let mut r = vec![format!(
                "block drop in{log} quick from {t} label \"threat-feeds:inbound\""
            )];
            if cfg.both_directions {
                r.push(format!(
                    "block drop in{log} quick to {t} label \"threat-feeds:outbound\""
                ));
                r.push(format!(
                    "block drop out{log} quick to {t} label \"threat-feeds:outbound\""
                ));
            }
            r
        }
        Mode::LogOnly => {
            let mut r = vec![format!(
                "match in log from {t} label \"threat-feeds:inbound\""
            )];
            if cfg.both_directions {
                r.push(format!(
                    "match in log to {t} label \"threat-feeds:outbound\""
                ));
                r.push(format!(
                    "match out log to {t} label \"threat-feeds:outbound\""
                ));
            }
            r
        }
    }
}

fn encode_list(list: &[(IpAddr, u8)]) -> String {
    let mut s = String::with_capacity(list.len() * 18);
    for (ip, len) in list {
        s.push_str(&format!("{ip}/{len}\n"));
    }
    s
}

fn decode_list(s: &str) -> Vec<(IpAddr, u8)> {
    s.lines().filter_map(parse_cidr).collect()
}

fn list_key(id: &str) -> String {
    format!("list:{id}")
}

fn meta_key(id: &str) -> String {
    format!("meta:{id}")
}

impl Inner {
    fn any_due(&self, state: &State, now: DateTime<Utc>) -> bool {
        self.cfg.sources.iter().any(|src| {
            state
                .meta
                .get(&src.id)
                .is_none_or(|m| m.is_due(self.cfg.refresh, now))
        })
    }

    /// Load the last good lists from the KV store — protection is back in
    /// place right after boot, before any download — and drop the stored
    /// lists of feeds that are no longer selected.
    async fn load(&self, ctx: &PluginContext) -> Result<()> {
        let keep: BTreeSet<&str> = self.cfg.sources.iter().map(|s| s.id.as_str()).collect();
        for key in ctx.kv_keys("list:").await? {
            if !keep.contains(&key[5..]) {
                ctx.kv_delete(&key).await?;
                ctx.kv_delete(&meta_key(&key[5..])).await?;
            }
        }
        let mut state = self.state.lock().await;
        for src in &self.cfg.sources {
            if let Some(meta) = ctx.kv_get_json::<FeedMeta>(&meta_key(&src.id)).await? {
                state.meta.insert(src.id.clone(), meta);
            }
            if let Some(list) = ctx.kv_get(&list_key(&src.id)).await? {
                state.lists.insert(src.id.clone(), decode_list(&list));
            }
        }
        Ok(())
    }

    /// Rebuild the pf table from every configured feed's current list. The
    /// state lock is held only while the entry list is built, never across
    /// the pfctl call.
    async fn apply(&self, ctx: &PluginContext) -> Result<usize> {
        let (entries, dropped) = {
            let state = self.state.lock().await;
            let all: Vec<(IpAddr, u8)> = self
                .cfg
                .sources
                .iter()
                .filter_map(|s| state.lists.get(&s.id))
                .flatten()
                .copied()
                .collect();
            sanitize(all, &self.cfg.allowlist, self.cfg.max_entries)
        };
        ctx.replace_table(TABLE, &entries).await?;
        if dropped.over_cap > 0 {
            ctx.warn(format!(
                "{} entries over the {}-entry cap were left out; raise the cap or select fewer feeds",
                dropped.over_cap, self.cfg.max_entries
            ));
        }
        let mut state = self.state.lock().await;
        state.table_entries = entries.len();
        state.dropped = dropped;
        state.last_applied = Some(Utc::now());
        Ok(entries.len())
    }

    /// Download one feed and record the outcome. Returns a one-line result.
    async fn fetch(&self, ctx: &PluginContext, src: &Source) -> String {
        let (mut meta, have_list) = {
            let state = self.state.lock().await;
            (
                state.meta.get(&src.id).cloned().unwrap_or_default(),
                state.lists.contains_key(&src.id),
            )
        };
        // Only send If-None-Match when we still hold the list it refers to.
        let etag = meta.etag.clone().filter(|_| have_list);
        let now = Utc::now();
        let outcome = self
            .client
            .get_text(&src.url, etag.as_deref(), MAX_BODY)
            .await;

        meta.last_attempt = Some(now);
        let mut new_list = None;
        let result = match outcome {
            Ok(Fetched::NotModified) => {
                meta.last_success = Some(now);
                meta.last_error = None;
                "unchanged".to_string()
            }
            Ok(Fetched::Body { text, etag }) => {
                let parsed = parse(src.format, &text);
                if parsed.entries.is_empty() && parsed.skipped > 0 {
                    let msg = format!(
                        "no addresses found in {} lines — has the feed format changed?",
                        parsed.skipped
                    );
                    meta.last_error = Some(msg.clone());
                    msg
                } else {
                    meta.last_success = Some(now);
                    meta.last_error = None;
                    meta.etag = etag;
                    meta.entries = parsed.entries.len();
                    meta.skipped_lines = parsed.skipped;
                    let n = parsed.entries.len();
                    new_list = Some(parsed.entries);
                    format!("{n} entries")
                }
            }
            Err(e) => {
                meta.last_error = Some(e.to_string());
                format!("failed: {e}")
            }
        };
        // Persist outside the state lock: a multi-MB write must not stall
        // the timer hook or the status view.
        if let Some(list) = &new_list
            && let Err(e) = ctx.kv_set(&list_key(&src.id), &encode_list(list)).await
        {
            ctx.warn(format!("{}: could not persist list: {e}", src.name));
        }
        if let Err(e) = ctx.kv_set_json(&meta_key(&src.id), &meta).await {
            ctx.warn(format!("{}: could not persist state: {e}", src.name));
        }
        {
            let mut state = self.state.lock().await;
            if let Some(list) = new_list {
                state.lists.insert(src.id.clone(), list);
            }
            state.meta.insert(src.id.clone(), meta.clone());
        }

        if meta.last_error.is_some() {
            ctx.warn(format!("{}: {result}", src.name));
        } else {
            ctx.info(format!("{}: {result}", src.name));
        }
        result
    }

    /// Download due feeds (all of them when `force`), then rebuild the
    /// table. Only one refresh runs at a time.
    async fn refresh(&self, ctx: &PluginContext, force: bool) -> Result<Value> {
        if self
            .refreshing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(PluginError::Validation(
                "a refresh is already running".into(),
            ));
        }
        let _guard = RefreshGuard(&self.refreshing);
        let now = Utc::now();
        let due: Vec<Source> = {
            let state = self.state.lock().await;
            self.cfg
                .sources
                .iter()
                .filter(|s| {
                    force
                        || state
                            .meta
                            .get(&s.id)
                            .is_none_or(|m| m.is_due(self.cfg.refresh, now))
                })
                .cloned()
                .collect()
        };
        let mut results = Vec::with_capacity(due.len());
        for src in &due {
            let r = self.fetch(ctx, src).await;
            results.push(json!({"feed": src.name, "result": r}));
        }
        let entries = self.apply(ctx).await?;
        ctx.info(format!(
            "refreshed {} feed(s); {entries} networks in <{TABLE}>",
            due.len()
        ));
        Ok(json!({"feeds": results, "table_entries": entries}))
    }

    fn start_refresh(self: &Arc<Self>, ctx: &PluginContext, force: bool) {
        if self.refreshing.load(Ordering::Acquire) {
            return;
        }
        let inner = self.clone();
        let task_ctx = ctx.clone();
        ctx.spawn(async move {
            if let Err(e) = inner.refresh(&task_ctx, force).await {
                task_ctx.warn(format!("refresh failed: {e}"));
            }
        });
    }
}

#[async_trait]
impl Plugin for ThreatFeeds {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            name: NAME.to_string(),
            title: "Threat Intel Feeds".to_string(),
            version: "1.1.0".to_string(),
            description: "Blocks traffic to and from addresses on public threat-intelligence \
                          blocklists (Spamhaus DROP, abuse.ch, DShield and more), refreshed \
                          automatically."
                .to_string(),
            author: "AiFw".to_string(),
            hooks: vec![HookPoint::Timer],
        }
    }

    fn settings_schema(&self) -> Vec<SettingField> {
        let feed_options = CATALOG
            .iter()
            .map(|f| SelectOption::new(f.id, f.name).help(f.description))
            .collect();
        let defaults: Vec<&str> = CATALOG
            .iter()
            .filter(|f| f.default_on)
            .map(|f| f.id)
            .collect();
        vec![
            SettingField::multi_select("feeds", "Feeds", feed_options, &defaults)
                .help("Lists to download. Entries from every selected list are combined.")
                .group("Sources"),
            SettingField::list("custom_urls", "Custom feed URLs", ListItem::Url, 20)
                .help("Extra https:// lists with one IP address or CIDR per line.")
                .group("Sources"),
            SettingField::integer("refresh_hours", "Refresh every (hours)", 1, 168, 12)
                .help("Feed publishers ask clients not to download more than once an hour.")
                .group("Sources"),
            SettingField::select(
                "mode",
                "Action",
                vec![
                    SelectOption::new("block", "Block").help("Drop matching traffic."),
                    SelectOption::new("log", "Log only")
                        .help("Let traffic through but log it to pflog — try this first."),
                ],
                "block",
            )
            .group("Enforcement"),
            SettingField::select(
                "direction",
                "Direction",
                vec![
                    SelectOption::new("inbound", "Inbound")
                        .help("Stop listed addresses from connecting in."),
                    SelectOption::new("both", "Inbound and outbound")
                        .help("Also stop LAN hosts and the firewall from reaching them."),
                ],
                "both",
            )
            .group("Enforcement"),
            SettingField::bool("log_matches", "Log blocked packets", true)
                .help("Send blocked packets to pflog so they appear in the blocked-traffic view.")
                .visible_if("mode", "block")
                .group("Enforcement"),
            SettingField::list("allowlist", "Never block", ListItem::Cidr, 256)
                .help(
                    "Addresses or networks to keep reachable. Add the address you manage \
                     this firewall from: these blocks run before every other rule, and some \
                     feeds list residential ranges. A feed entry that overlaps any of these \
                     is skipped entirely.",
                )
                .group("Enforcement"),
            SettingField::integer(
                "max_entries",
                "Maximum entries",
                1_000,
                MAX_ENTRIES_LIMIT,
                150_000,
            )
            .help("Upper bound on the pf table size. pf allows 200,000 table entries in total.")
            .group("Advanced"),
        ]
    }

    fn validate_settings(&self, settings: &PluginSettings) -> Result<()> {
        if config(settings)?.sources.is_empty() {
            return Err(PluginError::Validation(
                "Select at least one feed or add a custom URL.".into(),
            ));
        }
        Ok(())
    }

    fn actions(&self) -> Vec<ActionInfo> {
        vec![
            ActionInfo::new(
                "refresh",
                "Refresh now",
                "Download every selected feed now, ignoring the schedule.",
            ),
            ActionInfo::new(
                "lookup",
                "Look up address",
                "Check which feeds list an address and whether it is blocked.",
            )
            .arg(SettingField::text("ip", "IP address", 64)),
        ]
    }

    async fn start(
        &self,
        settings: &PluginSettings,
        ctx: &PluginContext,
    ) -> Result<Box<dyn PluginInstance>> {
        let cfg = config(settings)?;
        let inner = Arc::new(Inner {
            client: http::Client::new(NAME, FETCH_TIMEOUT, false),
            cfg,
            state: Mutex::new(State::default()),
            refreshing: AtomicBool::new(false),
        });
        inner.load(ctx).await?;
        // Table first, then the rules that reference it.
        let restored = inner.apply(ctx).await?;
        ctx.set_rules(rules(&inner.cfg)).await?;
        if restored > 0 {
            ctx.info(format!(
                "restored {restored} networks from the last download"
            ));
        }
        let due = {
            let state = inner.state.lock().await;
            inner.any_due(&state, Utc::now())
        };
        if due {
            inner.start_refresh(ctx, false);
        }
        Ok(Box::new(Running { inner }))
    }
}

#[async_trait]
impl PluginInstance for Running {
    async fn on_hook(&self, event: &HookEvent, ctx: &PluginContext) -> HookAction {
        if event.hook != HookPoint::Timer {
            return HookAction::Continue;
        }
        let due = {
            let state = self.inner.state.lock().await;
            self.inner.any_due(&state, Utc::now())
        };
        if due {
            self.inner.start_refresh(ctx, false);
        }
        HookAction::Continue
    }

    async fn run_action(&self, action: &str, args: Value, ctx: &PluginContext) -> Result<Value> {
        let inner = &self.inner;
        match action {
            "refresh" => inner.refresh(ctx, true).await,
            "lookup" => {
                let raw = args["ip"].as_str().unwrap_or("").trim();
                let ip: IpAddr = raw.parse().map_err(|_| {
                    PluginError::Validation(format!("'{raw}' is not an IP address"))
                })?;
                let bits = if ip.is_ipv4() { 32 } else { 128 };
                let contains = |(net, len): &(IpAddr, u8)| {
                    net.is_ipv4() == ip.is_ipv4() && network(ip, *len) == (*net, *len)
                };
                let state = inner.state.lock().await;
                let listed_in: Vec<&str> = inner
                    .cfg
                    .sources
                    .iter()
                    .filter(|s| {
                        state
                            .lists
                            .get(&s.id)
                            .is_some_and(|l| l.iter().any(contains))
                    })
                    .map(|s| s.name.as_str())
                    .collect();
                let allowlisted = inner.cfg.allowlist.iter().any(contains);
                let public = aifw_common::net_safety::is_public_prefix(ip, bits);
                let blocked = !listed_in.is_empty() && !allowlisted && public;
                Ok(json!({
                    "ip": ip.to_string(),
                    "listed_in": listed_in,
                    "allowlisted": allowlisted,
                    "blocked": blocked && inner.cfg.mode == Mode::Block,
                    "logged": blocked,
                }))
            }
            other => Err(PluginError::NotFound(format!("action '{other}'"))),
        }
    }

    async fn status(&self, ctx: &PluginContext) -> Value {
        let inner = &self.inner;
        let state = inner.state.lock().await;
        let feeds: Vec<Value> = inner
            .cfg
            .sources
            .iter()
            .map(|s| {
                let meta = state.meta.get(&s.id).cloned().unwrap_or_default();
                json!({
                    "id": s.id,
                    "name": s.name,
                    "url": s.url,
                    "entries": state.lists.get(&s.id).map_or(0, Vec::len),
                    "last_success": meta.last_success,
                    "last_attempt": meta.last_attempt,
                    "last_error": meta.last_error,
                    "next_due": meta.next_due(inner.cfg.refresh),
                    "skipped_lines": meta.skipped_lines,
                })
            })
            .collect();
        json!({
            "table": TABLE,
            "table_entries": state.table_entries,
            "pf_table_entries": ctx.table_len(TABLE).await.ok(),
            "dropped": state.dropped,
            "last_applied": state.last_applied,
            "refreshing": inner.refreshing.load(Ordering::Acquire),
            "mode": if inner.cfg.mode == Mode::Block { "block" } else { "log" },
            "direction": if inner.cfg.both_directions { "both" } else { "inbound" },
            "feeds": feeds,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema;

    fn settings(v: Value) -> PluginSettings {
        let schema = ThreatFeeds.settings_schema();
        let (values, _) =
            schema::normalize(&schema, v.as_object().unwrap(), &serde_json::Map::new()).unwrap();
        schema::effective(&schema, &values, &serde_json::Map::new())
    }

    #[test]
    fn defaults_select_low_false_positive_feeds() {
        let cfg = config(&settings(json!({}))).unwrap();
        let ids: Vec<&str> = cfg.sources.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(
            ids,
            ["spamhaus-drop", "spamhaus-drop-v6", "feodo", "dshield"]
        );
        assert_eq!(cfg.mode, Mode::Block);
        assert!(cfg.both_directions);
        assert_eq!(cfg.refresh, chrono::Duration::hours(12));
        assert_eq!(cfg.max_entries, 150_000);
    }

    #[test]
    fn rules_pass_the_plugin_rule_validator() {
        for v in [
            json!({"mode": "block", "direction": "inbound", "log_matches": false}),
            json!({"mode": "block", "direction": "both"}),
            json!({"mode": "log", "direction": "both"}),
        ] {
            let r = rules(&config(&settings(v.clone())).unwrap());
            assert!(!r.is_empty());
            for rule in &r {
                crate::rules::check_rule(rule).unwrap_or_else(|e| panic!("{v}: {e}"));
            }
        }
        let inbound_block = rules(
            &config(&settings(
                json!({"mode": "block", "direction": "inbound", "log_matches": false}),
            ))
            .unwrap(),
        );
        assert_eq!(
            inbound_block,
            ["block drop in quick from <plugin_threat_feeds> label \"threat-feeds:inbound\""]
        );
    }

    #[test]
    fn requires_a_source() {
        assert!(
            ThreatFeeds
                .validate_settings(&settings(json!({"feeds": []})))
                .is_err()
        );
        assert!(
            ThreatFeeds
                .validate_settings(&settings(
                    json!({"feeds": [], "custom_urls": ["https://example.com/l.txt"]})
                ))
                .is_ok()
        );
    }

    #[test]
    fn custom_ids_are_stable_and_distinct() {
        assert_eq!(custom_id("https://a/x"), custom_id("https://a/x"));
        assert_ne!(custom_id("https://a/x"), custom_id("https://a/y"));
    }

    #[test]
    fn due_schedule() {
        let refresh = chrono::Duration::hours(12);
        let now = Utc::now();
        assert!(FeedMeta::default().is_due(refresh, now), "never fetched");
        let fresh = FeedMeta {
            last_attempt: Some(now),
            last_success: Some(now),
            ..Default::default()
        };
        assert!(!fresh.is_due(refresh, now + chrono::Duration::hours(11)));
        assert!(fresh.is_due(refresh, now + chrono::Duration::hours(12)));
        let failed = FeedMeta {
            last_attempt: Some(now),
            last_success: Some(now - chrono::Duration::hours(3)),
            last_error: Some("HTTP 503".into()),
            ..Default::default()
        };
        assert!(!failed.is_due(refresh, now + chrono::Duration::minutes(30)));
        assert!(failed.is_due(refresh, now + chrono::Duration::hours(1)));
    }

    /// Mark every default feed as freshly fetched so no download is due
    /// and the test never touches the network.
    async fn mark_fresh(ctx: &PluginContext, ids: &[&str]) {
        let meta = FeedMeta {
            last_attempt: Some(Utc::now()),
            last_success: Some(Utc::now()),
            entries: 2,
            ..Default::default()
        };
        for id in ids {
            ctx.kv_set_json(&meta_key(id), &meta).await.unwrap();
        }
    }

    #[tokio::test]
    async fn restores_table_from_kv_without_network() {
        let t = PluginContext::for_tests(NAME).await;
        let ctx = &t.ctx;

        // A previous run left one feed's list behind.
        ctx.kv_set("list:feodo", "50.16.16.211/32\n10.0.0.0/8\n")
            .await
            .unwrap();
        mark_fresh(
            ctx,
            &["spamhaus-drop", "spamhaus-drop-v6", "feodo", "dshield"],
        )
        .await;

        let p = ThreatFeeds.start(&settings(json!({})), ctx).await.unwrap();

        let table = t.pf.get_table_entries(TABLE).await.unwrap();
        assert_eq!(table.len(), 1, "RFC1918 entry must be sanitized out");
        assert_eq!(table[0].addr.to_string(), "50.16.16.211");
        assert_eq!(
            t.pf.get_rules(aifw_common::anchors::PLUGINS)
                .await
                .unwrap()
                .len(),
            3
        );

        let status = p.status(ctx).await;
        assert_eq!(status["table_entries"], 1);
        assert_eq!(status["dropped"]["non_public"], 1);
        assert_eq!(status["refreshing"], false);

        let hit = p
            .run_action("lookup", json!({"ip": "50.16.16.211"}), ctx)
            .await
            .unwrap();
        assert_eq!(hit["listed_in"], json!(["abuse.ch Feodo Tracker"]));
        assert_eq!(hit["blocked"], true);
        let miss = p
            .run_action("lookup", json!({"ip": "8.8.8.8"}), ctx)
            .await
            .unwrap();
        assert_eq!(miss["blocked"], false);
    }

    #[tokio::test]
    async fn start_prunes_lists_of_deselected_feeds() {
        let t = PluginContext::for_tests(NAME).await;
        let ctx = &t.ctx;
        ctx.kv_set("list:firehol-l1", "1.2.3.0/24\n").await.unwrap();
        ctx.kv_set("list:feodo", "50.16.16.211/32\n").await.unwrap();
        mark_fresh(ctx, &["firehol-l1", "feodo"]).await;

        ThreatFeeds
            .start(&settings(json!({"feeds": ["feodo"]})), ctx)
            .await
            .unwrap();

        assert_eq!(ctx.kv_keys("list:").await.unwrap(), ["list:feodo"]);
        assert_eq!(ctx.kv_keys("meta:").await.unwrap(), ["meta:feodo"]);
    }

    #[tokio::test]
    async fn fetches_a_custom_feed_and_persists_it() {
        use crate::http::testing::{Reply, TestServer};
        // The SSRF guard refuses loopback feeds; test the fetch path
        // through the HTTP client with a LAN-allowing client instead.
        let srv = TestServer::bind().await;
        let url = srv.url("/list.txt");
        srv.run(vec![
            Reply::body(
                200,
                "# comment\nnot-an-address\n1.2.3.0/24\n5.6.7.8\n10.0.0.1\n",
            )
            .header("ETag", "\"abc\""),
        ]);
        let inner = Arc::new(Inner {
            client: http::Client::new(NAME, FETCH_TIMEOUT, true),
            cfg: Config {
                sources: vec![Source {
                    id: custom_id(&url),
                    name: url.clone(),
                    url: url.clone(),
                    format: Format::Lines,
                }],
                mode: Mode::Block,
                both_directions: false,
                log_matches: false,
                refresh: chrono::Duration::hours(12),
                allowlist: Vec::new(),
                max_entries: 1000,
            },
            state: Mutex::new(State::default()),
            refreshing: AtomicBool::new(false),
        });
        let t = PluginContext::for_tests(NAME).await;
        let out = inner.refresh(&t.ctx, true).await.unwrap();
        assert_eq!(out["table_entries"], 2, "private entry sanitized out");
        let meta: FeedMeta = t
            .ctx
            .kv_get_json(&meta_key(&custom_id(&url)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(meta.etag.as_deref(), Some("\"abc\""));
        assert_eq!(meta.entries, 3);
        assert_eq!(meta.skipped_lines, 1);
        assert_eq!(t.pf.get_table_entries(TABLE).await.unwrap().len(), 2);
    }
}

/// Live check against the real publishers — run manually with
/// `cargo test -p aifw-plugins live_catalog -- --ignored`.
#[cfg(test)]
mod live {
    use super::*;

    #[tokio::test]
    #[ignore = "downloads every catalog feed from the internet"]
    async fn live_catalog_feeds_download_and_parse() {
        let client = http::Client::new(NAME, FETCH_TIMEOUT, false);
        for feed in CATALOG {
            let Fetched::Body { text, .. } = client
                .get_text(feed.url, None, MAX_BODY)
                .await
                .unwrap_or_else(|e| panic!("{}: {e}", feed.id))
            else {
                panic!("{}: unexpected 304", feed.id);
            };
            let parsed = parse(feed.format, &text);
            let (kept, dropped) = sanitize(parsed.entries.clone(), &[], 190_000);
            println!(
                "{:<18} parsed {:>6} skipped {:>3} kept {:>6} dropped {:?}",
                feed.id,
                parsed.entries.len(),
                parsed.skipped,
                kept.len(),
                dropped
            );
            assert!(!kept.is_empty(), "{} produced no usable entries", feed.id);
        }
    }
}
