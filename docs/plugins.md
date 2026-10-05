---
layout: default
title: Plugin System — AiFw
description: Extend AiFw with native Rust plugins — typed settings, event hooks, a sandboxed pf context, and a walkthrough that builds the Threat Intel Feeds plugin.
permalink: /plugins/
date: 2026-05-09
breadcrumb:
  - { title: "Docs", url: "/docs/" }
  - { title: "Plugins", url: "/plugins/" }
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "AiFw plugin system — native Rust plugins with typed settings and sandboxed pf access",
  "description": "How AiFw plugins work, the built-in Threat Intel Feeds and Notifier plugins, and a step-by-step guide to writing your own.",
  "author": { "@type": "Organization", "name": "ZerosAndOnesLLC" },
  "datePublished": "2026-05-09",
  "dateModified": "2026-10-05"
}
</script>

<div class="content-page">
<article markdown="1">

# AiFw Plugin System <span class="badge-beta">Beta</span>

Plugins add optional features to AiFw without touching the core engines. A
plugin is a Rust type compiled into AiFw. It declares the events it wants
and the settings it accepts. AiFw provides the settings form, the CLI, backup
and restore, an activity log, and a sandboxed handle into pf.

AiFw ships two plugins. They are also the examples this guide builds on:

| Plugin | What it does |
|---|---|
| **Threat Intel Feeds** (`threat-feeds`) | Downloads public IP blocklists on a schedule (Spamhaus DROP, abuse.ch Feodo, DShield, FireHOL, ET, CINS, or your own URLs) into a pf table and drops traffic to and from those addresses. |
| **Notifier** (`notifier`) | Sends IDS alerts, gateway outages, VPN up/down, and selected configuration changes to ntfy, Discord, Slack, Telegram, or a signed JSON webhook. |

## Using plugins

Open **Extensions → Plugins** in the web UI. Each card shows the plugin's
state and has a switch to enable it. **Configure** opens a panel with three
tabs:

- **Overview** shows live status (feed health and table size, delivery stats
  per channel), operator actions (*Refresh now*, *Look up address*,
  *Send test*), hook statistics, and the pf rules the plugin currently has
  loaded.
- **Settings** is a form generated from the plugin's settings. Changes save
  as you make them. A running plugin restarts with the new settings at once.
  Secrets such as webhook URLs and tokens can be written but never read back.
- **Activity** is the plugin's own log: what it did, and what went wrong.

Turning a plugin off stops its background work, removes its pf rules, and
empties its pf tables. Nothing it added stays behind.

The same configuration is available from the shell:

```sh
aifw plugins list
aifw plugins show threat-feeds          # every setting, its value, and allowed values
aifw plugins set threat-feeds refresh_hours=6 feeds=spamhaus-drop,feodo
aifw plugins set notifier --secret ntfy_url=https://ntfy.sh/my-topic
aifw plugins enable notifier
aifw plugins set threat-feeds --unset refresh_hours   # back to the default
aifw plugins reset notifier                           # forget everything, disable
```

The running API applies CLI changes within about ten seconds.

Plugin configuration is part of config backups and history. Secrets are
redacted or passphrase-encrypted on export, like every other credential.

### Threat Intel Feeds

- **Feeds.** The defaults (Spamhaus DROP v4/v6, Feodo, DShield) have a very
  low false-positive rate. FireHOL Level 1 is a broader aggregate. CINS Army
  is aggressive.
- **Action.** *Block* drops matching traffic. *Log only* passes it but sends
  it to pflog, so you can see what would be blocked before you enforce.
- **Direction.** *Inbound* stops listed addresses connecting in. *Inbound and
  outbound* also stops LAN hosts and the firewall itself reaching them, for
  example malware calling a botnet C2 server.
- **Never block.** Addresses or networks to keep reachable. A feed entry that
  overlaps this list is skipped entirely.
- **Safety filtering.** Before anything reaches pf, AiFw drops feed entries
  that overlap private, loopback, bogon or other non-public space (FireHOL
  Level 1 lists `10.0.0.0/8` and friends). It also drops entries broader
  than /8 (IPv4) or /12 (IPv6), collapses duplicates, and caps the total
  size.
- **Persistence.** The last good download of every feed is stored. After a
  reboot the table is refilled immediately, before any network access.

To check on the firewall:

```sh
pfctl -a aifw-plugins -sr                 # the plugin's rules
pfctl -t plugin_threat_feeds -T show | wc -l
pfctl -t plugin_threat_feeds -T test 1.10.16.5
```

### Notifier

- **Channels:** ntfy (topic URL plus optional token), Discord webhook, Slack
  webhook, Telegram bot, or a generic webhook. Generic webhook requests carry
  `X-AiFw-Signature: sha256=<HMAC-SHA256 of the body>` when a signing secret
  is set.
- **Events:**
  - IDS alerts at or above a chosen severity.
  - Gateway down, degraded, or recovered.
  - WireGuard peer or IPsec tunnel up or down. A WireGuard peer counts as
    down 3 minutes after its last handshake.
  - Selected audit-log changes.
- **Delivery:**
  - Repeats of the same event are suppressed for a configurable window.
  - Bursts are capped per minute.
  - Failed deliveries are retried, honouring `Retry-After`.
- Destinations must be public https URLs unless you enable **Allow LAN /
  http destinations**, which you need for a self-hosted ntfy.
- **Send test** checks each channel immediately.

## How plugins work

```
             ┌──────────────────────────── aifw-api ───────────────────────────┐
 audit_log ─▶│ tail ─┐                                                         │
 ids_alerts ▶│ tail ─┤                         ┌─ threat-feeds ─┐               │
 gw events ─▶│ tail ─┼──▶ PluginManager ──────▶│  on_hook()     │──▶ ctx ──▶ pf │
 wg / ipsec ▶│ poll ─┤    (time budget,        └────────────────┘   (plugin_*   │
 pflog0 ────▶│ read ─┤     panic isolation)    ┌─ notifier ─────┐    tables,   │
 60 s timer ▶│ tick ─┤                         │  on_hook()     │    block /   │
 API request▶│ auth ─┘                         └────────────────┘    match)    │
             └─────────────────────────────────────────────────────────────────┘
```

Plugins run inside the `aifw-api` process. AiFw lists them in one registry,
`aifw-plugins/src/registry.rs`. Each plugin's configuration lives in the
`plugin_config` table, which the API, CLI, config restore and cluster sync
all write to. A reconcile loop restarts any plugin whose stored
configuration changed.

### Lifecycle

When a plugin is enabled, or its settings change, the manager:

1. Builds a fresh instance from the registry.
2. Validates the stored settings against the plugin's schema and its
   `validate_settings` check.
3. Calls `init(settings, ctx)`. Init runs in its own task with a 30 s
   budget. An error or panic leaves the plugin in the **error** state, and
   the message is shown on its card.
4. Delivers subscribed hook events until the plugin is stopped.
5. On stop, calls `shutdown`, aborts every task started with `ctx.spawn`,
   removes the plugin's pf rules, and flushes every pf table it touched.

### Hooks

| Hook | Fired when | Payload (`HookEventData`) |
|---|---|---|
| `timer` | every 60 s | `Tick { timestamp }` |
| `log_event` | an audit-log row is written (rule/NAT/config changes, plugin changes) | `Log { action, details, source }` |
| `ids_alert` | the IDS writes an alert | `IdsAlertEvent { alert_id, timestamp, signature_id, signature_msg, severity, src_ip, dst_ip, src_port, dst_port, protocol, action, rule_source }` |
| `gateway_event` | a multi-WAN gateway changes state | `Gateway { gateway_id, gateway_name, interface, from_state, to_state, reason }` |
| `vpn_event` | a WireGuard peer/tunnel or IPsec tunnel goes up or down | `Vpn { kind, tunnel_name, peer, action, detail }` |
| `post_rule` | pf logs a packet (rules with `log`) | `Rule { src_ip, dst_ip, src_port, dst_port, protocol, action, rule_id }` |
| `api_request` | an authenticated API request arrives | `Api { method, path, remote_addr }` |

Each event source does nothing until a running plugin subscribes to it.
When a source starts, it begins from "now", so enabling a plugin never
replays history.

A plugin gets 5 s per event, or 250 ms for `api_request`, because that hook
sits in the request path. A plugin that runs over its budget or panics is
counted and logged. Other plugins still get the event.

### What `on_hook` can return

| `HookAction` | Effect |
|---|---|
| `Continue` | Nothing (the default). |
| `Block` | For `api_request`: the request is rejected with 403. Ignored elsewhere. |
| `Log(msg)` | Written to the plugin's activity log. |
| `AddToTable { table, ip }` / `RemoveFromTable { … }` | Applied through the plugin's context, so only `plugin_*` tables are allowed. |
| `Multi(vec)` | Several of the above (bounded depth and count). |

### The sandbox

`PluginContext` is the plugin's only handle into AiFw:

- **pf tables:** `add_to_table`, `remove_from_table`, `replace_table`,
  `flush_table`, `table_len`. Only tables named `plugin_<name>` are allowed.
- **pf rules:** `set_rules` / `clear_rules` load into the shared
  `aifw-plugins` anchor. That anchor is hooked first in `pf.conf`, so plugin
  drops win over multi-WAN `pass quick` policy routes. Rules must start with
  `block` or `match` and reference a `plugin_*` table. `pass`, `nat`/`rdr`,
  `route-to` and similar keywords are refused, so a plugin can drop or log
  traffic but never open or redirect it.
- **Storage:** `kv_get` / `kv_set` (plus `_json` variants) give the plugin a
  persistent key/value store that only it can see.
- **Background work:** `spawn` runs a task that is cancelled when the plugin
  stops. A panic in it is caught and logged.
- **Logging:** `info` / `warn` / `error` write to the plugin's activity log
  (500 entries) and to the service log.
- **Outbound HTTP:** use `aifw_plugins::http` rather than a raw client. Every
  request goes through the SSRF check, which allows public https only unless
  the plugin passes `allow_private`. Redirects are limited and re-checked,
  and response bodies are size-capped while they stream.

## Build your first plugin

This walkthrough follows the real Threat Intel Feeds plugin
(`aifw-plugins/src/builtin/threat_feeds/`), trimmed to the parts that matter.

### 1. Create the module

```
aifw-plugins/src/builtin/
├── mod.rs                 # pub mod threat_feeds; pub use …
└── threat_feeds/
    ├── mod.rs             # module docs + re-exports only
    ├── feeds.rs           # the feed catalog
    ├── parse.rs           # body parsing (pure, unit-tested)
    ├── sanitize.rs        # safety filtering (pure, unit-tested)
    └── plugin.rs          # the Plugin impl
```

Keep I/O-free logic, such as parsing and filtering, in its own files with
its own tests. The `Plugin` impl should mostly wire those pieces together.

### 2. Describe the plugin

```rust
#[derive(Default)]
pub struct ThreatFeeds {
    inner: Option<Arc<Inner>>,   // built in init()
}

impl ThreatFeeds {
    pub fn boxed() -> Box<dyn Plugin> {
        Box::new(Self::default())
    }
}

#[async_trait]
impl Plugin for ThreatFeeds {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            name: "threat-feeds".into(),          // [a-z0-9-], the registry key
            title: "Threat Intel Feeds".into(),
            version: "1.0.0".into(),
            description: "Blocks traffic to and from addresses on public …".into(),
            author: "AiFw".into(),
            hooks: vec![HookPoint::Timer],        // only what you need
        }
    }
    // …
}
```

### 3. Declare settings

The schema drives validation (API and CLI), the UI form, and the CLI's
`show` output. Settings are never accepted unvalidated.

```rust
fn settings_schema(&self) -> Vec<SettingField> {
    vec![
        SettingField::multi_select("feeds", "Feeds", feed_options, &defaults)
            .help("Lists to download. Entries from every selected list are combined.")
            .group("Sources"),
        SettingField::integer("refresh_hours", "Refresh every (hours)", 1, 168, 12)
            .group("Sources"),
        SettingField::select("mode", "Action", vec![
            SelectOption::new("block", "Block").help("Drop matching traffic."),
            SelectOption::new("log", "Log only").help("Let traffic through but log it."),
        ], "block").group("Enforcement"),
        SettingField::bool("log_matches", "Log blocked packets", true)
            .visible_if("mode", "block")          // UI hint
            .group("Enforcement"),
        SettingField::list("allowlist", "Never block", ListItem::Cidr, 256)
            .group("Enforcement"),
    ]
}

fn validate_settings(&self, s: &PluginSettings) -> Result<()> {
    if s.strings("feeds").is_empty() && s.strings("custom_urls").is_empty() {
        return Err(PluginError::Validation("Select at least one feed or add a custom URL.".into()));
    }
    Ok(())
}
```

Field kinds are `bool`, `integer` (with range), `text`, `url` (optionally
https-only), `select`, `multi_select` and `list` (CIDR / URL / text items).

Mark credentials with `.secret()`. A secret is sealed at rest, never returned
by the API, redacted in exports, and shown in the UI as *Set* with
*Replace* / *Clear*. Your plugin receives the plaintext in
`PluginSettings` like any other value.

`validate_settings` runs on every settings change while the plugin is
enabled, and again when it is enabled. Its message is what the operator
sees, so write it for them.

### 4. Start up: restore state, then enforce

```rust
async fn init(&mut self, settings: &PluginSettings, ctx: &PluginContext) -> Result<()> {
    let inner = Arc::new(Inner { cfg: config(settings), /* … */ });

    // Last good lists from the plugin's KV store: protection is back
    // immediately after a reboot, before any download.
    inner.load(ctx).await?;

    // Table first, then the rules that reference it.
    inner.apply(ctx).await?;                  // ctx.replace_table("plugin_threat_feeds", …)
    ctx.set_rules(rules(&inner.cfg)).await?;  // block drop in log quick from <plugin_threat_feeds> …

    // Never block init on the network: schedule the download.
    if inner.any_due(/* … */) {
        inner.start_refresh(ctx, false);      // ctx.spawn(…)
    }
    self.inner = Some(inner);
    Ok(())
}
```

A settings change restarts the plugin. Keep anything expensive to rebuild,
such as downloaded lists and ETags, in the KV store so a restart costs
nothing.

### 5. React to hooks without blocking

```rust
async fn on_hook(&self, event: &HookEvent, ctx: &PluginContext) -> HookAction {
    if event.hook == HookPoint::Timer && self.due() {
        self.inner().start_refresh(ctx, false);   // background task, returns at once
    }
    HookAction::Continue
}
```

`on_hook` has a time budget. Decide quickly and hand slow work to a task
started with `ctx.spawn`. The Notifier pushes each event into a bounded
queue that a delivery task drains.

### 6. Show status and offer actions

```rust
async fn status(&self, ctx: &PluginContext) -> Value {
    json!({ "table_entries": …, "feeds": […], "refreshing": … })
}

fn actions(&self) -> Vec<ActionInfo> {
    vec![
        ActionInfo::new("refresh", "Refresh now", "Download every selected feed now."),
        ActionInfo::new("lookup", "Look up address", "Which feeds list an address?")
            .arg(SettingField::text("ip", "IP address", 64)),
    ]
}

async fn run_action(&self, action: &str, args: Value, ctx: &PluginContext) -> Result<Value> {
    match action {
        "refresh" => self.inner()?.refresh(ctx, true).await,
        "lookup" => { /* … */ }
        other => Err(PluginError::NotFound(format!("action '{other}'"))),
    }
}
```

The UI renders actions as buttons, with a small form when they take
arguments, and shows the returned JSON as a readable result. A plugin
without a custom status view gets a generic one. Threat Feeds and Notifier
have small dedicated views in `aifw-ui/src/app/plugins/components/status/`.

### 7. Register it

```rust
// aifw-plugins/src/registry.rs
const BUILTINS: &[fn() -> Box<dyn Plugin>] = &[
    crate::builtin::ThreatFeeds::boxed,
    crate::builtin::Notifier::boxed,
    crate::builtin::YourPlugin::boxed,   // ← one line
];
```

That is the only change outside your module. The API, UI, CLI, and backup
and restore pick the plugin up from the registry.

### 8. Test it

Everything runs on Linux with the in-memory database and the mock pf
backend:

```rust
#[tokio::test]
async fn restores_table_from_kv_without_network() {
    let db = aifw_core::Database::new_in_memory().await.unwrap();
    let pf: Arc<dyn aifw_pf::PfBackend> = Arc::new(aifw_pf::PfMock::new());
    let sink = Arc::new(RuleSink::new(pf.clone(), "aifw-plugins"));
    let ctx = PluginContext::new("threat-feeds", pf.clone(), db.pool().clone(), sink);

    ctx.kv_set("list:feodo", "50.16.16.211/32\n10.0.0.0/8\n").await.unwrap();
    // … mark feeds fresh so no download is due …

    let mut p = ThreatFeeds::default();
    p.init(&settings(json!({})), &ctx).await.unwrap();

    let table = pf.get_table_entries("plugin_threat_feeds").await.unwrap();
    assert_eq!(table.len(), 1, "RFC1918 entry must be sanitized out");
}
```

For lifecycle tests, `PluginManager::with_factories` takes an explicit plugin
list. Network code can be tested against a throwaway local HTTP server. The
Notifier's channel tests show how.

### Checklist

- [ ] `info().hooks` lists only the hooks you use (each one wakes an event source).
- [ ] Settings have labels and help text written for operators; secrets are `.secret()`.
- [ ] `validate_settings` explains what to fix.
- [ ] `init` doesn't wait on the network; slow work runs in `ctx.spawn` tasks.
- [ ] Anything you want to survive a restart lives in the KV store.
- [ ] pf tables are named `plugin_<something>`; rules are `block`/`match` only.
- [ ] Outbound HTTP goes through `aifw_plugins::http`.
- [ ] Pure logic has unit tests; the plugin has an init/status test with `PfMock`.

## API

All under `/api/v1/plugins`. Reading needs `plugins:read`; changes and
actions need `plugins:write`. Errors return `{ "message": "…" }`, with 400
for validation, 404 for an unknown plugin or action, and 422 when the
plugin itself failed.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/plugins` | Plugins with state, stats, and the hook catalog |
| `GET` | `/api/v1/plugins/{name}` | Detail: schema, values, which secrets are set, actions, pf rules |
| `PUT` | `/api/v1/plugins/{name}/enabled` | `{ "enabled": true }` |
| `PATCH` | `/api/v1/plugins/{name}/settings` | `{ "values": {…}, "secrets": {…} }`; `null` resets a value or clears a secret |
| `POST` | `/api/v1/plugins/{name}/reset` | Forget all settings and disable |
| `GET` | `/api/v1/plugins/{name}/status` | Plugin-specific live status |
| `GET` | `/api/v1/plugins/{name}/logs?limit=&level=` | Activity log (newest first) |
| `POST` | `/api/v1/plugins/{name}/actions/{action}` | Run an action; body holds its arguments |

## Limits and notes

- Plugins are compiled into AiFw. There is no runtime loading of
  third-party binaries.
- Activity logs and hook statistics are kept in memory and reset when the
  API restarts. Plugin settings, secrets and KV data persist.
- In an HA pair, plugin configuration replicates with the rest of the
  config, so both nodes run enabled plugins (and both send notifications).

## See also

- [Features overview →]({{ '/features/' | relative_url }})
- [API reference →]({{ '/docs/api/' | relative_url }})
- [CLI reference →]({{ '/docs/cli/' | relative_url }})
- Source: [`aifw-plugins/src/`](https://github.com/ZerosAndOnesLLC/AiFw/tree/main/aifw-plugins/src)

</article>
</div>
