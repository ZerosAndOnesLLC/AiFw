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
  "dateModified": "2026-10-15"
}
</script>

<div class="content-page">
<article markdown="1">

# AiFw Plugin System <span class="badge-beta">Beta</span>

Plugins add optional features to AiFw without touching the core engines. A
plugin is a Rust type compiled into AiFw. It declares the events it wants
and the settings it accepts. AiFw provides the settings form, the CLI, backup
and restore, an activity log, and a scoped handle into pf.

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

The same configuration is available from the shell, plus the runtime views:

```sh
aifw plugins list                       # enabled + runtime state
aifw plugins show threat-feeds          # every setting, its value, and allowed values
aifw plugins set threat-feeds refresh_hours=6 feeds=spamhaus-drop,feodo
aifw plugins set notifier --secret ntfy_url=https://ntfy.sh/my-topic
printf '%s' "$TOKEN" | aifw plugins set notifier --secret-stdin ntfy_token
aifw plugins enable notifier            # waits for the API to confirm it started
aifw plugins set threat-feeds --unset refresh_hours   # back to the default
aifw plugins reset notifier             # forget everything, disable

aifw plugins status                     # state, last error, counters, live status
aifw plugins logs threat-feeds --level warn
aifw plugins run threat-feeds refresh
aifw plugins run notifier test channel=ntfy
```

Configuration commands write the database directly and work whether or not
the API is running; the API applies them within about ten seconds. `status`,
`logs` and `run` ask the running API and need an API key in `AIFW_TOKEN`.

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
  - WireGuard interface or IPsec tunnel up or down, including a tunnel that
    disappears (interface destroyed, tunnel deleted). Per-peer WireGuard
    changes are a separate switch, off by default: a peer counts as down 3
    minutes after its last handshake, which is noisy on road-warrior tunnels.
  - Selected audit-log changes.
- **Delivery:**
  - Repeats of the same event are suppressed for a configurable window.
  - Bursts are capped per minute.
  - Failed deliveries are retried, honouring `Retry-After`.
- Destinations must be public https URLs unless you enable **Allow LAN /
  http destinations**, which you need for a self-hosted ntfy.
- **Send test** checks each channel immediately and reports per channel,
  so one broken webhook doesn't hide the ones that worked.

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

1. Validates the stored settings against the plugin's schema and its
   `validate_settings` check.
2. Asks the plugin which hooks it wants for these settings (`hooks`).
3. Calls `start(settings, ctx)`, which returns the running instance. It
   runs in its own task with a 30 s budget. An error or panic leaves the
   plugin in the **error** state, and the message is shown on its card.
4. Delivers subscribed hook events to the instance until the plugin is
   stopped.
5. On stop, calls the instance's `shutdown`, aborts every task started
   with `ctx.spawn`, removes the plugin's pf rules, and flushes every pf
   table it touched — in this run or an earlier one (the list is
   persisted, so a disable written while the API was down still cleans up).

Every configuration write and start/stop for a plugin is serialized, and
runs to completion even if the HTTP client that asked for it goes away.
Enabling an already-running plugin, or saving settings that didn't change,
does nothing.

### Hooks

| Hook | Fired when | Payload (`HookEventData`, same name as the hook) |
|---|---|---|
| `timer` | every 60 s | `Timer { timestamp }` |
| `log_event` | an audit-log row is written (rule/NAT/config changes, plugin changes) | `LogEvent { action, details, source }` |
| `ids_alert` | the IDS writes an alert | `IdsAlert { alert_id, timestamp, signature_id, signature_msg, severity, src_ip, dst_ip, src_port, dst_port, protocol, action, rule_source }` |
| `gateway_event` | a multi-WAN gateway changes state | `GatewayEvent { gateway_id, gateway_name, interface, from_state, to_state, reason }` |
| `vpn_event` | a WireGuard peer/tunnel or IPsec tunnel goes up or down, or stops being reported | `VpnEvent { kind, tunnel_name, peer, action, detail }` |
| `post_rule` | pf logs a packet (rules with `log`) | `PostRule { src_ip, dst_ip, src_port, dst_port, protocol, action, rule_id }` |
| `api_request` | an authenticated API request arrives | `ApiRequest { method, path, remote_addr }` |

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
| `Block` | For `api_request`: the request is rejected with 403. Ignored elsewhere. Fails open: a plugin that times out or panics does not block, so this is for policy hints, not authentication. |
| `Log(msg)` | Written to the plugin's activity log. |
| `AddToTable { table, ip }` / `RemoveFromTable { … }` | Applied through the plugin's context, so only `plugin_*` tables are allowed. |
| `Multi(vec)` | Several of the above (bounded depth and count). |

### The sandbox

`PluginContext` is the plugin's handle into AiFw. The pf side is enforced
by code: a plugin cannot touch a table that isn't its own or load a rule
that opens, redirects or reroutes traffic. The rest — the KV store, logging,
background tasks and the HTTP client — is the supported surface for
in-tree plugins, not a security boundary: plugins are compiled into the
API process and `ctx.pool()` hands them the whole database for reading
firewall state. Code review keeps plugins on the supported surface.

- **pf tables:** `add_to_table`, `remove_from_table`, `replace_table`,
  `flush_table`, `table_len`. Only tables named `plugin_<name>` are allowed.
- **pf rules:** `set_rules` / `clear_rules` load into the shared
  `aifw-plugins` anchor. That anchor is hooked first in `pf.conf`, so plugin
  drops win over everything that follows — including the operator's own
  `pass` rules, which is why Threat Feeds asks for a management allowlist.
  A rule must start with `block` or `match`, may carry one `label "…"`,
  and must reference a `plugin_*` table after `from` or `to`. Negation,
  comments and every keyword that passes, translates, routes, shapes or
  tags traffic (`pass`, `nat-to`, `rdr-to`, `route-to`, `rtable`, `dnpipe`,
  `queue`, `tag`, …) are refused, however they are spaced.
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

A plugin is two types: the **definition** (`Plugin`), a stateless value the
registry holds — metadata, settings schema, and `start` — and the
**instance** (`PluginInstance`) that `start` returns with the settings
already applied. Every instance method sees a fully built `self`; there is
no "not initialized yet" state to guard against.

```rust
pub struct ThreatFeeds;                   // the definition: nothing to store

struct Running { inner: Arc<Inner> }      // the instance: built by start()

#[async_trait]
impl Plugin for ThreatFeeds {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            name: "threat-feeds".into(),          // [a-z0-9-], the registry key
            title: "Threat Intel Feeds".into(),
            version: "1.1.0".into(),
            description: "Blocks traffic to and from addresses on public …".into(),
            author: "AiFw".into(),
            hooks: vec![HookPoint::Timer],        // only what you need
        }
    }
    // settings_schema, validate_settings, actions, start — below
}
```

The smallest possible plugin, for reference (it logs a line every minute):

```rust
pub struct Hello;
struct HelloRunning;

#[async_trait]
impl Plugin for Hello {
    fn info(&self) -> PluginInfo {
        PluginInfo {
            name: "hello".into(), title: "Hello".into(), version: "0.1.0".into(),
            description: "Says hello once a minute.".into(), author: "you".into(),
            hooks: vec![HookPoint::Timer],
        }
    }
    async fn start(&self, _s: &PluginSettings, ctx: &PluginContext)
        -> Result<Box<dyn PluginInstance>>
    {
        ctx.info("hello: started");
        Ok(Box::new(HelloRunning))
    }
}

#[async_trait]
impl PluginInstance for HelloRunning {
    async fn on_hook(&self, _e: &HookEvent, ctx: &PluginContext) -> HookAction {
        ctx.info("hello: tick");
        HookAction::Continue
    }
}
```

Add `Arc::new(Hello)` to `registry::builtins()` and it appears in the UI
and CLI with an empty settings form and an activity log.

### 3. Declare settings

The schema drives validation (API and CLI), the UI form, and the CLI's
`show` output. Settings are never accepted unvalidated. Defaults live in
the schema and nowhere else: `PluginSettings::deserialize` fills a plain
struct with every key present, so the plugin never repeats a default.

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

#[derive(Deserialize)]
struct Settings {                           // one field per schema key
    feeds: Vec<String>,
    custom_urls: Vec<String>,
    refresh_hours: i64,
    mode: String,
    log_matches: bool,
    allowlist: Vec<String>,
}

fn validate_settings(&self, s: &PluginSettings) -> Result<()> {
    let s: Settings = s.deserialize()?;
    if s.feeds.is_empty() && s.custom_urls.is_empty() {
        return Err(PluginError::Validation("Select at least one feed or add a custom URL.".into()));
    }
    Ok(())
}
```

If some settings turn whole event kinds on or off, override `hooks` so the
event sources the operator disabled stay idle:

```rust
fn hooks(&self, s: &PluginSettings) -> Vec<HookPoint> {
    // Notifier: only the hooks whose events are switched on.
    let s: Settings = s.deserialize().unwrap_or_default();
    let mut h = Vec::new();
    if s.notify_ids { h.push(HookPoint::IdsAlert); }
    if s.notify_vpn { h.push(HookPoint::VpnEvent); }
    h
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
async fn start(&self, settings: &PluginSettings, ctx: &PluginContext)
    -> Result<Box<dyn PluginInstance>>
{
    let inner = Arc::new(Inner { cfg: config(settings)?, /* … */ });

    // Last good lists from the plugin's KV store: protection is back
    // immediately after a reboot, before any download. Lists of feeds
    // that are no longer selected are pruned here (ctx.kv_keys).
    inner.load(ctx).await?;

    // Table first, then the rules that reference it.
    inner.apply(ctx).await?;                  // ctx.replace_table("plugin_threat_feeds", …)
    ctx.set_rules(rules(&inner.cfg)).await?;  // block drop in log quick from <plugin_threat_feeds> …

    // Never block start on the network: schedule the download.
    if inner.any_due(/* … */) {
        inner.start_refresh(ctx, false);      // ctx.spawn(…)
    }
    Ok(Box::new(Running { inner }))
}
```

A settings change restarts the plugin. Keep anything expensive to rebuild,
such as downloaded lists and ETags, in the KV store so a restart costs
nothing. Don't hold a lock across `ctx.replace_table` or a large `kv_set`:
`on_hook` and `status` have time budgets and would queue behind it.

### 5. React to hooks without blocking

```rust
#[async_trait]
impl PluginInstance for Running {
    async fn on_hook(&self, event: &HookEvent, ctx: &PluginContext) -> HookAction {
        if event.hook == HookPoint::Timer && self.inner.due().await {
            self.inner.start_refresh(ctx, false);   // background task, returns at once
        }
        HookAction::Continue
    }
    // run_action, status — below
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
        "refresh" => self.inner.refresh(ctx, true).await,
        "lookup" => { /* … */ }
        other => Err(PluginError::NotFound(format!("action '{other}'"))),
    }
}
```

`actions` lives on the definition (the UI shows them even while the plugin
is stopped); `run_action` lives on the instance. Return
`PluginError::Validation` for a bad argument — it is shown as a 400 and
logged quietly — and anything else for a failure the operator should see.

The UI renders actions as buttons, with a small form when they take
arguments, and shows the returned JSON as a readable result. A plugin
without a custom status view gets a generic one. Threat Feeds and Notifier
have small dedicated views in `aifw-ui/src/app/plugins/components/status/`.

### 7. Register it

```rust
// aifw-plugins/src/registry.rs
pub fn builtins() -> Vec<Arc<dyn Plugin>> {
    vec![
        Arc::new(crate::builtin::ThreatFeeds),
        Arc::new(crate::builtin::Notifier),
        Arc::new(crate::builtin::YourPlugin),   // ← one line
    ]
}
```

That is the only change outside your module. The API, UI, CLI, and backup
and restore pick the plugin up from the registry.

### 8. Test it

Everything runs on Linux with the in-memory database and the mock pf
backend. `PluginContext::for_tests` builds the whole fixture:

```rust
#[tokio::test]
async fn restores_table_from_kv_without_network() {
    let t = PluginContext::for_tests("threat-feeds").await;   // ctx + mock pf + db

    t.ctx.kv_set("list:feodo", "50.16.16.211/32\n10.0.0.0/8\n").await.unwrap();
    // … mark feeds fresh so no download is due …

    let p = ThreatFeeds.start(&settings(json!({})), &t.ctx).await.unwrap();

    let table = t.pf.get_table_entries("plugin_threat_feeds").await.unwrap();
    assert_eq!(table.len(), 1, "RFC1918 entry must be sanitized out");
    assert_eq!(p.status(&t.ctx).await["table_entries"], 1);
}
```

For lifecycle tests, `PluginManager::with_plugins` takes an explicit plugin
list. Network code is tested against the crate's scripted local HTTP server
(`http::testing::TestServer`); the HTTP module's own tests and the
Notifier's channel tests show how. On FreeBSD, `freebsd/tests/t11-plugins.sh`
proves the pf side with real packets.

### Checklist

- [ ] `info().hooks` lists only the hooks you use (each one wakes an event source); `hooks(settings)` drops the ones the operator switched off.
- [ ] Settings have labels and help text written for operators; secrets are `.secret()`; defaults live only in the schema.
- [ ] `validate_settings` explains what to fix.
- [ ] `start` doesn't wait on the network; slow work runs in `ctx.spawn` tasks; no lock is held across pfctl or large KV writes.
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
  third-party binaries, and the sandbox is a pf-side guarantee plus a
  supported API surface, not an isolation boundary.
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
