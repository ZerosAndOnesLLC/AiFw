# AiFw Plugin System Overhaul — Working Plan

Goal: make the plugin system genuinely work end to end (correct lifecycle,
honest hooks, sandboxed actions, typed settings, real UI/CLI UX) and ship two
reference plugins that double as the "how to write a plugin" example:
**Threat Intel Feeds** (`threat-feeds`) and **Notifier** (`notifier`).

Decisions:
- Retire the no-op built-ins `ip-reputation`, `custom-logger`, `webhook-notifier`.
- Native in-tree Rust plugins only — remove the WASM stub + manifest discovery
  and the docs claims about them.
- Keep only hooks that actually fire: Timer, LogEvent, ApiRequest, PostRule,
  IdsAlert, VpnEvent, GatewayEvent (new). Connection hooks removed.

Workflow: one sub-phase at a time, `cargo check` zero warnings, commit after
each phase, mark `[x]`. No version bump (release-time only).
Branch: `feat/plugin-system` off `main`. Mack merges the PR.

## Phase 1 — Prune
- [x] Delete wasm.rs, discovery.rs, examples/, `toml` dep, `/plugins/discover`
- [x] Remove unfireable hooks/payloads/actions; remove connection hook block in ws.rs
- [x] Retire old `plugin_config` rows; fix README/matrix/features/compare claims
- [x] Shrink tests to manager/context with a local test plugin

## Phase 2 — Framework (aifw-plugins)
- [x] Trait extensions: settings_schema, validate_settings, actions, run_action, status; shutdown(&self, ctx)
- [x] schema.rs (SettingField/FieldKind + validate)
- [x] registry.rs (single built-in list)
- [x] store.rs (PluginStore: plugin_config + sealed secrets + plugin_kv migration)
- [x] manager.rs rewrite (enable/disable keeps entry, Error state, hook mask, JoinSet+timeout dispatch, apply_actions, stats)
- [x] context.rs per-plugin (log ring, namespaced KV, spawn, table ops, rules)
- [x] error.rs variants + AifwError mapping; ALTER guard list

## Phase 3 — API + pf anchor
- [x] `aifw-api/src/plugins/` handlers with new endpoints + typed errors + audit
- [x] Reconcile task (DB updated_at vs applied)
- [x] `anchors::PLUGINS` at front of FILTER_HOOKS; rule rendering + validation
- [x] `patch_pf_conf` pure fn for upgrades; list_system_rules; auto-snapshot skip

## Phase 4 — Event bridges
- [x] RowTail helper; IdsAlert bridge
- [x] GatewayEvent hook + bridge (multiwan_gateway_events, dedupe)
- [x] VpnEvent bridge (WireGuard + IPsec diff)
- [x] Timer gated on subscribers

## Phase 5 — Threat Intel Feeds plugin
- [x] http.rs fetch_capped (net_safety, redirects, cap, ETag)
- [x] Feed catalog + parsers + sanitize
- [x] Plugin: settings, KV restore, refresh scheduling, rules, status, actions

## Phase 6 — Notifier plugin
- [x] Channels: ntfy, Discord, Slack, generic webhook (HMAC), Telegram
- [x] Classification, filters, limiter/dedupe, delivery task, retries
- [x] Status + `test` action

## Phase 7 — UI
- [x] lib/api/plugins.ts, hooks/usePlugins.ts, hooks/usePlugin.ts, hooks/useAutoSave.ts
- [x] PluginCard, PluginDrawer (Overview/Settings/Activity), SchemaForm/SchemaField/SecretField
- [x] Threat feeds + notifier status widgets; states, gating, a11y

## Phase 8 — Backup/export + CLI
- [x] Config export/restore of plugin_config incl. secrets handling
- [x] `aifw plugins list|show|enable|disable|set|reset`

## Phase 9 — Docs
- [x] docs/plugins.md "Build your first plugin" (threat-feeds walkthrough)
- [x] features/cli/README/CLAUDE.md endpoint updates

## Phase 10 — Review fixes (2026-10-07 + 2026-10-15 reviews)
- [x] H1 rule validator escapes (negation, label smuggling, `nat-to(`, rtable/dnpipe/tag/#)
- [x] M1/M2 config lock across read-modify-write; lifecycle detached from the request
- [x] M3 outbound HTTP: resolve-and-pin, re-checked redirects, Telegram public-only
- [x] M4 Threat Feeds pfctl/KV outside the state lock; UI batches feed toggles
- [x] M6 VPN bridge reports vanished endpoints; L6 quiet IDS tail; M7 allowlist hint
- [x] L1/L2/L3/L4/L7 load-error backoff, stopped-run writes refused, persisted table list, reset clears KV, restore validates
- [x] M-A CLI status/logs/run via API, enable confirms, --secret-stdin
- [x] M-B per-peer VPN notifications opt-in
- [x] M-C Plugin/PluginInstance split, typed settings, hooks(settings)
- [x] L-A stale old-system references; L-B honest sandbox wording; L-H hello-world + for_tests()
- [x] L-D/L-E/L-F redundant enable no-op, partial Send test result, stable field focus
- [x] L-G freebsd/tests/t11-plugins.sh
- [ ] M5 PostRule dispatch off the pflog reader — deferred until a plugin subscribes
- [ ] L5 IDS cursor across VACUUM — deferred (rare; re-anchor handles the common case)
