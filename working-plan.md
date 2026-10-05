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
- [ ] Trait extensions: settings_schema, validate_settings, actions, run_action, status; shutdown(&self, ctx)
- [ ] schema.rs (SettingField/FieldKind + validate)
- [ ] registry.rs (single built-in list)
- [ ] store.rs (PluginStore: plugin_config + sealed secrets + plugin_kv migration)
- [ ] manager.rs rewrite (enable/disable keeps entry, Error state, hook mask, JoinSet+timeout dispatch, apply_actions, stats)
- [ ] context.rs per-plugin (log ring, namespaced KV, spawn, table ops, rules)
- [ ] error.rs variants + AifwError mapping; ALTER guard list

## Phase 3 — API + pf anchor
- [ ] `aifw-api/src/plugins/` handlers with new endpoints + typed errors + audit
- [ ] Reconcile task (DB updated_at vs applied)
- [ ] `anchors::PLUGINS` at front of FILTER_HOOKS; rule rendering + validation
- [ ] `patch_pf_conf` pure fn for upgrades; list_system_rules; auto-snapshot skip

## Phase 4 — Event bridges
- [ ] RowTail helper; IdsAlert bridge
- [ ] GatewayEvent hook + bridge (multiwan_gateway_events, dedupe)
- [ ] VpnEvent bridge (WireGuard + IPsec diff)
- [ ] Timer gated on subscribers

## Phase 5 — Threat Intel Feeds plugin
- [ ] http.rs fetch_capped (net_safety, redirects, cap, ETag)
- [ ] Feed catalog + parsers + sanitize
- [ ] Plugin: settings, KV restore, refresh scheduling, rules, status, actions

## Phase 6 — Notifier plugin
- [ ] Channels: ntfy, Discord, Slack, generic webhook (HMAC), Telegram
- [ ] Classification, filters, limiter/dedupe, delivery task, retries
- [ ] Status + `test` action

## Phase 7 — UI
- [ ] lib/api/plugins.ts, hooks/usePlugins.ts, hooks/usePlugin.ts, hooks/useAutoSave.ts
- [ ] PluginCard, PluginDrawer (Overview/Settings/Activity), SchemaForm/SchemaField/SecretField
- [ ] Threat feeds + notifier status widgets; states, gating, a11y

## Phase 8 — Backup/export + CLI
- [ ] Config export/restore of plugin_config incl. secrets handling
- [ ] `aifw plugins list|show|enable|disable|set|reset`

## Phase 9 — Docs
- [ ] docs/plugins.md "Build your first plugin" (threat-feeds walkthrough)
- [ ] features/cli/README/CLAUDE.md endpoint updates
