# AiFw CLI v2 — Working Plan

Goal: make `aifw` a first-class client of the REST API (console admins, scripts,
remote/fleet operators) with a small `aifw local` break-glass group for when the
API is down. Full design: see the "CLI v2" section of docs/docs/cli.md once
written; decisions below.

Decisions:
- Phase 0 fixes + extends API keys before the CLI relies on them.
- API-only for every resource command; direct DB/pf only under `aifw local`.
- Named contexts (`~/.config/aifw/config.toml`, secrets 0600) + read-only fan-out.
- Exit codes: 0 ok, 1 other, 2 usage, 3 401, 4 403, 5 404, 6 validation,
  7 unreachable/TLS, 8 partial fan-out, 9 commit-confirm rolled back.
- Back-compat callers stay green: maintenance cron `aifw update …`, aifw-console,
  `cluster verify --json`, `update install --from`, `--version`, `reload`/`reconcile`.

Workflow: one sub-phase at a time, `cargo check` zero warnings, tests added/updated
for every change, commit after each phase, mark `[x]`. No version bump.
Branch: `feat/cli-v2` off `main`. Mack merges the PR.

(Previous working plan — plugin system overhaul — is in git history; its two
deferred items M5/L5 remain deferred.)

## Phase 0 — API key prerequisites
- [x] Bind created keys to the calling user (not `users LIMIT 1`); self-service create
- [x] api_keys: role_id (subset of owner), expires_at, last_used_at via add_column_if_missing
- [x] GET /auth/api-keys, DELETE /auth/api-keys/{id}; enforce expiry + subset per request
- [x] Rate-limit POST /auth/totp/login
- [x] Reserve `aifw-cli-local` key name. (Change: no `local-cli` role and no setup-time
      provisioning — root already owns the box, so `aifw local cli-key` mints the root-only
      /usr/local/etc/aifw/cli.key straight into the DB in phase 1.)
- [x] Fix: delete_user removed the user row before its FK children → 500 for any user who
      had ever logged in; now children first, in one transaction
- [x] UI: Profile → API Keys card (create with role/expiry, show-once secret, revoke)
- [x] Tests: binding, subset, deleted-role fail-closed, expiry, revoke, list scoping,
      internal keys hidden, keys can't mint keys, last_used, user delete, totp rate limit

## Phase 1 — aifw-client crate + CLI foundation
- [x] aifw-client: Client, Auth (ApiKey/Session, prefix detection), ClientError, refresh rotation
- [x] Pin verifier moved from aifw-core peer_tls (re-exported)
- [x] `aifw local cli-key` + automatic first-use minting as root (aifw-cli-local key, cli.key 0600)
- [x] CLI: contexts/credentials, login/logout/whoami/context, output (table/wide/json/yaml),
      prompts, exit codes; aifw-cli is now lib + thin bin (`aifw_cli::run`)
- [x] pending / apply / confirm (arm → change → apply → accept; `apply` fails on "Partial reload")
- [x] Tests: aifw-client unit + mock-server tests; CLI unit tests; API-side integration
      harness (tests/cli_harness.rs) running real commands against the real router
- (moved to phase 2) Remove legacy HTTP helpers — they go with porting their command groups

## Phase 2 — Port existing command groups to the API
- [x] rules, nat, geoip, shaper, routes, dns, users (+ status/reload/interfaces via API;
      ratelimit/reconcile/init + break-glass status/reload moved under commands/local —
      no API for them; fixed: user PUT/DELETE rejected API keys, NAT hint misfire,
      geoip import multi-file upload)
- [ ] vpn wg, ids, plugins, syslog, logrotate
- [ ] multiwan, cluster, reverse-proxy, dhcp
- [ ] update, config (back-compat tests for every external caller)

## Phase 3 — New coverage
- [ ] aliases, schedules, interfaces/vlans
- [ ] ipsec, acme/ddns, ca, time
- [ ] dns resolver/blocklists, backup/s3/smtp, settings, system
- [ ] roles/api-keys/oauth/totp, connections/blocked/logs, ai

## Phase 4 — Streams and jobs
- [ ] logs --follow (poll), pending --watch (SSE), top (/ws), update os-upgrade --wait, long timeouts

## Phase 5 — Fleet fan-out
- [ ] --context a,b / --all-contexts on read-only commands, merged output, exit 8

## Phase 6 — `aifw local` + DB-free guard
- [ ] Move break-glass to commands/local/, guard test, update scanning guard tests

## Phase 7 — Docs and polish
- [ ] docs/docs/cli.md rewrite, AIFW_TOKEN docs, README, CLAUDE.md, completions + man page
