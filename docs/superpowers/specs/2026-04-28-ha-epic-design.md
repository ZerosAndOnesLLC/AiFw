# HA Epic Design — Active-Passive Failover

**Status**: Draft for review
**Date**: 2026-04-28
**GitHub**: epic [#224](https://github.com/ZerosAndOnesLLC/AiFw/issues/224); sub-issues #216 #217 #218 #219 #220 #221 #222 #223 #225 #226 #227

## Goal

Make AiFw's "Cluster & High Availability" feature actually deliver on its name: stand up two AiFw nodes, reboot the master, **no TCP connections drop, no DHCP leases lost, no DNS gap, no VPN re-handshake storm**. Today the feature is a database schema and a set of unused helper functions; this design wires it up end-to-end.

## Non-goals

- Active-active beyond what rDHCP already does. Multi-master with stateful pf is a different architecture.
- N>2 node clusters. Active-passive pair only.
- WAN-side / multi-site / geographic HA. Single broadcast domain only.
- Async replication. pfsync is sync-only.
- Out-of-band heartbeat *daemon* (schema-only this epic — daemon process is a follow-up after #219).

## Shipping decisions

- **One PR for the entire epic, eleven commits** (one per sub-issue) in dependency order.
- **Heartbeat: schema only.** Config fields land on `pfsync_config` so #217's UI/API don't churn later, but no daemon process consumes them yet. Aggressive latency profile is documented as "requires future heartbeat daemon".
- **Wizard: full HA step at first-boot** as #216 specifies — "Configure HA pair?" Y/N, then role + pfsync iface + per-LAN/WAN VIP/VHID + advskew preset + password.
- **Single rc.conf opt-in flag**: `aifw_cluster_enabled=YES`. Every demote/heartbeat/snapshot path no-ops on standalone nodes. Cluster UI hides itself when the flag is off.

## Architecture

Two nodes share a LAN broadcast domain. They exchange three independent streams over distinct channels:

```
┌──────────── Node A (MASTER) ──────────┐         ┌──────────── Node B (BACKUP) ──────────┐
│                                       │         │                                       │
│  aifw-daemon ─┬─ HealthProber  ───────┼──┐  ┌───┼─ HealthProber  ──┬── aifw-daemon      │
│               └─ ClusterReplicator ───┼──┼──┼───┼─ ClusterReplicator                    │
│                                       │  │  │   │                                       │
│  aifw-api ─── /api/v1/cluster/* ──────┼──┼──┼───┼─ aifw-api                             │
│                                       │  │  │   │                                       │
│  pf  (state-policy floating) ─────────┼──┼──┼───┼─ pf                                   │
│   └── pfsync0  ◄══ kernel state sync ═╪══╪══╪═══╪══►  pfsync0                           │
│                                       │  │  │   │                                       │
│  CARP VIPs on LAN/WAN ◄═ adv frames ══╪══╪══╪═══╪══►  CARP VIPs (BACKUP)                │
└───────────────────────────────────────┘  │  │   └───────────────────────────────────────┘
                                           │  │
                              [optional dedicated heartbeat NIC — schema only this epic]
```

- **Channel 1 — kernel layer**: pfsync (state migration) + CARP (VIP failover). Built once in #216, tuned in #227, demoted-on-shutdown in #220.
- **Channel 2 — HTTP control plane**: `/api/v1/cluster/*` for CRUD + status; `PUT /cluster/snapshot` for config replication; `POST /cluster/cert-push` for cert distribution. Built in #217, used by #218/#221/#222/#225/#226.
- **Channel 3 — automation**: `HealthProber` runs in `aifw-daemon`, drives `net.inet.carp.demotion` sysctl when local services fail. Built in #219.

**Conflict policy**: master always wins. Snapshot pushes from master overwrite standby; standby's `PUT /cluster/snapshot` is rejected if our local role is MASTER. On split-brain heal, higher node-id concedes.

## Component design (eleven commits)

### Layer 1 — OS layer

**Commit 1 (#216) — pfsync + CARP wired into the OS.**

- `aifw-setup/src/wizard.rs`: new step "Configure HA pair?" Y/N. If yes: pick role (Primary/Secondary), pfsync sync-iface, peer IP, per-LAN/WAN CARP VHID + VIP + prefix, advskew preset, password.
- `aifw-setup/src/apply.rs`: flip `state-policy if-bound` → `floating`; insert `set skip on pfsync0`; emit `pfsync_enable=YES`, `ifconfig_pfsync0`, per-iface `ifconfig_<wan>_aliases`/`ifconfig_<lan>_aliases` via `sysrc`; write `aifw_cluster_enabled=YES` + `aifw_cluster_role=primary|secondary`; call `ClusterEngine::apply_ha_rules()` at end of apply.
- `aifw-daemon/src/main.rs`: on startup, if `cluster_nodes`/`pfsync_config`/`carp_vips` exist in DB but kernel state is missing (`ifconfig pfsync0` errors / no CARP aliases), re-run `to_ifconfig_cmds()` idempotently.
- `freebsd/overlay/usr/local/etc/rc.d/aifw_carp_demote` (new): one-shot at boot, sets `net.inet.carp.demotion=0` once interfaces settle.

**Commit 2 (#220) — graceful demote on planned shutdown / restart.**

- `freebsd/overlay/usr/local/etc/rc.d/aifw_{daemon,api,ids}`: prepend `[ "$(sysrc -n aifw_cluster_enabled 2>/dev/null)" = "YES" ] && sysctl net.inet.carp.demotion=240 2>/dev/null && sleep 1` to each `stop_cmd`.
- `freebsd/overlay/usr/local/libexec/aifw-restart.sh`: same pre-bounce demote.
- `freebsd/overlay/usr/local/libexec/aifw-shutdown-hook.sh` (new) + `freebsd/overlay/usr/local/etc/rc.d/aifw_demote_on_shutdown` (new) with `KEYWORD: shutdown` for `shutdown -r`.
- `aifw-setup/src/apply.rs`: same patch when emitting rc.d templates.

**Commit 3 (#227) — CARP timer profiles + heartbeat schema.**

- `aifw-common/src/ha.rs`: new enum `CarpLatencyProfile { Conservative, Tight, Aggressive }` mapped to (advbase, advskew_master, advskew_backup, preempt) tuples. Add `latency_profile: CarpLatencyProfile` on `PfsyncConfig` (singleton holds the cluster-level knob). Add **schema-only** fields `heartbeat_iface: Option<Interface>`, `heartbeat_interval_ms: Option<u32>` (no daemon consumes them yet).
- `aifw-core/src/ha.rs`: SQLite columns; `apply_ha_rules` honors profile when rendering CARP commands; sets `net.inet.carp.preempt=1` via sysctl.
- Render correct advskew per local node role (read `aifw_cluster_role` from rc.conf at apply time).

### Layer 2 — Control plane

**Commit 4 (#217) — REST API + cluster UI page.**

- `aifw-api/src/cluster.rs` (new): handlers for `GET/POST /cluster/carp`, `PUT/DELETE /cluster/carp/{id}`, `GET/PUT /cluster/pfsync`, `GET/POST/PUT/DELETE /cluster/nodes[/id]`, `GET/POST /cluster/health`, `GET /cluster/status` (live: role, peer reachability, advskew, pfsync state count via `pfctl -ss | wc -l` and `ifconfig pfsync0`), `POST /cluster/promote`, `POST /cluster/demote` (sysctl). New `Permission::HaManage`.
- `aifw-api/src/ws.rs`: introduce `tokio::sync::broadcast` channel for cluster events (`role_changed`, `health_changed`, `metrics`); WS subscribers receive them. Existing polling loop kept.
- `aifw-api/src/main.rs`: nest the new router under auth middleware.
- `aifw-ui/src/app/cluster/page.tsx`: replace stub with config CRUD (CARP VIPs, pfsync, nodes, health checks). Live status banner via WS. Promote/Demote buttons.

**Commit 5 (#218) — config replication loop.**

- `aifw-daemon/src/main.rs`: spawn `ClusterReplicator` task. Hashes (rules, NAT, VPN, geoip, aliases, multiwan, reverse-proxy, IDS overrides + suppressions) every 10s. Skipped when role=BACKUP for the *push* direction; BACKUP only polls `GET /cluster/snapshot/hash` from master to detect drift.
- `aifw-api/src/cluster.rs`: `GET /cluster/snapshot/hash`, `GET /cluster/snapshot`, `PUT /cluster/snapshot` (rejects if local role is MASTER). Reuse `aifw-api/src/backup.rs` export logic.
- Auth: per-peer API key generated at cluster setup, stored in `cluster_nodes`.
- "Force sync from peer" button in UI calls `PUT` with body fetched from peer.
- Split-brain heal: higher node-id concedes; conflict logged in `update_history`.

**Commit 6 (#225) — CLI parity.**

- `aifw-cli/src/main.rs`: add `Cluster(ClusterAction)` to `Subcommand`; `ClusterAction` enum mirrors REST surface (`status`, `carp {list,show,add,remove,update}`, `pfsync {get,set}`, `nodes {…}`, `health {list,add,remove,run}`, `promote`, `demote`, `sync [--from]`, `verify [--json]`).
- `aifw-cli/src/commands.rs`: thin wrappers over the loopback HTTP client (existing pattern from `update_*`).
- `aifw cluster verify` is the canonical implementation; the shell script in #223 calls it.

### Layer 3 — Automation

**Commit 7 (#219) — HealthProber.**

- `aifw-daemon/src/main.rs`: new task. Reads enabled `health_checks` rows; probe types: HTTP, TCP-connect, local `service X status`, PID-file existence, `pfctl -si`.
- On N consecutive failures of a *local* check: `sysctl net.inet.carp.demotion=240` → CARP yields master.
- On recovery (peer healthy + local probes pass): `sysctl net.inet.carp.demotion=0` after configurable hold-down (default 30s) to prevent flap.
- Default checks pre-populated when cluster is first enabled: `aifw_api`, `aifw_daemon`, `aifw_ids`, `pf`.
- Emits `cluster.health_changed` over WS broadcast channel.

### Layer 4 — Service awareness

**Commit 8 (#221) — rDHCP HA inheritance.**

- `aifw-common/src/ha.rs` or `cluster_nodes` table: add `cluster_dhcp_link: bool` (cluster-level singleton flag).
- `aifw-api/src/dhcp.rs`: when flag=true, `update_ha_config` ignores incoming peer list and computes it from `cluster_nodes`. Uses cluster's per-peer API key as TLS material. On change to `cluster_nodes`, re-emit DHCP HA config.
- `aifw-ui/src/app/dhcp/ha/page.tsx`: when linked, gray peer list with "Inherited from cluster config"; "Unlink" button.

**Commit 9 (#222) — WG/IDS/ACME service awareness.**

- `aifw-core/src/vpn.rs`: when an active-passive cluster has a CARP VIP on WAN, render WG `ListenAddress` to that VIP rather than the physical iface.
- `aifw-daemon` role-change subscriber: on transition to BACKUP, optionally `wg-quick down` interfaces; on transition to MASTER, `up` them. Configurable via `wg_deconfigure_on_backup` flag (default false).
- `aifw-core/src/ha.rs` `ConfigSnapshot`: extend hashed inputs to include IDS rule overrides + suppressions table. `aifw-api/src/cluster.rs` snapshot apply fires `POST /ids/reload` when IDS rows change.
- `aifw-core/src/acme_engine.rs`: skip renewal loop when role=BACKUP. After successful issue/renew on master, `POST /api/v1/cluster/cert-push` to each peer in `cluster_nodes`.
- `aifw-api/src/cluster.rs`: `POST /cluster/cert-push` accepts cert+key from master, writes to local TLS store. Rejects if local role=MASTER.

### Layer 5 — Validation

**Commit 10 (#226) — cluster dashboard.**

- `aifw-ui/src/app/cluster/dashboard/page.tsx` (new): hero status, pfsync gauge (60s chart, drift highlighted), CARP-per-VIP table, per-node panel (role, last-seen, version, services, WG bound to VIP, ACME last-pushed), config sync widget with "Force sync now", health-check matrix, failover timeline (24h), quick actions.
- `aifw-api/src/ws.rs`: emit `cluster.metrics` event every ~2s with pfsync counters + state counts.
- `aifw-api/src/cluster.rs`: `GET /cluster/failover-history` reads from `cluster_failover_events` table.
- `aifw-ui/src/app/dashboard/page.tsx`: add HA status card (hidden when `aifw_cluster_enabled` is false).

**Commit 11 (#223) — verification harness + docs.**

- `docs/ha.md` (new): architecture diagram, setup procedure, prerequisites (dedicated pfsync link, same broadcast domain), failure-mode table (TCP/DHCP/VPN survive; in-flight DNS lookups, IDS ring-buffer don't), split-brain handling, runbooks (planned maintenance, rolling upgrade, manual promote/demote, decommission). "Minimizing unplanned-failure gap" section with latency-profile guidance + UPS recommendation.
- `scripts/ha-verify.sh` (new): SSH/cluster-API probe both nodes, asserts pfsync counters non-zero, exactly one master, pfctl state counts within tolerance, config hashes match. Calls `aifw cluster verify --json` on each node and joins results. Exit 0/1 + specific failure code.
- `README.md`: move HA from "Features" claim to "HA pair" capability with link to `docs/ha.md`.
- `docs/index.html`: align marketing copy with what's actually shipped.

## Data flow

### Boot path

```
1. rc.d aifw_firstboot → aifw-setup wizard → operator chooses HA + role
   ↓ writes:  rc.conf (aifw_cluster_enabled=YES, role, pfsync_enable, ifconfig aliases)
              SQLite (carp_vips, pfsync_config, cluster_nodes, peer API keys)
2. rc.d pf → pf.conf already has state-policy floating + set skip on pfsync0 + anchor "aifw-ha"
3. rc.d aifw_daemon → ClusterEngine::apply_ha_rules() loads anchor; HealthProber + ClusterReplicator spawn
4. rc.d aifw_carp_demote (one-shot, last) → sysctl net.inet.carp.demotion=0 → node enters CARP election
```

If the node was already configured (re-boot after install), step 1 is skipped and step 3's daemon-startup recovery re-runs `to_ifconfig_cmds()` to re-create pfsync0 / aliases idempotently.

### Config replication tick (every 10s)

```
master.ClusterReplicator
  ├── snapshot = ConfigSnapshot { rules_hash, nat_hash, ..., ids_hash, data: <serialized export> }
  └── for each peer in cluster_nodes:
        peer_hash = GET https://<peer>/api/v1/cluster/snapshot/hash  (peer API key)
        if peer_hash != snapshot.hash:
            PUT https://<peer>/api/v1/cluster/snapshot { snapshot.data }
              ├── peer rejects if peer.role == MASTER  → conflict logged, higher-id concedes
              └── peer applies; reload affected engines (rules, nat, vpn, ids, …)

backup.ClusterReplicator
  └── only polls master_hash via GET; never pushes
```

### Role-change event flow

```
CARP kernel transition (advert lost / demotion changed)
   → aifw-daemon polls `ifconfig <iface>` every 1s for CARP state
   → on change, broadcasts cluster.role_changed via tokio::broadcast
       ├── WS subscribers (UI dashboard) get it within ~2s
       ├── WG service-awareness subscriber re-binds tunnels
       └── ACME service-awareness subscriber pauses/resumes renewal
```

No node-to-node "I just promoted" message — CARP advertisements *are* the signal, observed via `ifconfig` on each node independently.

### Planned-shutdown sequence

```
operator → `service aifw_api restart` (or `shutdown -r now`)
   → rc.d stop_cmd → sysctl net.inet.carp.demotion=240; sleep 1
       (BACKUP sees adv with worse skew → promotes itself in <1s)
   → kill aifw-api / proceed with shutdown
   (data plane never sees a down master; CARP transition completes before this node stops forwarding)
```

### Unplanned-failure sequence

```
master power-cycle / panic / kernel-NIC death
   → CARP advertisements stop
   → BACKUP miss-counter exceeded after advbase × (3 + advskew/256) s
   → BACKUP promotes; pfsync state already replicated → TCP sessions survive
   → UDP packets in-flight during the gap are lost (1.5s Tight, 3s Conservative)
```

## Invariants

Enforced in code, not just convention:

1. **Master never accepts snapshot pushes.** `PUT /cluster/snapshot` reads local CARP role; returns 409 if MASTER. Prevents BACKUP from clobbering MASTER during partition.
2. **ACME renewal is master-only.** `aifw-core/src/acme_engine.rs` queries local role at the top of every renewal tick.
3. **Demote is opt-in via `aifw_cluster_enabled`.** rc.d scripts short-circuit on `[ "$(sysrc -n aifw_cluster_enabled)" = "YES" ]` before touching the sysctl, so standalone nodes never invoke it and no error is logged.
4. **`state-policy floating` is non-negotiable.** Without it, pfsync replication is decorative — states bind to interface and won't match traffic on the new master's iface. Asserted by `aifw cluster verify`.
5. **CARP `preempt=1`** so a returning master with better skew reclaims, avoiding both-think-master state. Set at apply time.
6. **`set skip on pfsync0`** so pf doesn't filter the sync traffic itself.
7. **Per-peer API key** generated at cluster setup, scoped to `Permission::HaManage` only — limits blast radius if a peer is compromised.
8. **Higher node-id concedes** on split-brain heal — deterministic tie-break.

## Schema additions

| Table | New columns |
|---|---|
| `pfsync_config` | `latency_profile TEXT`, `heartbeat_iface TEXT NULL`, `heartbeat_interval_ms INTEGER NULL`, `dhcp_link BOOLEAN` |
| `cluster_nodes` | `peer_api_key TEXT`, `peer_api_key_hash TEXT`, `software_version TEXT NULL`, `last_pushed_cert_at TEXT NULL` |
| (new) `cluster_failover_events` | `id, ts, from_role, to_role, cause, detail` |
| (new) `cluster_snapshot_state` | `last_applied_hash TEXT, last_applied_at TEXT, last_applied_from TEXT` |

Migrations stay inline-SQL in `aifw-core/src/ha.rs::migrate()` per project convention.

## Acceptance — definition of done

The verification harness in #223 exits 0 on a real two-node deployment, with these specific behaviors observable end-to-end:

1. Reboot of master: `ping <gateway-VIP>` from a LAN client misses ≤ 2 packets.
2. SSH session through the firewall (TCP state in pf) survives master reboot without re-auth.
3. WireGuard peer connected through master continues delivering traffic within 5s of failover.
4. DHCP `RENEW` against the new master succeeds with the same lease the old master issued.
5. Operator changes a firewall rule on standby's UI (after promotion) — no manual sync needed; state inherited from before-failover master.
6. Going from zero to a working HA pair takes < 15 minutes via the UI alone (no SSH or CLI).

## Out of scope

- Active-active stateful pf (different architecture).
- N>2 node clusters.
- WAN-side / multi-site / geographic HA.
- Out-of-band heartbeat *daemon* (schema only this epic).
- NUT (Network UPS Tools) integration — documented as recommendation, not built.
- CI smoke-test that spins up two FreeBSD VMs and kills master (manual procedure documented instead).

## Risks

- **pf.conf change risk**: flipping `state-policy if-bound` → `floating` changes pf semantics for *every* connection, not just clustered ones. Need to verify no existing rules depend on per-interface state binding. Mitigation: ship with verification harness, document in upgrade notes.
- **Wizard burden at first boot**: full HA wizard step is the riskiest UX call. Operators who don't yet know their topology can skip the section, but if they accept it without all answers ready, they get a half-configured node. Mitigation: wizard step is one Y/N gate; saying No is the obvious default; the cluster UI in #217 handles full post-install setup.
- **Rolling-upgrade software-version drift**: dashboard surfaces it (#226), but config replication doesn't gate on version match. A snapshot from a newer master applied to an older standby could fail mid-import. Mitigation: dashboard flags drift with red badge; document "upgrade backup first" runbook in `docs/ha.md`.
- **WS broadcast channel back-pressure**: a slow WS client could block `cluster.metrics` emission. Use `broadcast::channel(capacity)` with `RecvError::Lagged` handling; drop on lag rather than block.
