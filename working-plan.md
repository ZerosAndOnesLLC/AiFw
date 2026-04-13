# AiFw Enterprise Multi-WAN — Working Plan

Goal: add multi-WAN support that exceeds Cisco (IOS PBR + IP SLA + track objects) and Juniper (routing-instances, RPM, `then routing-instance`, rib-groups) in features, usability, correctness, and observability.

Track progress here per CLAUDE.md workflow: one sub-phase at a time, `cargo check`, commit after each, mark `[x]` when done.

## Design Principles

1. `cargo check` zero warnings, all tests green, `npm run build` succeeds before every commit.
2. Mock (Linux/WSL) compiles with full coverage for every FreeBSD-only code path.
3. Each sub-phase is independently shippable; migrations forward-only.
4. Default behavior for existing single-WAN users is identical before/after upgrade. Multi-WAN is opt-in.
5. pf state is global on FreeBSD — every PBR rule emits paired `reply-to` and uses `(if-bound)` state policy.

## Convergence Contract

- Probe interval default: 500 ms
- Declare down after 3 consecutive failures (1.5 s)
- pf re-apply within 200 ms of state change
- End-to-end target: ≤3 s median, ≤5 s p99 (probe-fail → dataplane)
- Failed WAN's `(if-bound)` states → killed via `pfctl -k` scoped to failed iface

## Data Model

```
Interface ─(ifconfig fib N)─► RoutingInstance (fib_number unique)
                                   │
                                   ▼
                              Gateway (monitor, state, RTT/loss/jitter/MOS)
                                   │
                                   ▼
                              GatewayGroupMember (tier, weight)
                                   │
                                   ▼
                              GatewayGroup (policy, preempt, sticky, hysteresis)

PolicyRule (priority-ordered, evaluated before aifw anchor)
  match: src/dst/port/proto/iface-in/schedule/dscp/geoip/user
  action: SetInstance | SetGateway | SetGroup | MarkDscp | Shape | Mix

RouteLeak (decoupled)
  src_instance, dst_instance, prefix, proto, ports, direction

GatewayEvent (100 per gw, append-only)
SlaSample (1-min buckets, 30-day retention)
```

## Anchor Hierarchy

Root ruleset ordering:
`aifw-pbr` → `aifw-mwan-leak` → `aifw-mwan-reply` → `aifw-nat` → `aifw` → `aifw-vpn` → `aifw-geoip`

Loader emitter lives in `aifw-setup/src/apply.rs`.

## Kernel / Build Prereqs (one-time, Phase 1)

- [ ] `aifw-setup/src/tuning.rs::generate_tuning()` — append `TuningItem { LoaderConf, "net.fibs", "16", "Multi-WAN" }` gated behind wizard step
- [ ] `freebsd/overlay/usr/local/etc/rc.d/aifw_fibs` — pins iface→FIB at boot via `aifw-cli multiwan apply-boot`
- [ ] `freebsd/manifest.json` — add `aifw_fibs` to `rc_scripts`
- [ ] `docs/multi-wan.md` — document `net.fibs` loader tunable

---

## Phase 1 — Foundations: FIB-aware PfBackend + RoutingInstance engine (→ v5.35.0)

User value: declare named routing instances, assign interfaces to FIBs via UI/API. Feature-flagged "Multi-WAN preview."

- [x] 1a. `aifw-common/src/multiwan.rs` — types: `RoutingInstance`, `InstanceStatus`, `InstanceMember`
- [x] 1b. `PfBackend` additions — `set_interface_fib`, `get_interface_fib`, `list_fibs` (mock + ioctl)
- [x] 1c. `aifw-core/src/multiwan/instance.rs::InstanceEngine` + migrate (tables + seed `default/fib 0/mgmt_reachable=1`)
- [x] 1d. `aifw-common/src/permission.rs` — `MultiWanRead`, `MultiWanWrite`
- [x] 1e. `aifw-api/src/multiwan.rs` — instances CRUD + members + `/fibs` endpoint; wire in `main.rs` AppState + build_router
- [x] 1f. `aifw-ui/src/app/multi-wan/page.tsx` + nav entry
- [x] 1g. Tests: unit CRUD, duplicate fib, cascade delete; API integration tests
- [x] 1h. Version bump to 5.35.0, commit

Tables:
```sql
multiwan_instances (id PK, name UNIQUE, fib_number UNIQUE, description, mgmt_reachable, created_at, updated_at)
multiwan_instance_members (instance_id FK, interface, PRIMARY KEY (instance_id, interface))
```

Risks:
- `ifconfig fib` on live default iface can drop routes → require `?confirm_drops=true`, pre-flight check via `netstat -rnF 0`
- Default seed must be idempotent → `INSERT OR IGNORE` with fixed UUID constant

---

## Phase 2 — Gateways + health monitoring

User value: define gateways; live RTT/loss/jitter/MOS. No dataplane effect.

- [x] 2a. Probes module in `aifw-core/src/multiwan/probe.rs` (kept inline for minimal deps)
- [x] 2b. `IcmpProbe` (sudo `/sbin/ping`)
- [x] 2c. `TcpProbe` (tokio TcpStream + timeout)
- [x] 2d. `HttpProbe` (curl shell-out with expect status)
- [x] 2e. `DnsProbe` (`/usr/bin/host` shell-out)
- [x] 2f. `GatewayEngine` with hysteresis, broadcast event channel, MOS scoring
- [ ] 2g. `aifw-daemon` starts/stops monitors on engine boot (deferred — start_monitor wired in API CRUD)
- [x] 2h. API CRUD + `/probe-now` + `/events` (SSE deferred)
- [x] 2i. UI `multi-wan/gateways/page.tsx` with live polling + manual probe injection
- [ ] 2j. Metrics emission (deferred to phase 10 hardening)
- [x] 2k. `GatewayEngine::inject_sample` test helper
- [x] 2l. Tests: transitions emit events, CRUD, probe outcomes, evaluate_transition

Tables:
```sql
multiwan_gateways (id, name UNIQUE, instance_id FK, interface, next_hop, ip_version,
                   monitor_kind, monitor_target, monitor_port, monitor_expect,
                   interval_ms=500, timeout_ms=1000,
                   loss_pct_down=20.0, loss_pct_up=5.0, latency_ms_down, latency_ms_up,
                   consec_fail_down=3, consec_ok_up=5,
                   weight=1, dampening_secs=10, dscp_tag, enabled=1,
                   state='unknown', last_rtt_ms, last_jitter_ms, last_loss_pct, last_mos,
                   last_probe_ts, created_at, updated_at)
multiwan_gateway_events (id AUTO, gateway_id FK, ts, from_state, to_state, reason,
                         probe_snapshot_json)
```

---

## Phase 3 — Gateway groups

User value: compose gateways into ordered groups with policy.

- [x] 3a. `aifw-core/src/multiwan/group.rs` — pure selection logic for failover/weighted/adaptive/LB
- [x] 3b. API CRUD + member mgmt + `/active` endpoint
- [ ] 3c. UI `multi-wan/groups/page.tsx` (deferred — API-accessible for now)
- [ ] 3d. `proptest` dev-dep (deferred)
- [x] 3e. Scenario tests: failover lowest-tier, fallback on down, adaptive MOS scaling

Tables:
```sql
multiwan_groups (id, name UNIQUE, policy (failover|weighted_lb|adaptive|load_balance),
                 preempt=1, sticky (none|src|five_tuple), hysteresis_ms=2000,
                 kill_states_on_failover=1, created_at, updated_at)
multiwan_group_members (group_id FK, gateway_id FK, tier=1, weight=1,
                        PRIMARY KEY (group_id, gateway_id))
```

---

## Phase 4 — Policy routing rules + pf emission

User value: first dataplane phase. Rules like "LAN→Netflix via WAN2" work end-to-end.

- [x] 4a. `PfBackend` additions: `kill_states_on_iface`, `kill_states_for_label` (used `load_rules` for PBR since existing trait method fits)
- [x] 4b. `PolicyEngine` with CRUD + `apply()` that composes instance/gateway/group state into pf strings
- [x] 4c. Emitters: `route-to`+`reply-to` for SetGateway; `rtable N` for SetInstance; weighted route-to with sticky-address for SetGroup
- [ ] 4d. Anchor wiring into root ruleset (deferred to phase 10 — anchors exist but need pf.conf wiring)
- [x] 4e. API CRUD + `/apply` under `/api/v1/multiwan/policies`
- [ ] 4f. UI policies page (deferred — API-accessible for now)
- [x] 4g. Golden tests: set_instance emits rtable, set_gateway emits paired route-to/reply-to with if-bound, disabled skipped

Tables:
```sql
multiwan_policies (id, priority, name, status, ip_version, iface_in,
                   src_addr='any', dst_addr='any', src_port, dst_port, protocol='any',
                   dscp_in, geoip_country, schedule_id,
                   action_kind, target_id, sticky='none', fallback_target_id,
                   description, created_at, updated_at)
```

Emission examples:
```
pass out quick on em1 inet proto udp from 10.0.0.0/24 to any port 443 \
  route-to (em1 203.0.113.1) keep state (if-bound) label "pbr:<id>"
pass in quick on em0 inet proto udp from 10.0.0.0/24 to any port 443 \
  reply-to (em1 203.0.113.1) keep state (if-bound) label "pbr:<id>:rep"

pass in quick on em_lan from 10.0.0.0/24 to any \
  rtable 1 keep state (if-bound) label "pbr:inst:<id>"

pass out quick on em1 inet proto tcp from 10.0.0.0/24 to any \
  route-to { (em1 203.0.113.1) weight 2, (em2 198.51.100.1) weight 1 } \
  round-robin sticky-address keep state (if-bound) label "pbr:grp:<id>"
```

Risks: rule explosion → consolidate via pf tables (`<pbr_src_10_0_0_0_24>`), defer if small.

---

## Phase 5 — Route leaking + mgmt escape hatches

User value: cross-FIB traffic for DNS/NTP/API (Juniper rib-groups, declarative).

- [ ] 5a. `aifw-core/src/multiwan/leak.rs::LeakEngine` + anchor `aifw-mwan-leak`
- [ ] 5b. Auto-seed defaults: API subnet → FIB 0, rDNS, rTIME (idempotent)
- [ ] 5c. API CRUD
- [ ] 5d. UI `multi-wan/leaks/page.tsx`
- [ ] 5e. Tests: 409 on deleting mgmt leak, 409 on self-stranding policy

Tables:
```sql
multiwan_leaks (id, name, src_instance_id FK, dst_instance_id FK, prefix,
                protocol='any', ports, direction (bidirectional|one_way), enabled=1,
                created_at, updated_at)
```

---

## Phase 6 — Pre-flight / blast-radius / force-migrate

User value: nobody in enterprise gear does this well. Dry-run config changes.

- [ ] 6a. `aifw-core/src/multiwan/preflight.rs` — consumes proposed policy set + `PfBackend::get_states`
- [ ] 6b. `BlastRadiusReport` serializer (affected flows, mgmt impact, rule diff, findings)
- [ ] 6c. `POST /api/v1/multiwan/preview` (non-mutating)
- [ ] 6d. `POST /api/v1/multiwan/apply` (idempotency-key)
- [ ] 6e. `POST /api/v1/multiwan/flows/{state_id}/migrate` — kill state to re-steer
- [ ] 6f. UI `multi-wan/preview/page.tsx` modal invoked from mutating forms
- [ ] 6g. Tests: inject states, assert diff accuracy, mgmt-strand detection

---

## Phase 7 — SLA reporting + AI anomaly detection

User value: long-term observability exceeding Cisco IP SLA.

- [ ] 7a. Table `multiwan_sla_samples` (1-min buckets, 30-day retention)
- [ ] 7b. Daemon housekeeper: aggregate live → samples, prune >30d
- [ ] 7c. `aifw-ai` hook: 7-day EWMA + std baseline; 3σ deviation > 30s → `GatewayAnomaly`
- [ ] 7d. API `/gateways/{id}/sla?window=24h|7d|30d`, `/anomalies`
- [ ] 7e. UI `multi-wan/sla/page.tsx` (reuse traffic/ chart lib)

---

## Phase 8 — Per-flow visibility + force-migrate UX

User value: live per-flow WAN table with 1-click re-steer.

- [ ] 8a. Extend `PfState` type with `iface_out`, `rtable` (populated from `pfctl -ss -v`)
- [ ] 8b. API `GET /multiwan/flows` joins states + labels to policy/gateway/group
- [ ] 8c. `POST /multiwan/flows/{id}/migrate` (already added in 6e, reuse)
- [ ] 8d. UI `multi-wan/flows/page.tsx` (WS streaming)

---

## Phase 9 — GitOps / BGP / discovery

User value: the stuff Cisco/Juniper still make hard.

- [ ] 9a. `GET /multiwan/config.yaml` — full multi-WAN as YAML
- [ ] 9b. `POST /multiwan/apply-yaml` — atomic via preview engine
- [ ] 9c. New crate `aifw-bgp` (optional) — FRR spawn + config, announce gated on probe health
- [ ] 9d. Auto-discovery: traceroute → peer ASN → popular AS destinations as extra probe targets
- [ ] 9e. IPv6 parity audit across all prior phases (probes, route-to6, reply-to6)
- [ ] 9f. `aifw-plugins` hook: `ProbeKind::Plugin(name)`

---

## Phase 10 — Hardening + chaos + docs

- [ ] 10a. `aifw-chaos` dev bin — random probe toggling for hours; invariant checks (no strand, no flap > hysteresis, state-kill budget)
- [ ] 10b. FreeBSD dual-WAN VM end-to-end test — assert ≤3s convergence
- [ ] 10c. Full `docs/multi-wan.md` — architecture, runbook, troubleshooting, migration, Cisco/Juniper comparison matrix; update `docs/compare.md`

---

## Observability Contract (cross-phase)

Metrics (`aifw-metrics`):
- `aifw_gateway_{rtt_ms,jitter_ms,loss_ratio,mos,state}{name,instance}` gauges
- `aifw_gateway_transitions_total{name,from,to}` counter
- `aifw_policy_flows_current{policy,gw}` gauge
- `aifw_multiwan_pf_reloads_total{anchor}` counter
- `aifw_multiwan_convergence_ms` histogram {gw}

Log lines (structured `tracing`):
- `target=multiwan.gateway event=transition gw=wan1 from=up to=down reason="loss=100%" consec_fail=3`
- `target=multiwan.policy event=reload anchor=aifw-pbr rules=42 took_ms=87`
- `target=multiwan.preflight event=block reason=would_strand_mgmt`

Webhooks (`/api/v1/multiwan/webhooks`): `gateway.transition`, `anomaly.detected`, `group.active_changed`.

---

## Migration Path

On first run with Phase 1:
1. Idempotent seed: `default` instance on FIB 0, `mgmt_reachable=1`
2. All existing interfaces stay on FIB 0 (no `ifconfig fib` calls)
3. UI shows Multi-WAN nav under "Advanced"
4. pf anchors `aifw-pbr`/`aifw-mwan-leak`/`aifw-mwan-reply` not emitted when empty → pf output byte-identical to pre-upgrade
5. Release notes link to `docs/multi-wan.md`

---

## Critical File Touchpoints

- `/home/mack/dev/AiFw/aifw-pf/src/backend.rs` — trait additions
- `/home/mack/dev/AiFw/aifw-pf/src/{mock,ioctl}.rs` — impls
- `/home/mack/dev/AiFw/aifw-core/src/lib.rs` — re-exports
- `/home/mack/dev/AiFw/aifw-core/src/multiwan/*.rs` — new engines
- `/home/mack/dev/AiFw/aifw-api/src/main.rs` — AppState + router
- `/home/mack/dev/AiFw/aifw-api/src/multiwan.rs` — handlers
- `/home/mack/dev/AiFw/aifw-common/src/{multiwan,permission}.rs` — types + perms
- `/home/mack/dev/AiFw/aifw-common/src/rule.rs` — `to_pf_rule` (extend to emit route-to/rtable)
- `/home/mack/dev/AiFw/aifw-setup/src/{tuning,apply,wizard}.rs` — kernel tuning + anchor wiring + wizard
- `/home/mack/dev/AiFw/aifw-daemon/` — probe supervisor
- `/home/mack/dev/AiFw/aifw-ui/src/app/multi-wan/` — new UI
- `/home/mack/dev/AiFw/freebsd/overlay/usr/local/etc/rc.d/aifw_fibs` — boot pin
- `/home/mack/dev/AiFw/freebsd/manifest.json` — rc_scripts entry

---

## Risk Summary

| Risk | Mitigation |
|---|---|
| pf state global → FIB leakage | `(if-bound)` on every PBR rule; `kill_states_on_iface` on failover |
| Asymmetric return traffic | `reply-to` auto-paired with every `route-to` |
| Admin lock-out from PBR | Pre-flight validation; default mgmt escape leak seeded |
| `ROUTETABLES` compile-time cap | `net.fibs` loader tunable; runtime check in `list_fibs` |
| Daemon lacks raw socket | TCP probe default; sudo ICMP fallback |
| Rule explosion | pf tables for src/dst sets; debounced reloads; anchor-scoped flushes |
| Mock/ioctl divergence | Golden pf-output tests run identically against both backends |
| Probe flapping | Hysteresis (consec_fail/ok), dampening_secs, group hysteresis_ms |
