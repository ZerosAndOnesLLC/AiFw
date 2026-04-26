# Process Hardening and IDS Extraction

**Status:** Draft
**Date:** 2026-04-26
**Author:** mack42

## Problem

A live AiFw appliance (172.29.69.1, uptime 1d 21h, version 5.72.3) shows two
classes of bug.

**Bug class 1 — duplicate processes accumulate.** `service trafficcop status`
reports one PID, but six trafficcop processes are running, started at five
distinct times over a 22-hour window. Five of them have no listening socket
and are dead-but-still-resident. The same daemon-pair tracking pattern is
buggy in `rdhcpd`, `rtime`, and the `aifw_daemon`/`aifw_api` rc.d scripts
written by `aifw-setup`. Only `rdns` has the correct pattern. Compounding the
risk, none of the binaries enforce a singleton at the process level, so
manually invoking the binary outside `service` will silently start a second
copy.

**Bug class 2 — aifw-api long-tail memory growth.** RSS grew from 585 MB at
boot to 2,297 MB over 13 days. The existing memstats heartbeat accounts for
~400 MB (alert buffer 64 MB capped + metrics history 337 MB capped). The
remaining ~1.3 GB is invisible to memstats. Source-level audit identified the
leak vector:

- `aifw-api/src/main.rs:1532` instantiates an `IdsEngine`, calls
  `engine.start()`, and runs BPF capture **inside the API process** — in
  parallel with `aifw-daemon/src/main.rs:196`, which does the exact same
  thing. The 47k-rule database (~1.9 GB) is loaded into both processes.
  Both maintain independent FlowTables.
- `aifw-ids/src/flow/mod.rs` allows up to 1 MB of stream-reassembly buffer
  per direction per flow (2 MB per flow). The DashMap has no hard count cap.
  `expire()` only fires every 10,000 packets, *and only when packets arrive* —
  if traffic pauses the table never shrinks. Neither flow count nor
  reassembly bytes are surfaced in memstats.
- `aifw-api/src/main.rs:64` (`LoginRateLimiter`) keeps per-IP and
  per-username `HashMap<String, (u32, DateTime<Utc>)>` entries with no
  time-based pruning. Entries are removed only on `clear()` after a
  successful login.

The user has explicitly ruled out band-aid fixes (periodic restart, RSS-cap
self-restart). All fixes here address root causes.

## Goals

1. No service can ever run as duplicate processes — at the rc.d layer **and**
   at the binary layer (defense in depth).
2. IDS / IPS state lives in exactly one process. The 47k-rule database
   exists in RAM exactly once. BPF capture runs exactly once.
3. The aifw-api process bounds its memory growth without help from cron,
   self-restart watchdogs, or process killers. RSS plateaus naturally.
4. Operators can see flow-table size and reassembly bytes via the existing
   memstats heartbeat — the leak vectors that bit us must be visible going
   forward.
5. All fixes ship via the normal update tarball / ISO / IMG. Existing
   appliances pick them up on update; fresh installs get them from
   `aifw-setup`.

## Non-Goals

- Rewriting BPF capture, packet decoding, or the IDS rule engine itself.
- Changing the on-disk schema for IDS rules or alerts.
- Replacing SQLite or migrating to a different storage layer.
- Periodic-restart / RSS-watchdog band-aids (explicitly out of scope per
  user direction).

## Architecture

### New process: `aifw-ids`

A new long-running binary that owns the entire IDS subsystem.

```
                  ┌────────────────┐
                  │   aifw-ids     │  (new — owns BPF capture, rule DB,
                  │   PID/lock      │   FlowTable, alert pipeline)
                  └──────┬─────────┘
                         │ Unix socket
                         │ /var/run/aifw/ids.sock
                         │ (root:aifw 0660)
        ┌────────────────┴────────────────┐
        │                                  │
┌───────▼────────┐                ┌───────▼────────┐
│  aifw-daemon   │                │   aifw-api     │
│  (no IDS)      │                │ (IPC client +  │
│                │                │  TTL cache)    │
└────────────────┘                └────────────────┘
```

Responsibilities:

- `aifw-ids` — BPF capture, rule loading and compilation, packet decode,
  detection, FlowTable, alert buffer, IDS config persistence. Writes alerts
  to `ids_alerts` in `/var/db/aifw/aifw.db` (unchanged). Exposes a Unix
  socket for queries and mutations.
- `aifw-daemon` — pf rule application, NAT, VPN, multiwan, conntrack,
  shaping, audit, AI analysis, plugin manager, SLA aggregation. **No IDS.**
- `aifw-api` — HTTP REST + WebSocket server, UI static hosting, auth, and
  IPC client to `aifw-ids` for everything in `/api/v1/ids/*`.

The IDS database tables (`ids_alerts`, `ids_config`, `ids_rules`,
`ids_rulesets`, `ids_suppressions`) remain in the shared SQLite DB and are
read by both `aifw-ids` (writer) and `aifw-api` (read-only — for endpoints
that just paginate alerts, where DB query is fine and IPC would be
gratuitous).

### IPC protocol

JSON request/response, length-prefixed (4-byte big-endian `u32` length).
Connection-per-call (no persistent state, no streaming yet — keeps the
server simple). The aifw-api side caches read results with a short TTL.

Methods (mirror the current `/api/v1/ids/*` surface):

| Method | Purpose | Cache TTL in api |
|--|--|--|
| `get_config` | current `IdsConfig` | 5s |
| `set_config` | update `IdsConfig`, triggers reload | (write — invalidates) |
| `reload` | recompile rules | (write) |
| `get_stats` | live counters: rules_loaded, flow_count, flow_bytes, packets_inspected, alerts_total | 2s |
| `list_rulesets` | name + enabled list | 30s |
| `get_rule(id)` | single rule detail | 60s |
| `set_rule(id, ...)` | enable/disable single rule | (write) |
| `tail_alerts(n)` | last N alerts from in-memory buffer | 1s |

Endpoints that paginate the alerts table (`GET /api/v1/ids/alerts`,
acknowledge, suppression list/create/delete) read/write the DB directly
from `aifw-api` — these are SQL queries, not state queries, and an IPC
hop adds nothing.

The wire types live in a new crate `aifw-ids-ipc` shared by client and
server, so both sides depend on the same `serde` shapes.

### aifw-ids binary layout

```
aifw-ids/
├── src/                     (existing — library code stays a library)
└── [unchanged]

aifw-ids-bin/                (new crate — the binary)
├── Cargo.toml
└── src/main.rs              (init, capture, IPC server, lockfile)

aifw-ids-ipc/                (new crate — shared types + client)
├── Cargo.toml
└── src/
    ├── lib.rs
    ├── proto.rs             (request/response enums, framing)
    ├── client.rs            (used by aifw-api)
    └── server.rs            (used by aifw-ids-bin)
```

The existing `aifw-ids` library crate keeps its current API. The new
`aifw-ids-bin` crate just wires `IdsEngine` + `aifw-ids-ipc` server +
lockfile + signal handling. The library can still be used in tests without
the IPC layer.

### FlowTable bounding (in `aifw-ids` library)

Three changes inside `aifw-ids/src/flow/mod.rs` and the capture loop in
`aifw-ids/src/lib.rs`:

1. **Smaller default stream depth.** `max_stream_depth` default drops from
   `1024 * 1024` (1 MB) to `65536` (64 KB) per direction. Plenty for HTTP
   header / TLS handshake / DNS / SMTP banner inspection — the workloads
   AiFw's signature set actually targets. Suricata's default
   `request-body-limit` is 100 KB; we land near that.
   New config key `flow_stream_depth_kb` exposes this for tuning, and
   `set_config` applies it on the next packet (existing flows keep their
   already-allocated depth — buffers don't grow past it anyway).
2. **Hard count cap.** `flow_table_size` becomes a real ceiling. The
   `track_packet` path checks `table.len() >= cap` before insert; if so,
   it evicts the entry with the smallest `last_ts` (LRU-by-recency).
   `flow_table_size` default stays at 65536. At 64 KB × 2 × 65,536 =
   8 GB worst case, which is still too high — we'll add a separate
   `flow_reassembly_budget_mb` (default 256) that tracks total reassembly
   bytes and evicts oldest flows when the budget is exceeded. This is
   the real cap.
3. **Time-based expiry.** A separate tokio task runs `flow_table.expire`
   every 30 s in `aifw-ids-bin` regardless of packet rate. The existing
   "expire every 10,000 packets" path stays as belt-and-suspenders.

memstats heartbeat in `aifw-api/src/main.rs:2128` adds `flow_count` and
`flow_reassembly_kb` (queried via the IPC `get_stats` call — no DB hit).

### LoginRateLimiter pruning

`aifw-api/src/main.rs:112` (`bump`) and `:129` (`over_cap`): each call
opportunistically removes entries where `(now - entry.1).num_seconds() >
window_secs`. The pattern matches `WsTicketStore::issue` —
`map.retain(|_, (_, ts)| (now - *ts).num_seconds() <= window_secs)` before
the read or insert. O(N) per call, but N is bounded by the number of
unique attackers seen in the last `window_secs` seconds (default 300 s),
so it stays small.

### rc.d daemon-pair fix

The buggy pattern across `trafficcop`, `rdhcpd`, `rtime`, the
`aifw-setup`-written `aifw_daemon` and `aifw_api`, and the new `aifw_ids`:
they pass only `-p <child>.pid` to `daemon(8)`. The `daemon(8)` supervisor
itself runs unsupervised; on `service stop` only the child is killed; on
the next `service start` the supervisor's `-R 5` may have already
respawned a fresh child, leaving an orphan pair. Multiple restarts
accumulate orphan pairs.

The correct pattern, already in `freebsd/overlay/usr/local/etc/rc.d/rdns`:

- `pidfile=` set to the **supervisor** pidfile (so `service stop` kills the
  supervisor, which signals the child).
- `procname=/usr/sbin/daemon` (rc.subr's pidfile-validity check matches the
  process whose PID is in `pidfile`, which is `daemon(8)`, not the
  application).
- `daemon -P <supervisor>.pid -p <child>.pid -R 5 -S -T <name> ...` — `-P`
  tracks the supervisor, `-p` tracks the child.
- A `start_precmd` (or inline at the top of `start_cmd`) reaps stragglers
  from prior buggy installs:
  ```sh
  /usr/bin/pkill -f "daemon:.*${procname_sentinel}" 2>/dev/null
  /usr/bin/pkill -x "${binary_basename}" 2>/dev/null
  /bin/rm -f ${supervisor_pidfile} ${child_pidfile}
  ```
- `stop_postcmd` removes both pidfiles.

This pattern is applied to:
- `freebsd/overlay/usr/local/etc/rc.d/trafficcop`
- `freebsd/overlay/usr/local/etc/rc.d/rdhcpd` (also overwritten by setup)
- `freebsd/overlay/usr/local/etc/rc.d/rtime`
- new `freebsd/overlay/usr/local/etc/rc.d/aifw_ids`
- `aifw-setup/src/apply.rs` writes new versions of `aifw_daemon`,
  `aifw_api`, `rdhcpd`, `aifw_ids`.

### Binary-level singleton (defense in depth)

A new helper in `aifw-common` (`aifw_common::single_instance`):

```rust
/// Acquire an exclusive lock on /var/run/<name>.lock. On success returns a
/// guard that releases the lock when dropped (or when the process dies —
/// the kernel handles that). On failure returns Err with a clear message
/// naming the holder PID.
pub fn acquire(name: &str) -> Result<InstanceLock, InstanceLockError>;
```

Implementation: `open(O_CREAT|O_RDWR, 0644)` the lockfile, `fcntl(F_SETLK,
F_WRLCK)` it (advisory lock — survives ungraceful crashes because the
kernel releases on close), write own PID into it for diagnostics. On
`EAGAIN`/`EACCES`, read the existing PID and return an error mentioning
it.

Each long-running binary calls `acquire(<name>)` immediately after
argument parsing, before initialisation. On error, log and exit non-zero.

Applied to (this repo):
- `aifw-daemon/src/main.rs`
- `aifw-api/src/main.rs`
- `aifw-ids-bin/src/main.rs`

Applied to (sibling repos under `~/dev`):
- `~/dev/trafficcop` — same `single_instance` pattern, local copy.
- `~/dev/rDNS` — already has correct rc.d but no binary lock; add it.
- `~/dev/rDHCP` — add it.
- `~/dev/rTime` — add it.

The sibling repos can each carry their own copy of the helper (it's ~30
lines) — no need to publish a shared crate. They already vendor/copy
similar utilities.

### `aifw-setup` updates

`aifw-setup/src/apply.rs:1576-1745` (`write_rcd_scripts`):

- Update the `aifw_daemon`, `aifw_api`, `rdhcpd` script bodies to the
  fixed pattern (supervisor + child pidfile, procname, reap on start).
- Add a 4th script: `aifw_ids` (same pattern).
- Enable `aifw_ids_enable="YES"` in `/etc/rc.conf` next to
  `aifw_daemon_enable` and `aifw_api_enable`.

### Updater behaviour

The update tarball already replaces files under `/usr/local/sbin/` and
`/usr/local/etc/rc.d/`. Three additions:

1. The tarball gains the `aifw-ids` binary in `/usr/local/sbin/`.
2. The tarball gains the new `aifw_ids` rc.d script. Updater enables it
   in `/etc/rc.conf` if not already present.
3. On first start of the updated services, any stale orphan pairs from
   pre-fix daemon(8) supervisors are killed by the new `start_precmd`'s
   `pkill -f "daemon:.*<binary>"` — so existing appliances are cleaned up
   automatically the first time `service <name> start` runs after update.

Migration: after the update lands, `service aifw_daemon restart && service
aifw_api restart && service aifw_ids start` (in that order; the updater
script handles this) — RSS in aifw-api drops by ~1.9 GB immediately,
because the duplicate IDS state is gone.

### `freebsd/manifest.json`

Add `aifw-ids` to the binary list under the existing AiFw entries.

## Components and Boundaries

| Unit | Owns | Depends on | Tests |
|--|--|--|--|
| `aifw-ids` (lib, existing) | rule DB, FlowTable, capture, detection | `aifw-pf`, `aifw-common` | unit tests for flow bounding (count cap, byte budget, time-expire) |
| `aifw-ids-ipc` (new) | wire types, client, server | `serde`, `tokio` | round-trip serde tests, framing tests, error-path tests |
| `aifw-ids-bin` (new) | binary lifecycle, signal handling, IPC server wiring | `aifw-ids`, `aifw-ids-ipc`, `aifw-common::single_instance` | smoke test: spawn, connect, send `get_stats`, verify response, send SIGTERM, verify clean shutdown |
| `aifw-common::single_instance` (new) | lockfile acquisition | `nix` (already a dep) | unit test: two concurrent acquires → second fails with PID of first |
| `aifw-api` (modified) | HTTP, IPC client, TTL cache | `aifw-ids-ipc::client` | existing tests stay green; new test: stub IPC server, verify api caches and invalidates correctly |
| `aifw-daemon` (modified) | everything except IDS | (IDS removed) | existing tests stay green |
| rc.d scripts | service lifecycle | `daemon(8)`, rc.subr | manual: `service start/stop/restart` 5x, verify exactly one supervisor + one child each time |

## Error handling

- **`aifw-ids` is down when aifw-api needs it.** IPC client returns
  `IdsClientError::Unavailable`. aifw-api's `/api/v1/ids/*` handlers
  return `503 Service Unavailable` with a clear body
  (`{"error":"ids service unavailable"}`). UI surfaces "IDS service
  offline." DB-backed endpoints (`GET /api/v1/ids/alerts`) keep working.
- **IPC timeout.** 2-second deadline per call. On timeout: same as
  unavailable.
- **Lockfile already held.** Binary logs `instance already running (pid
  X)`, exits 1. rc.d's `start_precmd` reaps stragglers, so this only
  trips when the operator manually launches the binary while the service
  is up.
- **Flow table over budget.** Eviction is silent under normal operation.
  When eviction rate is high (> 100/s for > 10s), aifw-ids logs a
  warning so operators know they need to bump the budget.
- **rc.d `start_precmd` `pkill` matches nothing.** Expected on a clean
  install. `pkill` returns 1; we ignore that.

## Testing

Beyond the per-unit tests above, two integration scenarios:

1. **Memory bound test.** A test in `aifw-ids` that synthesises 100k
   distinct flows with 256 KB payloads each. Asserts that
   `flow_table.len()` and `flow_table.reassembly_bytes()` both stay
   under their configured caps. Asserts that older flows are evicted
   in `last_ts` order.
2. **End-to-end IDS-via-IPC test.** Spawns `aifw-ids-bin` against a mock
   pf backend and an in-memory SQLite, spawns `aifw-api` pointed at the
   socket, exercises every `/api/v1/ids/*` endpoint, asserts behaviour
   matches the previous in-process implementation.

Manual on-appliance verification after deploy:

```sh
# 1. Singleton check
service aifw_api stop
/usr/local/sbin/aifw-api ... &     # should start
/usr/local/sbin/aifw-api ... &     # should refuse — exit 1, log "already running (pid X)"

# 2. rc.d restart hygiene — repeat 5x
for i in 1 2 3 4 5; do
  service trafficcop restart
done
pgrep -af trafficcop | wc -l    # must equal 2 (supervisor + child)

# 3. IDS memory bound
ps -o rss= -p $(pgrep -x aifw-api)        # baseline
# wait 24 h
ps -o rss= -p $(pgrep -x aifw-api)        # within 50 MB of baseline
ps -o rss= -p $(pgrep -x aifw-ids)        # well under 2 GB
```

## Rollout

The change is large enough that the work splits across multiple PRs,
shipped in one or more update tarballs:

1. PR 1: `aifw-common::single_instance` helper + apply to
   aifw-daemon and aifw-api. Tests. (Self-contained, low risk.)
2. PR 2: rc.d daemon-pair fix in overlay scripts and
   `aifw-setup/src/apply.rs`. (Self-contained, low risk.)
3. PR 3: `aifw-ids-ipc` crate (types only, no consumers yet). Tests.
4. PR 4: New `aifw-ids-bin` crate, IPC server, lockfile, rc.d. Tests.
5. PR 5: aifw-daemon — remove in-process IDS. aifw-api — switch to IPC
   client + TTL cache. Manifest update. Tests. **This is the cutover PR**
   and must merge after PRs 3 and 4 are deployed.
6. PR 6: FlowTable bounding (count cap, byte budget, time-based expiry).
   Tests. (Lands inside `aifw-ids` library — picked up by `aifw-ids-bin`
   automatically.)
7. PR 7: LoginRateLimiter pruning. (Trivial.)
8. PR 8 (separate repos): singleton lock + rc.d fix in trafficcop, rDNS,
   rDHCP, rTime.

Each PR is self-contained and reversible. PR 5 is the only one that
changes runtime behaviour observable to operators (RSS drops). All others
are invisible-when-working.

## Open Questions

None remaining — user has answered:
- Q1: Root cause, not band-aid. ✓
- Q2: In-memory IDS state is fine, just handled correctly (single owner). ✓
- Q3: Lock down sibling repos too. ✓
- Q4: Separate `aifw-ids` binary. ✓
