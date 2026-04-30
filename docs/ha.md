---
layout: default
title: High Availability — AiFw Active-Passive Pair
description: Setup, architecture, latency profiles, failure modes, split-brain handling, and ops runbooks for AiFw HA pairs using CARP and pfsync on FreeBSD.
permalink: /ha/
---

# High Availability — Active-Passive Pair

AiFw supports a two-node active-passive cluster: one master forwarding production
traffic, one backup with replicated pf state, ready to take over within seconds
of any failure on the master.

## What survives a master reboot

| Component | Survives | Notes |
|---|---|---|
| TCP sessions through the firewall | yes | pfsync replicates state to the backup; `state-policy floating` lets replicated states match traffic on the new master's interface |
| WireGuard tunnels | yes | wireguard-go binds wildcard; CARP VIPs on the WAN are accepted automatically. Existing peers reconnect within ~5 s |
| DHCP leases (rDHCP) | yes | rDHCP HA handles its own state replication; AiFw's `dhcp_link` flag keeps the peer list in sync |
| ACME certificates | yes | renewal happens master-only; on success the cert+key are pushed to peers via `POST /api/v1/cluster/cert-push` |
| In-flight DNS lookups | no | small visible glitch during the failover window — most resolvers retry transparently |
| IDS in-memory ring buffer | no | rule overrides and suppressions are replicated; runtime alert ring buffer is not |

## Prerequisites

- **Two AiFw nodes on the same broadcast domain.** CARP advertisements use multicast (224.0.0.18); the nodes must see each other's L2 traffic.
- **Dedicated NIC for pfsync.** Not strictly required, but state-sync traffic on a shared LAN link will degrade under load. A point-to-point cable between two NICs is ideal.
- **Synchronized time.** Both nodes should run NTP / `rtime` (the AiFw companion service). CARP advertisement timing is sensitive to clock drift.
- **Same software version.** Always upgrade the standby first; the cluster dashboard surfaces version drift between nodes.

## Setup

1. Install AiFw on both nodes via the ISO build.
2. On node A, in the first-boot wizard:
   - Answer **Yes** to "Configure HA pair?"
   - Choose **Primary**.
   - Select the pfsync interface, peer IP, password, and per-LAN/WAN VIPs.
3. On node B: run the same wizard, choose **Secondary**, enter the same VHIDs and password.
4. After both nodes are up: visit `https://<node-A-mgmt-ip>/cluster` and confirm both nodes appear in the table with a green health status.
5. Verify with `aifw cluster verify` on each node, then run `scripts/ha-verify.sh node-a node-b` over SSH for a pair-wide check.

## Latency profiles

The `pfsync.latency_profile` setting controls CARP advertisement timing and therefore the detection window for unplanned failures.

| Profile | advbase | secondary advskew | Detection time | Use when |
|---|---|---|---|---|
| Conservative *(default)* | 1 | 100 | ~3 s | Default. Tolerates flaky networks. |
| Tight | 1 | 20 | ~1.5 s | Reliable network with dedicated pfsync link. |
| Aggressive | 1 | 10 | ~1 s | **Requires future heartbeat daemon** — schema-only this release. |

The primary node always uses advskew=0 regardless of profile. Set the profile via the CLI:

```sh
aifw cluster pfsync set --latency-profile tight
```

Or via the API (`PUT /api/v1/cluster/pfsync`).

## Minimizing the unplanned-failure gap

For planned reboots and service restarts, AiFw demotes CARP via
`sysctl net.inet.carp.demotion=240` *before* tearing down the local data plane
(the `aifw_demote_on_shutdown` rc.d script + per-service stop preludes). The peer
takes over within ~1 s, so a reboot of the master typically misses zero to two
packets.

For unplanned failures (power loss, kernel panic, NIC death), the gap depends on
CARP timer detection:

- **UPS on each node** is the single biggest reliability win. It converts power
  loss into a graceful shutdown with a full CARP demote (near-zero-packet failover)
  instead of a 1–3 s detection gap.
- **Dedicated pfsync NIC** keeps replication off the data plane.
- **Tight latency profile** when the network is reliable.

Without a UPS, a hard power loss results in:

- TCP sessions: still survive (pfsync replicated state in real time).
- UDP packets in flight: lost (no retransmission semantics).
- Total user-visible outage: 1.5–3 s depending on latency profile.

## Split-brain handling

If the pfsync link fails but both nodes stay up, both may temporarily think they
are MASTER. When the link reconnects:

- Whichever node has the **higher node-id** (UUID lexicographic comparison)
  concedes — its `ClusterReplicator` detects the conflict on the next snapshot
  push (`409 Conflict` from the peer) and records an entry in
  `cluster_failover_events` with cause `split_brain_detected`.
- The conceding node's local config edits made during the partition are
  **discarded** when it accepts the master's snapshot. They appear in the audit
  log for forensics.
- The master continues forwarding without interruption.

If both nodes' kernels resolve the CARP election (CARP `preempt=1` with the
master's lower advskew), the demoted node rejoins as BACKUP automatically.

## Operations

### Planned maintenance / rolling upgrade

Always upgrade the standby first, then the master:

```sh
# On the standby node first
aifw update install --restart

# Then on the master node
aifw update install --restart
```

`aifw update install --restart` triggers `aifw cluster demote` before bouncing
services, so traffic flips to the peer before the local data plane stops.

### Manual promote / demote

```sh
aifw cluster demote   # this node becomes BACKUP  (sysctl carp.demotion=240)
aifw cluster promote  # this node becomes MASTER  (sysctl carp.demotion=0)
```

Demote the current master before promoting the standby to avoid a brief
split-brain window.

### Decommission a node

```sh
aifw cluster nodes remove <node-id>
```

The remaining node continues as a standalone (Standalone role). Obtain the
`<node-id>` from `aifw cluster nodes list`.

### Force a config sync

```sh
aifw cluster sync
```

Triggers an immediate snapshot push from master to standby. The dashboard's
**Force sync from peer** button does the same thing.

### Show cluster status

```sh
aifw cluster status
aifw cluster status --json
```

## Verifying

```sh
# On either node — exits 0 healthy, exits 1 with reason on failure
aifw cluster verify

# Machine-readable output (used by the harness)
aifw cluster verify --json | jq .
```

The `verify` command checks:

1. `pf state-policy floating` is set.
2. `pfsync0` interface is UP.
3. At least one CARP VIP is configured (`carp:` line in `ifconfig`).
4. `/api/v1/cluster/status` reports `peer_reachable: true`.
5. A config snapshot hash is present (replication is not stalled).

### Pair-wide check via SSH

```sh
sh scripts/ha-verify.sh node-a.example.com node-b.example.com
```

The harness asserts:

- Both nodes report `aifw cluster verify --json` with `ok: true`.
- Exactly one node reports MASTER role in the status block.

Exit codes:

| Code | Meaning |
|------|---------|
| 0 | Pair healthy |
| 1 | A node was unreachable or `aifw cluster verify` returned a non-zero exit |
| 2 | At least one node failed its local checks (ok=false) |
| 3 | Expected exactly 1 MASTER, got a different count (0 or 2) |

## Out of scope (this release)

- **Active-active stateful pf** — different architecture entirely; not planned.
- **N > 2 node clusters** — two-node pairs only.
- **WAN-side / multi-site / geographic HA** — not supported.
- **Out-of-band heartbeat daemon** — the `latency_profile` schema fields exist on
  `pfsync_config` and the `Aggressive` profile is documented, but no daemon
  process consumes the heartbeat yet. Aggressive is reserved for a future release.
- **NUT (Network UPS Tools) integration** — strongly recommended in this doc, but
  not built into AiFw. Configure NUT separately and point its shutdown hook at
  `aifw cluster demote && shutdown -p now`.
