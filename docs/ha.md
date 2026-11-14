---
layout: default
title: High Availability — AiFw Active-Passive Pair
description: Setup, architecture, latency profiles, failure modes, split-brain handling, and ops runbooks for AiFw HA pairs using CARP and pfsync on FreeBSD.
permalink: /ha/
date: 2026-05-09
breadcrumb:
  - { title: "Docs", url: "/docs/" }
  - { title: "HA cluster", url: "/ha/" }
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "High Availability on AiFw — CARP and pfsync",
  "description": "Setup, latency profiles, failure modes, and ops runbooks for AiFw HA pairs using CARP and pfsync on FreeBSD.",
  "author": { "@type": "Organization", "name": "ZerosAndOnesLLC" },
  "datePublished": "2026-05-09",
  "dateModified": "2026-11-07"
}
</script>

# High Availability — Active-Passive Pair

AiFw supports a two-node active-passive cluster: one master forwarding production
traffic, one backup with replicated pf state, ready to take over within seconds
of any failure on the master.

> **Validation status:** the failover behaviors and timing numbers on this page are design targets. The runtime fixes in [#712](https://github.com/ZerosAndOnesLLC/AiFw/issues/712) (demotion, preemption, boot ordering, replication) are covered by unit and API tests; the automated two-node failover suite is tracked in [#534](https://github.com/ZerosAndOnesLLC/AiFw/issues/534). Validate failover in your own environment before relying on it.

## What survives a master reboot

| Component | Survives | Notes |
|---|---|---|
| TCP sessions through the firewall | yes | pfsync replicates state to the backup; `state-policy floating` lets replicated states match traffic on the new master's interface |
| WireGuard tunnels | yes* | Tunnels replicate to the standby but run only on the CARP MASTER; the new master brings them up within ~2 s of taking over. Existing peers reconnect within ~5 s **provided remote peers have `PersistentKeepalive` ≤ 5** (the default is off — peers without keepalive only reconnect on next outbound traffic) |
| IPsec (IKEv2) tunnels | re-established | Tunnels replicate; the BACKUP renders them passive (`start_action = none`) so it never initiates with the master's identities, and re-renders them active when it becomes MASTER. SAs are not synced — IKE re-negotiates after failover |
| DHCP leases (rDHCP) | yes | rDHCP HA handles its own state replication; AiFw's `dhcp_link` flag keeps the peer list in sync |
| ACME certificates | yes | renewal happens master-only; on success the cert+key are pushed to peers via `POST /api/v1/cluster/cert-push` |
| In-flight DNS lookups | no | small visible glitch during the failover window — most resolvers retry transparently |
| IDS in-memory ring buffer | no | rule overrides and suppressions are replicated; runtime alert ring buffer is not |

## Prerequisites

- **Two AiFw nodes on the same broadcast domain.** CARP advertisements use multicast (224.0.0.18); the nodes must see each other's L2 traffic.
- **Dedicated NIC for pfsync.** pfsync is unauthenticated and AiFw refuses to put it on an interface that carries a CARP VIP. A point-to-point cable between two NICs is ideal.
- **Identical interface names on both nodes.** VIPs replicate by interface name, and multi-WAN `route-to`/`reply-to` states are interface-bound.
- **Synchronized time.** Both nodes should run NTP / `rtime` (the AiFw companion service). CARP advertisement timing is sensitive to clock drift.
- **Same software version.** Always upgrade the standby first; the cluster dashboard surfaces version drift between nodes.

## Security considerations

The replication channel between cluster nodes is treated as TRUSTED. Specifically:

- **Snapshot pushes carry secrets in plaintext.** The full firewall config is replicated across nodes, including VPN (WireGuard) private keys, preshared keys, DDNS TSIG keys, rDHCP HA TLS material, and the CARP shared password.
- **Inter-node calls are pinned to the peer's certificate** (SHA-256 of the API certificate, stored per node in `cluster_nodes.cert_fingerprint`; #317). The pin is learned on the first successful contact — trust-on-first-use, like an SSH `known_hosts` entry — and enforced from then on; a changed certificate fails the handshake and logs `TLS pin mismatch`. Daemon → local API loopback calls are pinned to `/usr/local/etc/aifw/tls/cert.pem` and follow that file when it changes.
  - Cert pushes (`cluster/cert-push`) clear the affected pins on both sides so the next contact re-learns them; a manual certificate change on a peer (self-signed regeneration, hand import) needs an operator re-pin: `aifw cluster nodes repin <id>` (optionally `--fingerprint <sha256>`), `POST /api/v1/cluster/nodes/{id}/repin`, or the **Re-pin** action on the HA → Nodes table.
  - The first contact and any re-pin are the residual MITM windows. Register nodes over a segment you trust, or pass the peer's fingerprint explicitly (`--fingerprint`, or the request body) instead of learning it.
- **Mitigation: use a dedicated, physically-secured pfsync NIC.** A back-to-back cable between the two nodes, or a VLAN that no other host can reach, is still the recommended configuration.
- **Per-peer API keys.** Each node holds an API key for the peer it pushes to (sealed at rest since #298); treat the DB file plus `secrets.key` as a credential store.
- **`/usr/local/etc/aifw/daemon.key`** holds the loopback API key used by daemon background tasks. File mode `640`, owned `root:aifw`. The aifw user must have read access; no other local user should.

If your network does not satisfy "trusted pfsync segment," do not enable HA replication.

## Setup

1. Install AiFw on both nodes via the ISO build.
2. On node A, in the first-boot wizard:
   - Answer **Yes** to "Configure HA pair?"
   - Choose **Primary**.
   - Select the pfsync interface, peer IP, password, and per-LAN/WAN VIPs.
3. On node B: run the same wizard, choose **Secondary**, enter the same VHIDs and password.
4. After both nodes are up: open **Cluster / HA → HA Dashboard** on node A. Expect MASTER on every VHID, the peer *answering* and reporting BACKUP, pfsync bulk sync *complete*, no demotion held and no warnings. Node health comes from an authenticated probe of the peer's API every 5 s.
5. Verify with `aifw cluster verify` on each node, then run `scripts/ha-verify.sh node-a node-b` over SSH for a pair-wide check.

Clusters built from the UI or API (instead of the wizard) get the same boot
handling: the first CARP VIP or pfsync config written sets
`aifw_cluster_enabled`, `aifw_cluster_role` and the boot/shutdown demotion
switches in `rc.conf`.

### Peer API port

Every cluster call to a peer (snapshot replication, health probes, cert push) goes to `https://<peer address>:<api_port>`. The port defaults to 8080 and is stored per node (`api_port` on `POST/PUT /api/v1/cluster/nodes`, the *API port* field on the Cluster → Nodes form, `aifw cluster nodes add --api-port`) — set it when a peer's API listens elsewhere.

### WireGuard and IPsec follow the CARP role

Both nodes hold the same WireGuard private keys and IPsec identities, so in
a cluster only the CARP MASTER runs WireGuard and initiates IPsec. The API
re-checks the kernel every 2 seconds (and immediately on a role-change
event): on MASTER it brings the enabled WireGuard tunnels up and renders
IPsec tunnels with their configured `start_action`; on BACKUP it tears
WireGuard down and renders IPsec passive (`start_action = none`). The older
`wg_deconfigure_on_backup` setting is kept for compatibility but no longer
changes anything.

## How CARP is driven

All CARP and pfsync kernel changes go through one root helper,
`/usr/local/libexec/aifw-sudo-carp`; the API and daemon run unprivileged and
call it via sudo.

- **Preemption is always on** (`net.inet.carp.preempt=1`, set at boot and on
  every reconcile). Without it a demoted master keeps the VIPs, and a failed
  interface doesn't move the other VIPs with it.
- **Demotion is tracked per reason.** `net.inet.carp.demotion` is an
  adjustment — writing N *adds* N — so AiFw keeps a ledger
  (`/var/run/aifw-carp/<reason>`) and adds or removes one step of 240 per
  reason exactly once. Reasons: `boot`, `shutdown`, `health`, `manual`,
  `maintenance`. The dashboard and `GET /cluster/status` show which are held.
- **AiFw only removes CARP addresses it manages** — VIPs deleted or moved
  through AiFw (UI, API, restore, replication). CARP addresses configured
  outside AiFw are left alone.
- **VIPs are created by aifw-daemon, not rc.conf.** The daemon configures
  pfsync0 (loading `pfsync(4)` if needed) and every VHID from the database.
  The CARP password is never written to `rc.conf`; it reaches the helper over
  stdin and is only on `ifconfig`'s own command line for the instant it runs.

### Boot sequence

1. `rc.d/aifw_carp_demote` runs before any interface is configured: enables
   preemption and holds a `boot` demotion (plus `maintenance` if persistent
   maintenance mode is on).
2. pfsync0 comes up from `rc.conf`, then pf.
3. aifw-daemon loads the `aifw-ha` pf anchor (CARP and pfsync pass rules),
   configures pfsync and the VHIDs, and releases the `boot` hold once
   pfsync's bulk update has finished (`syncok: 1` in `ifconfig pfsync0`)
   **and**, if the peer is MASTER, this node has the peer's replicated
   config — minimum 10 s, maximum 120 s.
4. If aifw-daemon never releases it (disabled, crashing), a failsafe started
   by step 1 releases the hold after 5 minutes.

A rebooted primary therefore comes back as BACKUP, receives the state table
and any config edits made on the peer while it was down, and only then
preempts. Running `service aifw_carp_demote start` again later is a no-op.

## Latency profiles

The `pfsync.latency_profile` setting sets the secondary's advskew. A BACKUP
declares the master dead after `3 × advbase + advskew/256` seconds without an
advertisement, and CARP's advbase cannot go below 1 s, so **hard-failure
takeover is about 3 seconds with every profile**:

| Profile | advbase | secondary advskew | Hard-failure takeover |
|---|---|---|---|
| Conservative *(default)* | 1 | 100 | ~3.4 s |
| Tight | 1 | 20 | ~3.1 s |
| Aggressive | 1 | 10 | ~3.0 s |

The primary uses advskew 0 regardless of profile. Timing follows the node's
*configured* role, so a primary that is temporarily BACKUP keeps advskew 0 and
takes the VIPs back once healthy.

**Planned** moves — demote, maintenance mode, shutdown, a failing health
check — don't wait for the timeout: the demoted node advertises a worse skew
and the peer preempts within about one advertisement (~1 s).

```sh
aifw cluster pfsync set --latency-profile tight
```

Or via the API (`PUT /api/v1/cluster/pfsync`).

## Minimizing the unplanned-failure gap

On shutdown or reboot, `aifw_demote_on_shutdown` holds a `shutdown` demotion
and waits 2 s before the data plane goes down, so the peer takes over first;
a reboot of the master typically misses zero to two packets. Restarting the
AiFw services (including `aifw update install --restart`) does **not** demote:
pf, pfsync and CARP live in the kernel and keep forwarding throughout.

For unplanned failures (power loss, kernel panic, NIC death) the gap is CARP's
~3 s detection:

- **UPS on each node** is the single biggest reliability win. It turns power
  loss into a graceful shutdown with a full CARP demote.
- **Dedicated pfsync NIC** keeps replication off the data plane.
- **Leave pfsync `defer` off** unless you have a reason: it holds the first
  packet of every new connection until the peer acknowledges the state. New
  pfsync configs default to off; configs created before #712 keep their
  setting (it used to default on) — check Cluster → pfsync.

Without a UPS, a hard power loss results in:

- TCP sessions: survive (pfsync replicated the state in real time).
- UDP packets in flight: lost.
- User-visible outage: ~3–3.5 s.

## Split-brain handling

If the links between the nodes fail but both stay up, both may become MASTER
(a "split brain").

- **Detection.** Each node's peer monitor asks the other for its live CARP
  role every 5 s. When both report MASTER, the dashboard turns red, the status
  API sets `split_brain: true`, an error is logged, and a
  `split_brain_detected` event is recorded (`split_brain_resolved` when it
  clears). A node also refuses config pushes while any of its VHIDs is MASTER,
  and a configured primary refuses them while CARP is still initialising.
- **Resolution is the kernel's.** With preemption on, once advertisements get
  through again the node with the lower effective advskew wins and the other
  falls back to BACKUP.
- Whichever node ends up BACKUP accepts the master's next snapshot push,
  replacing config edits made during the partition. They remain in the audit
  log.
- A node that is MASTER on some VHIDs and BACKUP on others is reported as
  `split`; with preemption on this only happens while an interface is down.

## Operations

### Planned maintenance / rolling upgrade

Always upgrade the standby first.

```sh
# On the standby
aifw update install --restart
```

Restarting the AiFw services doesn't touch CARP or pf, so traffic keeps
flowing on the node being upgraded. After the standby is healthy on the new
version, move the VIPs and upgrade the other node:

```sh
aifw cluster maintenance on    # on the master: VIPs move to the peer, stays BACKUP across reboots
aifw update install --restart  # upgrade (reboot if the update needs it)
aifw cluster maintenance off   # take the VIPs back (the primary preempts)
```

Confirm version drift is gone via `aifw cluster nodes list` (or the dashboard's
per-node panel — the `software_version` field shows the running version of each
node).

### Manual promote / demote

```sh
aifw cluster demote            # hand the VIPs to the peer until promote or reboot
aifw cluster promote           # clear manual demotion and maintenance mode
aifw cluster maintenance on    # stay BACKUP, across reboots, until turned off
aifw cluster maintenance off
```

`promote` clears this node's operator holds; it does not force MASTER over a
peer with a better advskew. To move the VIPs to the secondary, demote (or put
into maintenance) the primary. The same actions are on the HA Dashboard.

### Decommission a node

```sh
aifw cluster nodes remove <node-id>
```

Obtain the `<node-id>` from `aifw cluster nodes list`. To run the remaining
node standalone, also remove its CARP VIPs and pfsync config; that clears
`aifw_cluster_enabled` and the boot/shutdown demotion switches.

### Force a config sync

```sh
aifw cluster sync     # this node pulls the current snapshot from the primary
```

The dashboard's **Force sync from peer** button does the same thing. It pulls
from the peer that currently reports MASTER (or the only peer). Use this
when the standby's `cluster_snapshot_state.last_applied_hash` doesn't match the
master's live config hash and the next replicator tick is too far away.

Replication always flows from the current MASTER to the other node —
including from a promoted secondary back to the primary while the primary is
BACKUP — so changes made during a failover survive the primary's return.
Each node therefore needs a peer key for the other (Generate Peer Key on
both, register each on the opposite node); the dashboard warns when one is
missing.

Replication carries cluster-wide config only. Each node keeps its own node
table (peer keys, TLS pins, API ports), pfsync settings, DHCP-HA peer settings,
hostname and `/etc/resolv.conf`; services (rDHCP, DNS resolver, IPsec, …) are
only restarted on the standby when their section actually changed. A backup
taken on one node and restored on the other keeps the target's cluster
identity.

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
aifw cluster verify --json | python3 -m json.tool
```

Run as root on a node, `aifw cluster` authenticates with the on-box CLI key
(created on first use). From elsewhere, `aifw login https://<node>:8080` first,
or set `AIFW_TOKEN` to an API key with `ha:manage`. `--all-contexts cluster
verify` checks every node you have a context for.

The `verify` command checks:

1. `pf.conf.aifw` sets `state-policy floating`.
2. CARP VHIDs exist in the kernel, none in INIT, and they agree (no `split`).
3. `net.inet.carp.preempt` is 1 and no demotion is held.
4. `pfsync0` is up, has a syncdev, and its bulk update completed.
5. The peer is answering its API and there is no split brain.
6. On the secondary: a config snapshot from the primary has been applied.

`aifw cluster health run` runs every enabled health check once and prints the
results (the dashboard's **Run now** button does the same).

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
- **Out-of-band heartbeat daemon** — the `heartbeat_iface` /
  `heartbeat_interval_ms` fields exist on `pfsync_config`, but nothing consumes
  them yet; sub-3-second hard-failure detection would need it.
- **NUT (Network UPS Tools) integration** — strongly recommended in this doc, but
  not built into AiFw. Configure NUT separately; a normal `shutdown -p now`
  already demotes CARP first.

## See also

- [Features overview →]({{ '/features/' | relative_url }})
- [Comparison with pfSense / OPNsense →]({{ '/compare/' | relative_url }})
- [Auth &amp; RBAC →]({{ '/docs/auth/' | relative_url }}) — RBAC perms required for cluster operations
