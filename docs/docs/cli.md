---
layout: default
title: "CLI reference — aifw command line"
description: "Complete aifw CLI reference — rules, NAT, VPN, IDS, DHCP, DNS, multi-WAN, cluster, config, users, status, reload, with output examples."
permalink: /docs/cli/
date: 2026-05-09
breadcrumb:
  - { title: "Docs", url: "/docs/" }
  - { title: "CLI", url: "/docs/cli/" }
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "CLI reference — aifw command line",
  "description": "Complete aifw CLI reference — rules, NAT, VPN, IDS, DHCP, DNS, multi-WAN, cluster, config, users, status, reload, with output examples.",
  "author": { "@type": "Organization", "name": "ZerosAndOnesLLC" },
  "datePublished": "2026-05-09",
  "dateModified": "2026-05-09",
  "articleSection": "Reference"
}
</script>

<div class="content-page">
<article markdown="1">

# CLI reference

`aifw` is the local command-line interface to the AiFw daemon &mdash; it talks **directly to the SQLite database** and the local pf engine, not to the HTTP API. Use it when:

- You&rsquo;re on the appliance console (no UI) and need to inspect, recover, or change something.
- You want to script bulk imports or one-off changes without standing up an API client.
- You&rsquo;re writing post-install hooks or HA failover scripts that run as root locally.

For remote / unprivileged callers, use the [REST API]({{ '/docs/api/' | relative_url }}) instead &mdash; it does the same things but with full RBAC.

## Global flags

```
aifw [--db <path>] <subcommand> [<args>...]
```

| Flag | Default | Notes |
|---|---|---|
| `--db <path>` | `/var/db/aifw/aifw.db` | Path to the AiFw SQLite database. Override for tests or alternate installs. |
| `--help` / `-h` | &mdash; | Show help for any subcommand. |
| `--version` | &mdash; | Print the AiFw version string. |

Most list commands accept `--json` for machine-readable output. Most failures exit non-zero and print a one-line error to stderr.

## Subcommand groups

| Subcommand | Purpose |
|---|---|
| `aifw init` | Initialise the AiFw database file |
| `aifw rules` | Manage firewall rules |
| `aifw nat` | Manage NAT rules |
| `aifw queue` | Manage traffic queues (CoDel / HFSC / PRIQ) |
| `aifw ratelimit` | Manage rate-limit rules |
| `aifw geoip` | Manage geo-IP filtering |
| `aifw vpn` | Manage WireGuard / IPsec tunnels |
| `aifw config` | Versioned config history, import / export, rollback |
| `aifw routes` | Manage static routes |
| `aifw dns` | Manage DNS nameservers + post-switch probe |
| `aifw dhcp` | Manage the DHCP server (rDHCP) |
| `aifw users` | Manage local users |
| `aifw reverse-proxy` | Control TrafficCop |
| `aifw update` | AiFw firmware + OS updates |
| `aifw multiwan` | Multi-WAN instances, gateways, groups, policies, leaks |
| `aifw cluster` | HA / cluster operations (CARP, pfsync, nodes, health) |
| `aifw interfaces` | Show network interfaces |
| `aifw status` | Show firewall status |
| `aifw reload` | Reload rules from DB and apply to pf |
| `aifw reconcile` | Reconcile kernel pf state and rc.conf against DB / pf.conf.aifw |

Source: [`aifw-cli/src/main.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-cli/src/main.rs).

---

## init

Initialise the database (run once at install time; the installer wizard does this for you).

```bash
aifw init
aifw init --path /var/db/aifw/aifw.db
```

## rules

Manage stateful firewall rules in the `aifw` pf anchor.

```bash
# List rules
aifw rules list
aifw rules list --json

# Add a rule
aifw rules add \
  --action pass --direction in --proto tcp \
  --src any --dst any --dst-port 443 \
  --interface em0 --priority 100 \
  --label "https-inbound"

# Remove by UUID
aifw rules remove 8e2c1a9f-5c0e-4f7e-9a01-94f1b3a2e678
```

Field reference: `action` is `pass` / `block` / `block-drop` / `block-return`; `direction` is `in` / `out` / `any`; `priority` is 0&ndash;10000 (lower applies first).

## nat

Manage NAT rules in the `aifw-nat` anchor.

```bash
aifw nat list

# Port-forward 443 to an internal host
aifw nat add \
  --type dnat --interface em0 --proto tcp \
  --dst any --dst-port 443 \
  --redirect 10.0.0.20 --redirect-port 443 \
  --label "ingress-https"

# Outbound NAT (masquerade)
aifw nat add \
  --type masquerade --interface em0 --proto any \
  --src 10.0.0.0/24 --dst any --redirect any
```

Supported NAT types: `snat`, `dnat`, `masquerade`, `binat`, `nat64`, `nat46`.

## queue &amp; ratelimit

Traffic shaping and connection-rate limits.

```bash
# Create a CoDel queue capped at 100 Mb/s on em0
aifw queue add \
  --name uplink --interface em0 \
  --type codel --bandwidth 100Mb --class default --default

aifw queue list

# Limit any single source IP to 60 new TCP/443 conns per minute
aifw ratelimit add \
  --name https-flood --proto tcp \
  --max-conn 60 --window 60 \
  --table flooders --dst-port 443 --interface em0
```

Overload offenders land in the named pf table (`flooders` above) so you can block them with a rule.

## geoip

Country-level allow / block rules + interactive lookup.

```bash
aifw geoip add --country CN --action block --label "block China"
aifw geoip list
aifw geoip lookup 8.8.8.8
# => US — Google LLC (AS15169)
aifw geoip remove <id>
```

## vpn

WireGuard and IPsec tunnels in one tree.

```bash
# WireGuard tunnel
aifw vpn wg-add --name road-warriors \
  --interface wg0 --port 51820 --address 10.50.0.1/24

# Add a peer
aifw vpn wg-peer-add --tunnel <tunnel-id> \
  --name laptop --pubkey <peer-public-key> \
  --allowed-ips 10.50.0.10/32 --keepalive 25

# IPsec IKEv2 site-to-site tunnel (PSK; use the web UI/API for cert auth)
aifw vpn ipsec-add --name site-to-site \
  --remote 203.0.113.7 --psk <16+ char secret> \
  --local-ts 10.0.0.0/24 --remote-ts 10.1.0.0/24

# Live negotiated state from charon; manual initiate/terminate
aifw vpn ipsec-status
aifw vpn ipsec-start <tunnel-id>
aifw vpn ipsec-stop <tunnel-id>

aifw vpn list
```

## config

Versioned configuration: every `aifw reload` snapshots the active config so you can diff or roll back.

```bash
aifw config show
aifw config history --limit 20

# Diff version 17 against version 22
aifw config diff 17 22

# Rollback
aifw config rollback 17

# Export / import (full JSON dump)
aifw config export > backup.json
aifw config import backup.json
```

## routes

Static routes (kernel-level, separate from multi-WAN policy routing).

```bash
aifw routes add --dest 10.20.0.0/16 --gateway 10.0.0.1 --metric 0
aifw routes list
aifw routes system    # netstat -rn
aifw routes remove <id>
```

## dns

Manage the resolver&rsquo;s upstream nameservers and the post-switch probe (auto-rollback if `:53` goes silent after a backend swap).

```bash
aifw dns list
aifw dns set "1.1.1.1, 9.9.9.9"

aifw dns probe on        # enable auto-rollback
aifw dns probe off
aifw dns probe status
```

## dhcp

Drive the rDHCP companion service end-to-end.

```bash
aifw dhcp status
aifw dhcp start | stop | restart

# Subnets and reservations
aifw dhcp subnets
aifw dhcp subnet-add \
  --network 10.0.0.0/24 \
  --pool-start 10.0.0.100 --pool-end 10.0.0.200 \
  --gateway 10.0.0.1 --dns "10.0.0.1" \
  --domain "lan" --lease-time 86400

aifw dhcp reservations
aifw dhcp reservation-add \
  --mac aa:bb:cc:dd:ee:ff --ip 10.0.0.50 \
  --hostname printer-1

aifw dhcp leases
aifw dhcp apply       # write config + restart rDHCP
```

## users

Local-account CRUD. For SSO / OAuth users use the API or the UI.

```bash
aifw users add --username alice --password "...." --role admin
aifw users list
aifw users disable <id>
aifw users enable <id>
aifw users remove <id>
```

Roles: `admin` / `operator` / `viewer` (see [Auth &amp; RBAC]({{ '/docs/auth/' | relative_url }})).

## reverse-proxy

Control the local TrafficCop instance.

```bash
aifw reverse-proxy status
aifw reverse-proxy start | stop | restart
aifw reverse-proxy validate    # dry-run validate generated YAML
aifw reverse-proxy apply       # generate + write + reload

aifw reverse-proxy routers --json
aifw reverse-proxy services --json
aifw reverse-proxy middlewares
aifw reverse-proxy entrypoints
aifw reverse-proxy show-config   # print generated YAML
```

## update

AiFw firmware updates plus host OS / package updates.

```bash
# AiFw firmware
aifw update check
aifw update install                           # download + install latest
aifw update install --restart                 # also restart services
aifw update install --from /tmp/aifw.tar.xz   # local tarball
aifw update rollback                          # revert to previous version
aifw update restart                           # bounce services after install
aifw update reboot                            # full reboot

# OS / packages
aifw update os-check
aifw update os-install
```

`install` and `rollback` do **not** restart services automatically &mdash; run `aifw update restart` (or pass `--restart` / `-y`) when you&rsquo;re ready for the brief outage.

## multiwan

Inspect and apply multi-WAN configuration.

```bash
aifw multiwan instances
aifw multiwan gateways      # live health
aifw multiwan groups
aifw multiwan policies
aifw multiwan leaks
aifw multiwan flows         # live pf flows tagged by FIB
aifw multiwan fib-info

aifw multiwan apply         # recompile + apply all anchors
aifw multiwan seed-mgmt     # seed management-escape leaks

# Force a probe outcome (testing only)
aifw multiwan probe <gateway-id> ok
aifw multiwan probe <gateway-id> fail

# Export / import the full multi-WAN config as JSON
aifw multiwan export > mwan.json
aifw multiwan import mwan.json
```

## cluster

CARP + pfsync HA operations.

```bash
aifw cluster status --json

# CARP VIPs
aifw cluster carp list
aifw cluster carp add --vhid 10 --interface em0 \
  --vip 192.0.2.1/24 --password "carp-shared-secret"
aifw cluster carp remove <id>

# pfsync
aifw cluster pfsync get
aifw cluster pfsync set --sync-interface em1 --sync-peer 10.99.0.2 \
  --defer true --latency-profile conservative

# Cluster nodes
aifw cluster nodes list
aifw cluster nodes add --name node-b --address 10.99.0.2 --role secondary

# Health checks
aifw cluster health list
aifw cluster health add --name uplink --check-type ping \
  --target 8.8.8.8 --interval-secs 10
aifw cluster health run     # probe everything now

# Failover
aifw cluster promote        # this node -> master immediately
aifw cluster demote         # this node -> backup immediately
aifw cluster sync           # pull a snapshot from peer
aifw cluster verify --json  # exit non-zero if unhealthy
```

## interfaces / status / reload / reconcile

Diagnostic + apply commands.

```bash
aifw interfaces        # list interfaces with addresses + flags
aifw status            # daemon + pf health summary

aifw reload            # reload rules from DB and apply to pf
aifw reconcile         # repair drift between DB, pf.conf.aifw, and rc.conf
```

`reconcile` is the safe choice when you suspect the kernel pf state has drifted from the database &mdash; for example after a manual `pfctl -F` or a partial `freebsd-update` run. It re-applies anchor hooks if missing and fixes `rc.conf` DNS-backend flags that disagree with the database.

## Output formats

Subcommands that return lists accept `--json` to emit raw JSON for piping into `jq` or another tool:

```bash
aifw rules list --json | jq '.[] | select(.action == "block")'
aifw multiwan gateways | jq '.[] | {name, state}'
```

Subcommands without `--json` print human-readable tables.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `1` | Generic error (validation, missing record, runtime failure) &mdash; reason on stderr |
| `2` | Usage error (clap-level: bad args, unknown subcommand) |

`aifw cluster verify` is the most explicit user of non-zero exits &mdash; cron / monitoring scripts can rely on its exit code as a single-bit health signal.

## See also

- [REST API reference &rarr;]({{ '/docs/api/' | relative_url }})
- [Auth &amp; RBAC &rarr;]({{ '/docs/auth/' | relative_url }})
- [Backup &amp; migration &rarr;]({{ '/docs/backup/' | relative_url }})
- Source: [`aifw-cli/src/main.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-cli/src/main.rs)
- Source: [`aifw-cli/src/commands.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-cli/src/commands.rs)

</article>
</div>
