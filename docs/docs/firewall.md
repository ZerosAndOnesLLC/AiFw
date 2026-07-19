---
layout: default
title: Firewall rules — AiFw stateful pf rules
description: Build stateful firewall rules on AiFw with FreeBSD pf — scheduling, aliases, traffic shaping, and IPv4/IPv6 dual-stack matching.
permalink: /docs/firewall/
date: 2026-05-09
breadcrumb:
  - { title: "Docs", url: "/docs/" }
  - { title: "Firewall rules", url: "/docs/firewall/" }
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "Firewall rules — AiFw stateful pf rules",
  "description": "Build stateful firewall rules on AiFw with FreeBSD pf — scheduling, aliases, traffic shaping, and IPv4/IPv6 dual-stack matching.",
  "author": { "@type": "Organization", "name": "ZerosAndOnesLLC" },
  "datePublished": "2026-05-09",
  "dateModified": "2026-05-09",
  "articleSection": "Networking"
}
</script>

<div class="content-page">
<article markdown="1">

# Firewall rules

AiFw rules are stateful pf rules that live in a dedicated `aifw` anchor and are persisted in SQLite. The rule engine compiles each row into pf syntax, calls `pfctl` (or the in-memory mock on Linux/WSL), and never touches the system pf config. Match by interface, address family, protocol, source/destination with optional invert, attach a schedule, and reorder by drag-and-drop.

## Quickstart

Open the Web UI and go to **Firewall &rarr; Rules &rarr; Add rule**. Choose an action (`pass`, `block`, `block drop`, or `block return`), a direction (`in`, `out`, `any`), an IP version (`inet`, `inet6`, `both` &mdash; default), a protocol, source and destination addresses with optional ports, and an optional schedule.

Create one from the API:

```bash
curl -X POST https://aifw.local/api/v1/rules \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "action": "pass",
    "direction": "in",
    "ip_version": "both",
    "protocol": "tcp",
    "rule_match": {
      "src_addr": "any",
      "dst_addr": "any",
      "dst_port": "443"
    },
    "log": false,
    "quick": true,
    "label": "allow-https"
  }'
```

Reorder rules in bulk:

```bash
curl -X PUT https://aifw.local/api/v1/rules/reorder \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"order": ["<uuid-1>", "<uuid-2>", "<uuid-3>"]}'
```

Push the new ruleset to pf:

```bash
curl -X POST https://aifw.local/api/v1/reload \
  -H "Authorization: Bearer $TOKEN"
```

## CLI

```bash
aifw rules add --action pass --direction in --proto tcp --dst-port 443 --label "allow-https"
aifw rules add --action block --direction in --proto tcp --dst-port 22 --src 10.0.0.0/8
aifw rules list
aifw rules remove <uuid>
aifw reload
```

## API endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/rules` | List all AiFw rules |
| `GET` | `/api/v1/rules/system` | Show the system pf rules outside the `aifw` anchor |
| `GET` | `/api/v1/rules/{id}` | Get one rule |
| `POST` | `/api/v1/rules` | Create a rule |
| `PUT` | `/api/v1/rules/{id}` | Update a rule |
| `DELETE` | `/api/v1/rules/{id}` | Delete a rule |
| `PUT` | `/api/v1/rules/reorder` | Reorder rules by UUID array |
| `PUT` | `/api/v1/rules/block-logging` | Toggle the global block-rules-log default |
| `POST` | `/api/v1/reload` | Recompile and apply all rules + NAT to pf |
| `GET` | `/api/v1/aliases` | List aliases |
| `POST` | `/api/v1/aliases` | Create an alias |
| `PUT` | `/api/v1/aliases/{id}` | Update an alias |
| `DELETE` | `/api/v1/aliases/{id}` | Delete an alias |
| `GET` | `/api/v1/schedules` | List schedules |
| `POST` | `/api/v1/schedules` | Create a schedule |

## Aliases

An alias is a named bag of addresses, networks, hosts, or ports that is referenced in the source or destination of a rule. Aliases compile to pf tables on reload, so adding an entry is one INSERT plus one reload &mdash; no rule edit required. Use them for "trusted admins", "blocked countries", "internal RFC1918", etc. They keep the rule list short and let you bulk-update membership without touching policy.

## Scheduling

A schedule is a named time window with two fields:

- `time_ranges` &mdash; one or more `HH:MM-HH:MM` ranges, e.g. `"08:00-12:00,13:00-17:00"`.
- `days_of_week` &mdash; comma-separated short names, e.g. `"mon,tue,wed,thu,fri"`.

Attach a `schedule_id` to a rule and the rule is only loaded into pf during the active window. Outside the window the rule is dropped from the compiled ruleset.

Evaluation semantics:

- Windows are evaluated against the appliance's **local time** (system timezone, including DST).
- Range ends are exclusive (`08:00-17:00` deactivates at 17:00). A range that crosses midnight (`22:00-06:00`) belongs to the day it starts and runs into the next morning. `00:00-00:00` means the whole day.
- The daemon re-evaluates schedules once per minute (the same cadence pfSense/OPNsense use) and reloads the ruleset when a rule crosses a window boundary; schedule edits via the API reload immediately.
- A disabled schedule, or a `schedule_id` pointing at a deleted schedule, does not constrain the rule — it stays loaded as if unscheduled (fail-open is deliberate: rules can be `block` as well as `pass`, and unloading a block rule on a dangling reference would open the firewall).

## Traffic shaping

Queue policy lives alongside rules. Three queue disciplines are supported via the `aifw queue` subcommand:

- **CoDel** &mdash; default, low-latency AQM. Best for general LAN/WAN egress.
- **HFSC** &mdash; hierarchical share-based scheduler with bandwidth percentages. Use when you need strict per-class allocations (VoIP, interactive, default, bulk).
- **PRIQ** &mdash; strict priority queueing. Highest-priority class always preempts lower ones.

```bash
aifw queue add --name voip --interface em0 --type hfsc --bandwidth 1Gb --class voip --pct 20
```

Queues are a separate anchor; the firewall rule references the queue by name.

## Configuration

| Field | Default | Notes |
|---|---|---|
| Anchor name | `aifw` | All AiFw filter rules go here; the system pf ruleset just hooks the anchor |
| `quick` | `true` | The first matching rule wins. Disable for traditional last-match semantics |
| `log` | `false` for pass; **always on** for block | Block rules are forced to log so dropped traffic appears in `pflog0` |
| `state_options.tracking` | `keep state` | `none`, `modulate state`, and `synproxy state` are also supported |
| `ip_version` | `both` | Set to `inet` or `inet6` to scope a rule to a single family |
| `priority` | `100` | Used as the default sort key; UI drag-and-drop overrides this via `/rules/reorder` |

State tracking only applies to `pass` rules. Block rules in pf cannot keep state.

## See also

- [Features overview &rarr;]({{ '/features/' | relative_url }})
- [Comparison with pfSense / OPNsense &rarr;]({{ '/compare/' | relative_url }})
- [NAT &rarr;]({{ '/docs/nat/' | relative_url }})
- [Geo-IP &rarr;]({{ '/docs/geoip/' | relative_url }})
- [Multi-WAN &rarr;]({{ '/multi-wan/' | relative_url }})
- Source: [`aifw-core/src/engine.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-core/src/engine.rs)
- Source: [`aifw-common/src/rule.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-common/src/rule.rs)

</article>
</div>
