---
layout: default
title: "IDS / IPS — AiFw Suricata, Sigma, and YARA"
description: "Run Suricata, Sigma, and YARA rules on AiFw — three modes (Disabled / IDS alert-only / IPS inline drop), ET Open auto-update, alert classification, suppression, and AI behavioural detectors."
permalink: /docs/ids/
date: 2026-05-09
breadcrumb:
  - { title: "Docs", url: "/docs/" }
  - { title: "IDS / IPS", url: "/docs/ids/" }
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "IDS / IPS — AiFw Suricata, Sigma, and YARA",
  "description": "Run Suricata, Sigma, and YARA rules on AiFw — three modes (Disabled / IDS alert-only / IPS inline drop), ET Open auto-update, alert classification, suppression, and AI behavioural detectors.",
  "author": { "@type": "Organization", "name": "ZerosAndOnesLLC" },
  "datePublished": "2026-05-09",
  "dateModified": "2026-05-09",
  "articleSection": "Security"
}
</script>

<div class="content-page">
<article markdown="1">

# IDS / IPS

AiFw passively captures traffic and evaluates supported subsets of Suricata, Sigma, and YARA rule formats. It runs in one of three modes: **Disabled**, **IDS** (alert-only), or **Reactive blocking**. Reactive blocking adds the detected source address to a pf table after a match; it does not stop the triggering packet and may affect unrelated flows from that source. Behavioural AI detectors are opt-in.

## Quickstart

Open the Web UI and go to **IDS &rarr; Settings**. Pick a mode and an interface. Apply.

| Mode | Behaviour |
|---|---|
| `Disabled` | Engine off, no inspection |
| `IDS` | Inspect and log alerts; never block |
| `Reactive` | Inspect and alert, then add the source address to a pf block table; the triggering packet is not stopped |

From the API:

```bash
curl -X PUT https://aifw.local/api/v1/ids/config \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "mode": "ids",
    "interfaces": ["em0"],
    "home_net": ["10.0.0.0/8", "192.168.0.0/16"],
    "external_net": ["!$HOME_NET"],
    "alert_retention_days": 30,
    "eve_log_enabled": true
  }'

curl -X POST https://aifw.local/api/v1/ids/reload \
  -H "Authorization: Bearer $TOKEN"
```

## Rule formats

**Suricata-compatible.** The native format. AiFw parses Suricata 7.x syntax directly &mdash; `alert`, `drop`, `pass`, plus the usual `content`, `pcre`, `flow`, `threshold`, and `metadata` keywords. Existing Suricata rulesets drop in unchanged.

**Sigma.** YAML detection rules originally designed for log events. AiFw maps the detection section to network flow fields, so a Sigma rule that targets HTTP request URIs or DNS query names will fire on matching traffic. Sigma rules always alert &mdash; they never drop, regardless of mode.

**YARA.** Byte-pattern rules used for malware signatures. Useful inside reassembled HTTP / SMTP / FTP payloads. Run alongside Suricata rules in the same engine pass.

## ET Open integration

The seed ruleset is **ET Open** from Emerging Threats:

```
https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules
```

Auto-update runs every **24 hours** by default (configurable per ruleset via `update_interval_hours`). The engine fetches, parses, diffs against the live set, and reloads in place &mdash; no daemon restart. ET Open is shipped disabled-by-default; flip `enabled` on the ruleset to turn it on.

Add additional rulesets (Abuse.ch, ET Pro, custom feeds) via `POST /api/v1/ids/rulesets`. Each ruleset gets its own URL, format (`suricata` / `sigma` / `yara`), enable flag, and update cadence.

## AI threat detection

> **Status: opt-in / experimental.** The `aifw-ai` crate is a work in progress, disabled by default, and not yet production-ready. The Threats page in the UI marks this as WIP. See the README for the current framing.

Five behavioural detectors run on flow features extracted from conntrack:

| Detector | Trigger heuristic |
|---|---|
| **Port scan** | &geq; 15 unique destination ports with &geq; 60% failed connection ratio |
| **DDoS / SYN flood** | &gt; 100 SYNs with &gt; 80% failure ratio, or sustained &gt; 50 conn/sec |
| **Brute force** | &geq; 10 connections to &leq; 5 ports with &geq; 70% failure ratio |
| **C2 beacon** | &geq; 5 connections to &leq; 2 destinations with low duration variance and small payloads |
| **DNS tunneling** | &gt; 50 DNS queries with DNS / total connection ratio &gt; 80% |

Thresholds are tuneable per-detector at construction time. Detectors emit `Threat` records with a 0..1 score, evidence string, and per-metric breakdown that the API surfaces alongside Suricata alerts.

## Alert management

Every match &mdash; rule-driven or AI-detected &mdash; lands in the alerts table with severity, signature, source / destination, payload excerpt, and timestamp.

```bash
curl https://aifw.local/api/v1/ids/alerts?limit=50 \
  -H "Authorization: Bearer $TOKEN"

curl -X PUT https://aifw.local/api/v1/ids/alerts/{id}/acknowledge \
  -H "Authorization: Bearer $TOKEN"

curl -X PUT https://aifw.local/api/v1/ids/alerts/{id}/classify \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"classification": "false_positive", "notes": "internal scanner"}'
```

Acknowledged alerts stay in the timeline for audit but drop out of the unread counter. Classification (`true_positive`, `false_positive`, `benign`) feeds back into UI filters.

## Suppressions

Suppress noisy rules without disabling them. Three scopes:

- **By source IP** &mdash; ignore matches originating from a given address.
- **By destination IP** &mdash; ignore matches to a given address.
- **Per-rule** &mdash; ignore a specific signature ID entirely.

```bash
curl -X POST https://aifw.local/api/v1/ids/suppressions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"rule_sid": 2008581, "src_ip": "10.0.5.42"}'
```

Suppressions are paginated: `GET /api/v1/ids/suppressions?limit=50&offset=0`.

## API endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/ids/config` | Current engine config |
| `PUT` | `/api/v1/ids/config` | Update mode, interfaces, networks, retention |
| `POST` | `/api/v1/ids/reload` | Hot-reload rules without dropping flows |
| `GET` | `/api/v1/ids/stats` | Engine counters, packets, drops, memory |
| `GET` | `/api/v1/ids/alerts` | Paginated alert feed |
| `DELETE` | `/api/v1/ids/alerts` | Purge alerts (filtered) |
| `GET` | `/api/v1/ids/alerts/{id}` | One alert with full payload |
| `PUT` | `/api/v1/ids/alerts/{id}/acknowledge` | Mark as read |
| `PUT` | `/api/v1/ids/alerts/{id}/classify` | Set classification + notes |
| `GET` | `/api/v1/ids/alerts/buffer-stats` | Live alert ring-buffer stats |
| `GET` | `/api/v1/ids/rulesets` | List configured rulesets |
| `POST` | `/api/v1/ids/rulesets` | Add a new ruleset URL |
| `PUT` `/` `DELETE` | `/api/v1/ids/rulesets/{id}` | Update / remove a ruleset |
| `GET` | `/api/v1/ids/rules` | List parsed rules |
| `GET` | `/api/v1/ids/rules/search` | Full-text search rules |
| `GET` `/` `PUT` | `/api/v1/ids/rules/{id}` | Inspect or override a single rule |
| `GET` `/` `POST` | `/api/v1/ids/suppressions` | List / create suppressions |
| `DELETE` | `/api/v1/ids/suppressions/{id}` | Drop a suppression |

## See also

- [Features overview &rarr;]({{ '/features/' | relative_url }})
- [Comparison with pfSense / OPNsense &rarr;]({{ '/compare/' | relative_url }})
- [Firewall rules &rarr;]({{ '/docs/firewall/' | relative_url }})
- [Auth &amp; RBAC &rarr;]({{ '/docs/auth/' | relative_url }})
- Source: [`aifw-ids/src/`](https://github.com/ZerosAndOnesLLC/AiFw/tree/main/aifw-ids/src)
- Source: [`aifw-ai/src/detectors/`](https://github.com/ZerosAndOnesLLC/AiFw/tree/main/aifw-ai/src/detectors)

</article>
</div>
