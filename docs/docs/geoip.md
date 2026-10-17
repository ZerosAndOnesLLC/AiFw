---
layout: default
title: Geo-IP — AiFw country-based blocking
description: Country-based block and allow rules on AiFw using GeoLite2. Per-rule action override, IP lookup endpoint, ISO 3166 alpha-2 country codes.
permalink: /docs/geoip/
date: 2026-05-09
breadcrumb:
  - { title: "Docs", url: "/docs/" }
  - { title: "Geo-IP", url: "/docs/geoip/" }
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "Geo-IP — AiFw country-based blocking",
  "description": "Country-based block and allow rules on AiFw using GeoLite2. Per-rule action override, IP lookup endpoint, ISO 3166 alpha-2 country codes.",
  "author": { "@type": "Organization", "name": "ZerosAndOnesLLC" },
  "datePublished": "2026-05-09",
  "dateModified": "2026-05-09",
  "articleSection": "Networking"
}
</script>

<div class="content-page">
<article markdown="1">

# Geo-IP

AiFw maps countries to pf tables and emits one `block drop` or `pass quick` rule per country. The country list is sourced from MaxMind's free **GeoLite2** CSV release; AiFw aggregates adjacent CIDRs to keep the pf tables compact. Each rule takes a 2-letter ISO 3166-1 alpha-2 code and an action (`allow` or `block`). Rules live in the dedicated `aifw-geoip` anchor.

## The database comes first

A rule is only as good as the networks behind it. Until a GeoLite2 release is loaded, every country table is empty and the Geo-IP page says so. Two ways to load one, both under **Firewall → Geo-IP → GeoLite2 database**:

- **Automatic (recommended).** Create a free account at maxmind.com, generate a license key, and paste your **account ID** (shown at the top of the portal) and the key into the page (or `aifw geoip database --account-id 123456` and `--license-key-stdin`). MaxMind authenticates downloads with the account ID and key together; a key alone is refused with HTTP 401 unless it predates that change. AiFw downloads the `GeoLite2-Country-CSV` release at once and then on a schedule — weekly by default, like pfBlockerNG and OPNsense; choose daily, monthly, or off. The key is stored encrypted and never shown again.
- **Manual.** Download `GeoLite2-Country-CSV_*.zip` from your MaxMind account and upload it on the page (or `aifw geoip import FILE.zip`). The three CSV files inside are accepted as separate uploads too.

The page shows how many countries and networks are loaded, where the data came from, when it was refreshed, when the next download is due, and the last error if a download failed. Each rule shows how many networks its country table holds.

## Quickstart

In the Web UI go to **Firewall &rarr; Geo-IP**, load the database as above, then use **Add a country rule**. Pick a country, an action (block or allow), and an optional label. Rules apply to pf as soon as they are saved; click a row to edit it in place.

Block all inbound traffic from a country:

```bash
curl -X POST https://aifw.local/api/v1/geoip \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ "country": "CN", "action": "block", "label": "block-cn" }'
```

Look up which country an IP belongs to:

```bash
curl https://aifw.local/api/v1/geoip/lookup/1.2.3.4 \
  -H "Authorization: Bearer $TOKEN"
```

Response:

```json
{ "ip": "1.2.3.4", "country": "AU", "network": "1.0.0.0/8" }
```

## CLI

```bash
aifw geoip add --country CN --action block
aifw geoip add --country US --action allow
aifw geoip list                                      # rules with live network counts
aifw geoip remove <uuid>

# the database (asks the running API; needs AIFW_TOKEN)
aifw geoip database                                  # loaded? source, schedule, last error
printf '%s' "$KEY" | aifw geoip database --license-key-stdin
aifw geoip database --update-interval-hours 168      # 0 turns the schedule off
aifw geoip refresh                                   # download from MaxMind now
aifw geoip import GeoLite2-Country-CSV_20261001.zip
aifw geoip lookup 1.2.3.4
```

Rule commands write the database directly and work without the API; the running API re-applies the anchor within a minute.

## API endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/geoip` | List geo-IP rules |
| `POST` | `/api/v1/geoip` | Create a rule |
| `PUT` | `/api/v1/geoip/{id}` | Update a rule |
| `DELETE` | `/api/v1/geoip/{id}` | Delete a rule |
| `GET` | `/api/v1/geoip/lookup/{ip}` | Resolve an IP to its country code |
| `GET` | `/api/v1/geoip/database` | Database status: loaded counts, source, schedule, last error |
| `PUT` | `/api/v1/geoip/database` | `{ "license_key": "…" \| null, "account_id": "123456" \| null, "update_interval_hours": 168 }` |
| `POST` | `/api/v1/geoip/database/refresh` | Download the GeoLite2 Country release from MaxMind now |
| `POST` | `/api/v1/geoip/database/upload` | Multipart upload of the GeoLite2 zip or its CSV files |

The rule list returns each rule with its pf `table` and `cidr_count` (networks in the loaded database for that country).

## How it works

Each rule reads a pf table named `geoip_<cc>` (e.g. `geoip_cn`, `geoip_ru`) that AiFw fills at the root with the country's networks from the GeoLite2 database. The compiled pf rule is:

```text
block drop in quick from <geoip_cn> label "geoip-block-CN"
```

The anchor never defines the table itself: a `table` line inside the anchor would create an empty anchor-local copy that shadows the root table (#704). `pass`-action rules use `pass in quick`. Adjacent and overlapping CIDRs are merged before being loaded so a country's table stays small enough to evaluate cheaply. Disabling or deleting a rule empties its table. The `freebsd/tests/t12-geoip.sh` harness test proves the whole path on a real kernel.

**Evaluation order.** `aifw-geoip` is hooked into `pf.conf` after the main rule set (`aifw`), so an explicit operator `pass` for a port is matched first and lets listed countries through on that port; a geo-IP *block* stops traffic that no operator rule has already accepted (useful with non-quick or broad pass rules), and a geo-IP *allow* opens all inbound traffic from that country past the default deny. Put the geo-IP block ahead of a port you have opened by adding a block rule for the country in the main rule set, or move the hook earlier in `pf.conf` if you want country blocks to override every pass rule.

## Configuration

| Field | Default | Notes |
|---|---|---|
| Anchor name | `aifw-geoip` | Dedicated anchor, separate from the main rule list |
| `db_path` | `/var/db/aifw/geoip` | GeoLite2 CSV directory (`GeoLite2-Country-Blocks-IPv4.csv`, `-IPv6.csv`, `GeoLite2-Country-Locations-en.csv`) |
| `update_interval_hours` | `168` (weekly) | Scheduled MaxMind download; `0` disables. A failed download is retried after 6 hours |
| `license_key` | unset | MaxMind license key; sealed at rest, required for downloads (uploads work without one) |
| `account_id` | unset | MaxMind account ID; with it set, downloads use the permalink with HTTP Basic auth (required for keys issued by the current portal) |
| `country` (rule) | required | Two-letter ISO 3166-1 alpha-2 code; case-insensitive on input |

## See also

- [Features overview &rarr;]({{ '/features/' | relative_url }})
- [Comparison with pfSense / OPNsense &rarr;]({{ '/compare/' | relative_url }})
- [Firewall rules &rarr;]({{ '/docs/firewall/' | relative_url }})
- Source: [`aifw-core/src/geoip.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-core/src/geoip.rs)
- Source: [`aifw-common/src/geoip.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-common/src/geoip.rs)

</article>
</div>
