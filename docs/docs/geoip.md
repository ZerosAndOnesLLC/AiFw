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

## Quickstart

In the Web UI go to **Firewall &rarr; Geo-IP** and click **Add rule**. Pick a country, an action (block or allow), and an optional label.

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
aifw geoip lookup 1.2.3.4
aifw geoip list
aifw geoip remove <uuid>
```

## API endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/geoip` | List geo-IP rules |
| `POST` | `/api/v1/geoip` | Create a rule |
| `PUT` | `/api/v1/geoip/{id}` | Update a rule |
| `DELETE` | `/api/v1/geoip/{id}` | Delete a rule |
| `GET` | `/api/v1/geoip/lookup/{ip}` | Resolve an IP to its country code |

## How it works

Each rule generates a pf table named `geoip_<cc>` (e.g. `geoip_cn`, `geoip_ru`) populated with the country's networks from the GeoLite2 database. The compiled pf rule is:

```text
block drop in quick from <geoip_cn> label "geoip-block-CN"
```

`pass`-action rules use `pass in quick`. Adjacent and overlapping CIDRs are merged before being loaded into the table so a country's table stays small enough to evaluate cheaply.

## Configuration

| Field | Default | Notes |
|---|---|---|
| Anchor name | `aifw-geoip` | Dedicated anchor, separate from the main rule list |
| `db_path` | `/var/db/aifw/geoip` | GeoLite2 CSV directory |
| `update_interval_hours` | `168` (weekly) | Set to `0` to disable auto-update |
| `license_key` | unset | Optional MaxMind license key for direct downloads |
| `country` (rule) | required | Two-letter ISO 3166-1 alpha-2 code; case-insensitive on input |

## See also

- [Features overview &rarr;]({{ '/features/' | relative_url }})
- [Comparison with pfSense / OPNsense &rarr;]({{ '/compare/' | relative_url }})
- [Firewall rules &rarr;]({{ '/docs/firewall/' | relative_url }})
- Source: [`aifw-core/src/geoip.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-core/src/geoip.rs)
- Source: [`aifw-common/src/geoip.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-common/src/geoip.rs)

</article>
</div>
