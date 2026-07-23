---
layout: default
title: DNS — AiFw rDNS resolver and blocklists
description: Configure the rDNS recursive resolver, host and domain overrides, DNS blocklists with auto-refresh, DNSSEC, and access control on AiFw.
permalink: /docs/dns/
date: 2026-05-09
breadcrumb:
  - { title: "Docs", url: "/docs/" }
  - { title: "DNS", url: "/docs/dns/" }
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "DNS — AiFw rDNS resolver and blocklists",
  "description": "Configure the rDNS recursive resolver, host and domain overrides, DNS blocklists with auto-refresh, DNSSEC, and access control on AiFw.",
  "author": { "@type": "Organization", "name": "ZerosAndOnesLLC" },
  "datePublished": "2026-05-09",
  "dateModified": "2026-05-09",
  "articleSection": "Networking"
}
</script>

<div class="content-page">
<article markdown="1">

# DNS

The DNS data plane on AiFw is the **rDNS** companion service &mdash; a recursive resolver shipped alongside the firewall. AiFw owns the control plane: host and domain overrides, access lists, blocklists with auto-refresh, DNSSEC validation, and forwarding configuration. The Unbound backend remains available; switch via the `backend` field in resolver config.

## Quickstart

In the Web UI go to **Services &rarr; DNS &rarr; Resolver** to configure listening interfaces, DNSSEC, forwarding, and DoT. **Services &rarr; DNS &rarr; Host overrides** maps a hostname to an IP. **Services &rarr; DNS &rarr; Blocklists** wires up subscription URLs and refresh schedules.

Read the resolver config:

```bash
curl https://aifw.local/api/v1/dns/resolver/config \
  -H "Authorization: Bearer $TOKEN"
```

Add a host override:

```bash
curl -X POST https://aifw.local/api/v1/dns/resolver/hosts \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "hostname": "nas",
    "domain": "local",
    "record_type": "A",
    "value": "192.168.1.50"
  }'
```

Add a blocklist source and refresh it:

```bash
curl -X POST https://aifw.local/api/v1/dns/blocklists \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{ "name": "stevenblack", "url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" }'

curl -X POST https://aifw.local/api/v1/dns/blocklists/{id}/refresh \
  -H "Authorization: Bearer $TOKEN"
```

Apply a config change to rDNS:

```bash
curl -X POST https://aifw.local/api/v1/dns/resolver/apply \
  -H "Authorization: Bearer $TOKEN"
```

## API endpoints

### Resolver

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/dns` | Read root DNS config (legacy compatibility wrapper) |
| `PUT` | `/api/v1/dns` | Update root DNS config |
| `GET` | `/api/v1/dns/resolver/status` | Resolver up/down + version |
| `GET` `PUT` | `/api/v1/dns/resolver/config` | Read or update full resolver config |
| `POST` | `/api/v1/dns/resolver/apply` | Render config + reload rDNS |
| `POST` | `/api/v1/dns/resolver/start` `/stop` `/restart` | Service control |
| `GET` `POST` | `/api/v1/dns/resolver/hosts` | Host overrides (A, AAAA, MX, CNAME) |
| `PUT` `DELETE` | `/api/v1/dns/resolver/hosts/{id}` | Update / delete host override |
| `GET` `POST` | `/api/v1/dns/resolver/domains` | Domain overrides (forward whole zones) |
| `PUT` `DELETE` | `/api/v1/dns/resolver/domains/{id}` | Update / delete domain override |
| `GET` `POST` | `/api/v1/dns/resolver/acls` | Access list entries |
| `PUT` `DELETE` | `/api/v1/dns/resolver/acls/{id}` | Update / delete ACL entry |
| `GET` | `/api/v1/dns/resolver/logs` | Tail recent resolver logs |

### Blocklists

| Method | Endpoint | Description |
|---|---|---|
| `GET` `POST` | `/api/v1/dns/blocklists` | List or create blocklist sources |
| `GET` `PUT` `DELETE` | `/api/v1/dns/blocklists/{id}` | Manage one source |
| `POST` | `/api/v1/dns/blocklists/{id}/refresh` | Refresh one source now |
| `POST` | `/api/v1/dns/blocklists/refresh-all` | Refresh every source |
| `GET` `PUT` | `/api/v1/dns/blocklists/schedule` | Refresh cadence |
| `PUT` | `/api/v1/dns/blocklists/enabled` | Toggle blocklists on/off |
| `GET` `POST` `DELETE` | `/api/v1/dns/whitelist` | Whitelist patterns that override the blocklist |
| `GET` `POST` `DELETE` | `/api/v1/dns/customblocks` | Custom block patterns |
| `GET` | `/api/v1/dns/stats` | Snapshot of query/block counters |
| `GET` | `/api/v1/dns/stream` | WebSocket stream of live blocklist metrics |

## DNS blocklists

A source has a name and a URL pointing at any standard hosts-file or domain-list format. Pull cadence is set via `PUT /api/v1/dns/blocklists/schedule`. The default block action is `nxdomain` (the resolver returns `NXDOMAIN`); switching to `redirect` requires a `blocklist_redirect_ip`. Whitelist patterns override blocklists, so adding `youtube.com` to the whitelist will pass even if a list contains it.

## DNSSEC

DNSSEC validation is **on by default** (`dnssec: true` in `ResolverConfig`). Toggle it from the resolver config endpoint.

## Forwarding (default on)

The resolver ships with `forwarding_enabled: true` and forwards to `1.1.1.1` + `8.8.8.8` out of the box. This is intentional: rDNS 1.12.8's iterative recursion returns referrals that don't always resolve cleanly, so forwarding is the battle-tested default. Operators who want pure recursion can flip `forwarding_enabled` off in the UI or via `PUT /api/v1/dns/resolver/config`.

## Recent change

Issue #231 (commit `22c28b8`) routes `/api/v1/dns` and the OPNsense importer through rDNS forwarders rather than rewriting `/etc/resolv.conf`. If you upgraded from an older build and saw forwarders mysteriously revert, this is what fixed it.

## Configuration

| Field | Default | Notes |
|---|---|---|
| `backend` | `rdns` | Switch to `unbound` to use the legacy backend |
| `port` | `53` | The resolver listens on this port |
| `dnssec` | `true` | Validate DNSSEC signatures upstream |
| `dns64` | `false` | Synthesize AAAA records for IPv4-only names (RFC 6147) so v6-only clients work through NAT64 |
| `dns64_prefix` | `64:ff9b::/96` | /96 prefix for synthesized AAAAs — must match the NAT64 rule prefix |
| `register_dhcp` | `true` | Auto-publish DHCP leases as A records |
| `dhcp_domain` | `local` | Suffix appended to lease hostnames |
| `cache_max_ttl` / `cache_min_ttl` | `86400` / `0` | Resolver cache TTL bounds |
| `prefetch` | `true` | Refresh popular records before they expire |
| `rebind_protection` | `true` | Drop responses pointing to RFC1918 ranges |
| `probe_enabled` | `true` | After a backend switch, probe `:53` and auto-rollback on failure |

## See also

- [Features overview &rarr;]({{ '/features/' | relative_url }})
- [Comparison with pfSense / OPNsense &rarr;]({{ '/compare/' | relative_url }})
- [DHCP &rarr;]({{ '/docs/dhcp/' | relative_url }})
- [Firewall rules &rarr;]({{ '/docs/firewall/' | relative_url }})
- Source: [`aifw-api/src/dns_resolver.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-api/src/dns_resolver.rs)
- Source: [`aifw-api/src/dns_blocklists.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-api/src/dns_blocklists.rs)

</article>
</div>
