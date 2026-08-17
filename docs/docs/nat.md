---
layout: default
title: NAT — AiFw SNAT, DNAT, NAT64, NAT46
description: Configure SNAT, DNAT/port-forwarding, masquerade, 1:1 NAT, NAT64, and NAT46 on AiFw — including NAT46, unique to AiFw.
permalink: /docs/nat/
date: 2026-05-09
breadcrumb:
  - { title: "Docs", url: "/docs/" }
  - { title: "NAT", url: "/docs/nat/" }
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "NAT — AiFw SNAT, DNAT, NAT64, NAT46",
  "description": "Configure SNAT, DNAT/port-forwarding, masquerade, 1:1 NAT, NAT64, and NAT46 on AiFw — including NAT46, unique to AiFw.",
  "author": { "@type": "Organization", "name": "ZerosAndOnesLLC" },
  "datePublished": "2026-05-09",
  "dateModified": "2026-05-09",
  "articleSection": "Networking"
}
</script>

<div class="content-page">
<article markdown="1">

# NAT

AiFw supports four working NAT types today &mdash; SNAT, DNAT (port forwarding), Masquerade, and 1:1 BiNAT. All NAT rules compile into the dedicated `aifw-nat` anchor and never touch the system pf config.

> **NAT64 and NAT46 perform real cross-family translation** via pf `af-to` (FreeBSD 15+), validated by automated live-traffic tests (TCP, UDP, and ICMP↔ICMPv6) in CI. See the per-type sections below for the address-mapping rules.

## Quickstart

In the Web UI, go to **Firewall &rarr; NAT &rarr; Add rule**. Pick the NAT type, the interface the rule applies to, optional protocol/source/destination filters, and the redirect target.

Create a port forward (DNAT) for inbound HTTPS to an internal host:

```bash
curl -X POST https://aifw.local/api/v1/nat \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "nat_type": "dnat",
    "interface": "em0",
    "protocol": "tcp",
    "src_addr": "any",
    "dst_addr": "any",
    "dst_port": "443",
    "redirect": { "address": "192.168.1.10", "port": "443" },
    "label": "fwd-https"
  }'
```

DNAT rules automatically receive a NAT-reflection companion so reply traffic from the internal host routes back through the firewall (no asymmetric routing).

Then reload to push to pf:

```bash
curl -X POST https://aifw.local/api/v1/reload \
  -H "Authorization: Bearer $TOKEN"
```

## CLI

```bash
aifw nat add --type snat --interface em0 --src 192.168.1.0/24 --redirect 203.0.113.1
aifw nat add --type dnat --interface em0 --proto tcp --dst-port 80 \
             --redirect 192.168.1.10 --redirect-port 8080
aifw nat list
aifw nat remove <uuid>
```

## API endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/nat` | List all NAT rules |
| `GET` | `/api/v1/nat/{id}` | Get one rule |
| `GET` | `/api/v1/nat/pf-output` | Show the rendered pf NAT syntax |
| `POST` | `/api/v1/nat` | Create a rule |
| `PUT` | `/api/v1/nat/{id}` | Update a rule |
| `DELETE` | `/api/v1/nat/{id}` | Delete a rule |
| `PUT` | `/api/v1/nat/reorder` | Reorder NAT rules by UUID array |

## NAT types

### SNAT &mdash; source NAT

Rewrite the source address on outbound traffic to a fixed public IP. Use when you have a single static public address and need explicit, deterministic source addressing rather than the dynamic interface address.

```json
{ "nat_type": "snat", "interface": "em0",
  "src_addr": "192.168.1.0/24", "dst_addr": "any",
  "redirect": { "address": "203.0.113.1" } }
```

### DNAT &mdash; destination NAT / port forwarding

Forward inbound traffic on the WAN to an internal host. Compiles to a pf `rdr` rule plus an automatic reflection companion so replies route back through the firewall.

```json
{ "nat_type": "dnat", "interface": "em0", "protocol": "tcp",
  "dst_addr": "any", "dst_port": "443",
  "redirect": { "address": "192.168.1.10", "port": "443" } }
```

DNAT rules require either `dst_port` or a port on the redirect target.

### Masquerade

Dynamic source NAT using whichever address the WAN interface currently holds. The default for most home/SOHO setups where the WAN gets a DHCP-assigned public IP. The redirect address is ignored &mdash; pf uses `(<iface>)` and follows the interface address as it changes.

```json
{ "nat_type": "masquerade", "interface": "em0",
  "src_addr": "192.168.1.0/24", "dst_addr": "any",
  "redirect": { "address": "any" } }
```

### BiNAT &mdash; 1:1 NAT

Bidirectional 1:1 mapping between an internal address and an external address. Compiles to a single `binat` rule that handles both inbound and outbound translation.

```json
{ "nat_type": "binat", "interface": "em0",
  "src_addr": "192.168.1.10", "dst_addr": "any",
  "redirect": { "address": "203.0.113.10" } }
```

### NAT64

Let IPv6-only clients reach IPv4 servers. Compiles to a pf `af-to` filter rule (FreeBSD 15+) that statefully translates the address family, including return traffic and ICMPv6↔ICMP (RFC 7915):

```
pass in quick on em0 inet6 from any to 64:ff9b::/96 af-to inet from 203.0.113.1
```

Field mapping:

| Field | Meaning | Requirement |
|---|---|---|
| `src_addr` | IPv6 clients allowed to translate | IPv6 network or `any` |
| `dst_addr` | The NAT64 translation prefix | IPv6 prefix, exactly `/96` (default `64:ff9b::/96`) |
| `redirect.address` | IPv4 the firewall sources translated traffic from (usually the WAN address) | single IPv4 host |

Clients reach an IPv4 host by embedding its address in the low 32 bits of the prefix (RFC 6052): `10.1.2.3` becomes `64:ff9b::a01:203`. Print the embedding with `aifw nat embed 64:ff9b::/96 10.1.2.3`. The UI shows a live preview as you type.

```json
{ "nat_type": "nat64", "interface": "em0",
  "src_addr": "any", "dst_addr": "64:ff9b::/96",
  "redirect": { "address": "203.0.113.1" } }
```

**DNS64**: enable the `DNS64` toggle in DNS &rarr; Settings (rDNS backend) and set its prefix to the **same /96 prefix as the NAT64 rule**. The resolver then synthesizes AAAA records for IPv4-only names, so v6-only clients resolve and connect with no per-host configuration. If a name has real AAAA records those are used as-is (no synthesis, no translation).

Selecting protocol `icmp` on a NAT64 rule renders as `icmp6` automatically &mdash; the rule matches the IPv6 side.

### NAT46

Let IPv4-only clients reach an IPv6 service. Compiles to the opposite `af-to` direction:

```
pass in quick on em0 inet from any to 192.0.2.80 af-to inet6 from 2001:db8:2::1
```

Field mapping: `src_addr`/`dst_addr` are IPv4 (a concrete destination is required); `redirect.address` is a single IPv6 host the firewall owns. By default the translated destination is the IPv4 destination embedded in the /96 subnet of that IPv6 source (RFC 6052) &mdash; so the IPv6 server must answer on the embedded address (`192.0.2.80` under `2001:db8:2::/96` &rarr; `2001:db8:2::c000:250`; check with `aifw nat embed`).

To reach an IPv6 server on an address it already has, set **`af_to_dst`** (UI: *Translated destination*, CLI: `--af-to-dst`) to that single IPv6 host; pf then rewrites the destination explicitly:

```
pass in quick on em0 inet from any to 192.0.2.80 af-to inet6 from 2001:db8:2::1 to 2001:db8:2::80
```

```json
{ "nat_type": "nat46", "interface": "em0",
  "src_addr": "any", "dst_addr": "192.0.2.80",
  "redirect": { "address": "2001:db8:2::1" },
  "af_to_dst": "2001:db8:2::80" }
```

`af_to_dst` works the same way on NAT64 rules (a single IPv4 host instead of the address embedded in the /96), and is rejected on every other NAT type. NAT46 is uncommon on most firewall distros &mdash; AiFw exposes it as a first-class rule type.

Cross-family notes (both types): `af-to` translates addresses, not ports (`redirect.port` is rejected); rules apply to inbound traffic on the selected interface; pf tables aren't allowed on the matched side (family must be concrete); requires FreeBSD 15+ (every AiFw appliance image ships on 15.x).

## Configuration

| Field | Default | Notes |
|---|---|---|
| Anchor name | `aifw-nat` | NAT rules live in their own anchor, separate from filter rules |
| `protocol` | `any` | NAT applies regardless of L4 protocol unless you scope it |
| Reflection (DNAT) | always on | A second `nat` rule is auto-generated so replies route back through the firewall |
| `label` | optional | nat-class rules can't carry the pf `label` keyword (stored for UI display); NAT64/NAT46 rules are filter-class and DO emit the label for per-rule counters |

## See also

- [Features overview &rarr;]({{ '/features/' | relative_url }})
- [Comparison with pfSense / OPNsense &rarr;]({{ '/compare/' | relative_url }})
- [Firewall rules &rarr;]({{ '/docs/firewall/' | relative_url }})
- [Multi-WAN &rarr;]({{ '/multi-wan/' | relative_url }})
- Source: [`aifw-core/src/nat.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-core/src/nat.rs)
- Source: [`aifw-common/src/nat.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-common/src/nat.rs)

</article>
</div>
