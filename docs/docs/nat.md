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

AiFw supports SNAT, DNAT (port forwarding), Masquerade, and 1:1 BiNAT. NAT64 and NAT46 are retained as experimental model values for compatibility but creation is rejected: the current pf text does not perform cross-family translation. All supported NAT rules compile into the dedicated `aifw-nat` anchor.

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

**Unavailable.** No cross-family FreeBSD data-plane backend is implemented. The API returns `501 Not Implemented` for new or updated NAT64 rules.

```json
{ "nat_type": "nat64", "interface": "em0",
  "src_addr": "64:ff9b::/96", "dst_addr": "any",
  "redirect": { "address": "203.0.113.1" } }
```

### NAT46

**Unavailable.** No cross-family FreeBSD data-plane backend is implemented. The API returns `501 Not Implemented` for new or updated NAT46 rules.

```json
{ "nat_type": "nat46", "interface": "em0",
  "src_addr": "any", "dst_addr": "any",
  "redirect": { "address": "2001:db8::1" } }
```

## Configuration

| Field | Default | Notes |
|---|---|---|
| Anchor name | `aifw-nat` | NAT rules live in their own anchor, separate from filter rules |
| `protocol` | `any` | NAT applies regardless of L4 protocol unless you scope it |
| Reflection (DNAT) | always on | A second `nat` rule is auto-generated so replies route back through the firewall |
| `label` | optional | NAT rules don't accept the pf `label` keyword; AiFw stores the label for UI display only |

## See also

- [Features overview &rarr;]({{ '/features/' | relative_url }})
- [Comparison with pfSense / OPNsense &rarr;]({{ '/compare/' | relative_url }})
- [Firewall rules &rarr;]({{ '/docs/firewall/' | relative_url }})
- [Multi-WAN &rarr;]({{ '/multi-wan/' | relative_url }})
- Source: [`aifw-core/src/nat.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-core/src/nat.rs)
- Source: [`aifw-common/src/nat.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-common/src/nat.rs)

</article>
</div>
