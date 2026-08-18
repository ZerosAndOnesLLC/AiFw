---
layout: default
title: DHCP — AiFw DHCPv4 with HA failover
description: Configure rDHCP — multiple subnets, static reservations, HA failover with peer state sync, DDNS auto-updates, and per-subnet lease tuning.
permalink: /docs/dhcp/
date: 2026-05-09
breadcrumb:
  - { title: "Docs", url: "/docs/" }
  - { title: "DHCP", url: "/docs/dhcp/" }
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "DHCP — AiFw DHCPv4 with HA failover",
  "description": "Configure rDHCP — multiple subnets, static reservations, HA failover with peer state sync, DDNS auto-updates, and per-subnet lease tuning.",
  "author": { "@type": "Organization", "name": "ZerosAndOnesLLC" },
  "datePublished": "2026-05-09",
  "dateModified": "2026-05-09",
  "articleSection": "Networking"
}
</script>

<div class="content-page">
<article markdown="1">

# DHCP

The DHCP data plane on AiFw is the **rDHCP** companion service: a multi-subnet DHCPv4 server with HA-aware lease state. AiFw owns the control plane &mdash; subnets, static reservations, DDNS configuration, and HA mode. Configuration is rendered to rDHCP's TOML format on apply.

## Quickstart

In the Web UI go to **Services &rarr; DHCP &rarr; Subnets** to add a pool. Each subnet has a network CIDR, a `pool_start`/`pool_end` range, a gateway, and optional DNS, domain, lease times, and per-subnet DHCP option overrides. The **Leases** tab is grouped by subnet (re-organised in commit `0b36d37`) so a many-subnet deployment stays readable.

Add a subnet:

```bash
curl -X POST https://aifw.local/api/v1/dhcp/v4/subnets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "network": "192.168.1.0/24",
    "pool_start": "192.168.1.100",
    "pool_end": "192.168.1.200",
    "gateway": "192.168.1.1",
    "dns_servers": ["192.168.1.1"],
    "domain_name": "local",
    "lease_time": 86400,
    "enabled": true
  }'
```

Add a static reservation:

```bash
curl -X POST https://aifw.local/api/v1/dhcp/v4/reservations \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "mac_address": "aa:bb:cc:dd:ee:ff",
    "ip_address": "192.168.1.50",
    "hostname": "nas",
    "subnet_id": "<subnet-uuid>"
  }'
```

Apply the change (writes config + restarts rDHCP):

```bash
curl -X POST https://aifw.local/api/v1/dhcp/v4/apply \
  -H "Authorization: Bearer $TOKEN"
```

## CLI

```bash
aifw dhcp status
aifw dhcp subnets
aifw dhcp subnet-add --network 192.168.1.0/24 --pool-start 192.168.1.100 \
                    --pool-end 192.168.1.200 --gateway 192.168.1.1 \
                    --dns 192.168.1.1 --domain local --lease-time 86400
aifw dhcp reservation-add --mac aa:bb:cc:dd:ee:ff --ip 192.168.1.50 --hostname nas
aifw dhcp leases
aifw dhcp apply
aifw dhcp restart
```

## API endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/dhcp/status` | Service running state, subnet/reservation counts, pool stats |
| `POST` | `/api/v1/dhcp/start` `/stop` `/restart` | Service control |
| `GET` `PUT` | `/api/v1/dhcp/v4/config` | Global DHCPv4 config |
| `GET` `POST` | `/api/v1/dhcp/v4/subnets` | List or create subnets |
| `PUT` `DELETE` | `/api/v1/dhcp/v4/subnets/{id}` | Update or delete a subnet |
| `GET` `POST` | `/api/v1/dhcp/v4/reservations` | List or create static reservations |
| `PUT` `DELETE` | `/api/v1/dhcp/v4/reservations/{id}` | Update or delete a reservation |
| `GET` | `/api/v1/dhcp/v4/leases` | Active leases (live from rDHCP) |
| `DELETE` | `/api/v1/dhcp/v4/leases/{ip}` | Release one lease |
| `POST` | `/api/v1/dhcp/v4/apply` | Render TOML and restart rDHCP |
| `GET` `PUT` | `/api/v1/dhcp/ddns` | DDNS configuration |
| `GET` `PUT` | `/api/v1/dhcp/ha/config` | HA mode and peer settings |
| `GET` | `/api/v1/dhcp/ha/status` | HA role + peer state |
| `GET` | `/api/v1/dhcp/pool-stats` | Per-subnet utilisation |
| `GET` | `/api/v1/dhcp/metrics` | Prometheus-style metrics |
| `GET` | `/api/v1/dhcp/logs` | Recent rDHCP logs |

## Relay metrics

DHCP → Pool Metrics shows a **DHCP relay** card when rDHCP reports relay activity: relayed packets received (`giaddr ≠ 0`), accepted, and dropped by reason, both lifetime totals and the change since the last refresh. Counters are global (rDHCP does not label them per subnet). Drop reasons:

| reason | meaning |
|---|---|
| `accept_relayed_disabled` | relayed packets arrived while *Accept relayed requests* is off |
| `bad_giaddr` | `giaddr` is a bogon or matches no configured subnet — a misconfigured or spoofing relay |
| `untrusted_relay` | relay source IP is not in the subnet's trusted-relays list |
| `rate_limit` | the per-relay-source limiter engaged |

New `untrusted_relay` / `bad_giaddr` drops since the previous refresh highlight the card and the row in red — those are the abuse signals; the other two are configuration.

## HA failover

The DHCP `HaConfig` carries three modes: `standalone`, `active-active`, and `raft`.

- **`standalone`** &mdash; single node, no replication.
- **`active-active`** &mdash; classic ISC-style failover. Both peers serve leases; `scope_split` divides the pool, `mclt` is the maximum client lead time, and `partner_down_delay` is how long to wait before claiming the partner's range. Mutual TLS via `tls_cert` / `tls_key` / `tls_ca` is supported.
- **`raft`** &mdash; clustered consensus across `peers`. Use when you need more than two replicas or strong-consistency lease state.

The AiFw firewall HA layer (CARP + pfsync) and rDHCP HA are independent &mdash; rDHCP handles its own lease replication. AiFw's `dhcp_link` flag in cluster config keeps the peer list in sync between the two layers. See the [HA cluster doc]({{ '/ha/' | relative_url }}) for the full survival matrix.

## DDNS

When DDNS is enabled, every lease grant or release triggers a TSIG-signed update against the configured DNS server. Forward zone gets an A record (`<hostname>.<dhcp_domain>`); reverse zones get the matching PTR. The TSIG key and algorithm are stored in `DdnsConfig`. With both rDNS host registration and DDNS enabled, leases land in DNS automatically and survive a DHCP server restart.

## Configuration

| Field | Default | Notes |
|---|---|---|
| `lease_time` | unset (subnet) | Seconds; rDHCP applies a built-in default if unset |
| `subnet_type` | `address` | Set to `prefix-delegation` for IPv6 prefix-delegation |
| `enabled` (per subnet) | `true` | Disable to retain config without serving |
| HA `mode` | `standalone` | Set to `active-active` or `raft` for failover |
| `register_dhcp` (rDNS) | `true` | Companion DNS service auto-publishes lease hostnames |

## See also

- [Features overview &rarr;]({{ '/features/' | relative_url }})
- [Comparison with pfSense / OPNsense &rarr;]({{ '/compare/' | relative_url }})
- [DNS &rarr;]({{ '/docs/dns/' | relative_url }})
- [HA cluster &rarr;]({{ '/ha/' | relative_url }})
- Source: [`aifw-api/src/dhcp.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-api/src/dhcp.rs)

</article>
</div>
