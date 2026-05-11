---
layout: default
title: VPN — AiFw WireGuard and IPsec setup
description: Set up WireGuard tunnels with auto-keypair generation and per-peer config export, or IPsec ESP/AH tunnels in tunnel or transport mode on AiFw.
permalink: /docs/vpn/
date: 2026-05-09
breadcrumb:
  - { title: "Docs", url: "/docs/" }
  - { title: "VPN", url: "/docs/vpn/" }
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "VPN — AiFw WireGuard and IPsec setup",
  "description": "Set up WireGuard tunnels with auto-keypair generation and per-peer config export, or IPsec ESP/AH tunnels in tunnel or transport mode on AiFw.",
  "author": { "@type": "Organization", "name": "ZerosAndOnesLLC" },
  "datePublished": "2026-05-09",
  "dateModified": "2026-05-09",
  "articleSection": "Networking"
}
</script>

<div class="content-page">
<article markdown="1">

# VPN

AiFw ships with two VPN protocols: **WireGuard** and **IPsec**. Both compile their pass rules into the dedicated `aifw-vpn` anchor and are managed entirely through the API or CLI &mdash; no hand-edited `wg-quick` or `ipsec.conf` files. OpenVPN is intentionally not shipped; see the [comparison page]({{ '/compare/' | relative_url }}) for the reasoning.

## WireGuard

A WireGuard tunnel in AiFw is a server-side instance with its own keypair, listen port, and tunnel address. Peers (clients) are added one at a time and AiFw can auto-generate the client keypair so you can download a ready-to-import `.conf` file.

### Quickstart

In the Web UI, go to **VPN &rarr; WireGuard &rarr; Add tunnel**. Pick an interface name (`wg0`, `wg1`, ...), a listen port, and a tunnel address with prefix (e.g. `10.0.0.1/24`). The keypair is generated automatically when the row is created. Then add peers and click **Download config** to get the client `.conf` file.

Create a tunnel:

```bash
curl -X POST https://aifw.local/api/v1/vpn/wg \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "office-vpn",
    "interface": "wg0",
    "listen_port": 51820,
    "address": "10.0.0.1/24",
    "dns": "10.0.0.1",
    "mtu": 1420
  }'
```

Add a peer with an auto-generated keypair (the server keeps the private key so it can build the client config):

```bash
curl -X POST "https://aifw.local/api/v1/vpn/wg/$TID/peers" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "laptop",
    "allowed_ips": ["10.0.0.2/32"],
    "persistent_keepalive": 25
  }'
```

Download the peer's ready-to-import config (server fills in `[Interface]` private key, `[Peer]` public key, `Endpoint`, `AllowedIPs`):

```bash
curl "https://aifw.local/api/v1/vpn/wg/$TID/peers/$PID/config?split_tunnel=false" \
  -H "Authorization: Bearer $TOKEN" -o laptop.conf
```

Bring the tunnel up:

```bash
curl -X POST "https://aifw.local/api/v1/vpn/wg/$TID/start" \
  -H "Authorization: Bearer $TOKEN"
```

### Split-tunnel routes

Set `split_routes` on the tunnel to a comma-separated list of CIDRs (e.g. `"172.29.0.0/16, 10.0.0.0/8"`) and request `split_tunnel=true` on the peer config download. Clients then only route those networks through the VPN. Without `split_routes`, AiFw masks the tunnel's own address to its network boundary and uses that.

### HA failover

WireGuard tunnels survive a CARP failover provided peers run with `PersistentKeepalive`. The wireguard-go process binds wildcard so the new master receives traffic on the CARP VIP automatically. See [HA cluster]({{ '/ha/' | relative_url }}) for the full survival matrix.

## IPsec

AiFw supports IPsec Security Associations with ESP, AH, or ESP+AH protocols, in either tunnel or transport mode. Each SA gets a random SPI and sensible algorithm defaults (AES-256-GCM + HMAC-SHA256). When the SA is in tunnel mode the engine also emits a `pass quick on enc0` rule so encapsulated traffic flows.

### Quickstart

In the Web UI, go to **VPN &rarr; IPsec &rarr; Add SA**. Provide endpoints, protocol, and mode.

```bash
curl -X POST https://aifw.local/api/v1/vpn/ipsec \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "office-to-dc",
    "src_addr": "203.0.113.1",
    "dst_addr": "198.51.100.1",
    "protocol": "esp",
    "mode": "tunnel"
  }'
```

The created SA emits these pass rules into the `aifw-vpn` anchor:

- `pass in/out quick proto esp from <peer> to <peer>` (or `ah`)
- `pass in/out quick proto udp ... port { 500 4500 }` for IKE
- `pass quick on enc0 ...` (tunnel mode only)

## CLI

```bash
aifw vpn wg-add --name wg0 --interface wg0 --port 51820 --address 10.0.0.1/24
aifw vpn wg-peer-add --tunnel <id> --name laptop --pubkey <key> --endpoint 1.2.3.4:51820
aifw vpn ipsec-add --name office --src 203.0.113.1 --dst 198.51.100.1
aifw vpn list
aifw vpn remove <uuid>
```

## API endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/vpn/wg` | List WireGuard tunnels |
| `POST` | `/api/v1/vpn/wg` | Create a tunnel (auto-generates keypair) |
| `PUT` | `/api/v1/vpn/wg/{id}` | Update a tunnel |
| `DELETE` | `/api/v1/vpn/wg/{id}` | Delete a tunnel |
| `POST` | `/api/v1/vpn/wg/{id}/start` | Bring tunnel up |
| `POST` | `/api/v1/vpn/wg/{id}/stop` | Bring tunnel down |
| `GET` | `/api/v1/vpn/wg/{id}/status` | Live tunnel status |
| `GET` | `/api/v1/vpn/wg/{id}/peers` | List peers |
| `POST` | `/api/v1/vpn/wg/{id}/peers` | Add a peer |
| `GET` | `/api/v1/vpn/wg/{id}/peers/next-ip` | Suggest the next free peer IP |
| `DELETE` | `/api/v1/vpn/wg/{tid}/peers/{pid}` | Delete a peer |
| `GET` | `/api/v1/vpn/wg/{tid}/peers/{pid}/config` | Download peer .conf file |
| `GET` | `/api/v1/vpn/ipsec` | List IPsec SAs |
| `POST` | `/api/v1/vpn/ipsec` | Create an SA |
| `DELETE` | `/api/v1/vpn/ipsec/{id}` | Delete an SA |

## Configuration

| Field | Default | Notes |
|---|---|---|
| Anchor name | `aifw-vpn` | All WG/IPsec pass rules live here |
| `enc_algo` (IPsec) | `aes-256-gcm` | Set per SA |
| `auth_algo` (IPsec) | `hmac-sha256` | Set per SA |
| `persistent_keepalive` (WG) | unset | Set on the peer (typically `25`) so the tunnel survives NAT timeouts and HA failovers |
| `split_routes` (WG) | unset | Comma-separated CIDRs; falls back to the masked tunnel network |

## See also

- [Features overview &rarr;]({{ '/features/' | relative_url }})
- [Comparison with pfSense / OPNsense &rarr;]({{ '/compare/' | relative_url }})
- [Firewall rules &rarr;]({{ '/docs/firewall/' | relative_url }})
- [HA cluster &rarr;]({{ '/ha/' | relative_url }})
- Source: [`aifw-core/src/vpn.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-core/src/vpn.rs)
- Source: [`aifw-common/src/vpn.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-common/src/vpn.rs)

</article>
</div>
