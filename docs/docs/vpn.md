---
layout: default
title: VPN — AiFw WireGuard and IPsec setup
description: Set up WireGuard tunnels with auto-keypair generation and per-peer config export, or strongSwan-powered IKEv2 site-to-site IPsec tunnels with PSK or certificate auth on AiFw.
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
  "description": "Set up WireGuard tunnels with auto-keypair generation and per-peer config export, or strongSwan-powered IKEv2 site-to-site IPsec tunnels with PSK or certificate auth on AiFw.",
  "author": { "@type": "Organization", "name": "ZerosAndOnesLLC" },
  "datePublished": "2026-05-09",
  "dateModified": "2026-05-09",
  "articleSection": "Networking"
}
</script>

<div class="content-page">
<article markdown="1">

# VPN

AiFw ships two working VPN stacks: **WireGuard** for client/road-warrior and site-to-site use, and **IKEv2 IPsec** (strongSwan-powered, tunnel mode, PSK or X.509 auth) for site-to-site interop with other vendors. Pass rules compile into the dedicated `aifw-vpn` anchor and everything is managed through the API or CLI &mdash; no hand-edited `wg-quick` files. OpenVPN is intentionally not shipped; see the [comparison page]({{ '/compare/' | relative_url }}) for the reasoning.

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

AiFw ships real **IKEv2 site-to-site IPsec** (tunnel mode) powered by [strongSwan](https://www.strongswan.org/): the engine renders swanctl configuration, charon negotiates IKE and installs kernel Security Associations/policies, and live tunnel state is always read back from charon — never from a database status column. Authentication is **pre-shared key** or **X.509 certificate** (from the built-in ACME store or pasted PEM). NAT-T (UDP 4500 encapsulation), rekeying, dead-peer detection, and unattended recovery after reboot are all handled by the daemon.

Deliberately **not** offered: IKEv1 (deprecated, RFC 9395), AH, and transport mode — modern ESP with AEAD ciphers covers those use cases, and AiFw only advertises what its functional test matrix proves. Road-warrior/mobile IKEv2 (EAP) is not supported yet; use WireGuard for client VPN.

Defaults: `aes256gcm16-prfsha256-ecp256` (IKE) / `aes256gcm16-ecp256` (ESP), 4h IKE / 1h child rekey, 30s DPD.

### Quickstart (PSK site-to-site)

In the Web UI, go to **VPN &rarr; IPsec Tunnels &rarr; Add IPsec Tunnel**: name, remote endpoint, the subnets on each side, and a pre-shared key (16+ characters). Or via the API:

```bash
curl -X POST https://aifw.local/api/v1/vpn/ipsec/tunnels \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "office-to-dc",
    "remote_addr": "198.51.100.1",
    "psk": "use-a-long-random-secret-here",
    "local_ts": ["10.0.0.0/24"],
    "remote_ts": ["10.1.0.0/24"]
  }'
```

With the default `start_action: "start"`, charon initiates as soon as the config loads. Check the negotiated state:

```bash
curl -H "Authorization: Bearer $TOKEN" https://aifw.local/api/v1/vpn/ipsec/tunnels/<id>/status
# → ike_state ESTABLISHED, child SA INSTALLED, bytes/rekey counters
```

The peer must mirror the config: same PSK, swapped local/remote endpoints and traffic selectors, IKEv2, matching proposals. Any RFC-compliant IKEv2 peer should interoperate; strongSwan↔strongSwan is what AiFw's release matrix tests.

### Certificate authentication

Set `auth_method: "cert"` with either `cert_source: "acme"` + `acme_cert_id` (a cert issued by the built-in [ACME client]({{ '/docs/acme/' | relative_url }})) or `cert_source: "manual"` with `local_cert_pem`/`local_key_pem` pasted. Add the CA that signed the *peer's* certificate as `ca_cert_pem`, and set `local_id`/`remote_id` to the certificate identities (e.g. `CN=fw1.example.com`). Private keys are written root-only into strongSwan's `private/` directory and are redacted in every API response.

### Behavior details

- Each enabled tunnel renders to `/usr/local/etc/swanctl/conf.d/aifw-<id>.conf` (root, 0600). The database is the source of truth; files are regenerated on every change and at service startup, so tunnels **re-establish unattended after reboot or restore-from-backup**.
- A failed apply rolls back to the previous working configuration — a bad tunnel can't take down good ones. charon's diagnostic is returned in the error response.
- Firewall openings are scoped per tunnel into the `aifw-vpn` anchor: IKE (UDP 500/4500) and ESP to/from the configured peer only, plus decrypted traffic on `enc0`.
- `start_action`: `start` (initiate + keep up via DPD restart), `trap` (negotiate on first matching packet), `none` (respond only / manual start).
- Legacy pre-data-plane "IPsec SA" records (from AiFw ≤ 5.104) are kept read-only and clearly flagged; they never carried traffic and can be deleted or recreated as tunnels.

### Troubleshooting

- **Status shows DOWN** — check the peer is reachable on UDP 500/4500 and PSK/identities match. `POST .../tunnels/<id>/start` returns charon's negotiation error verbatim (e.g. `AUTHENTICATION_FAILED` = wrong PSK/cert identity).
- **Established but no traffic** — verify the traffic selectors cover the actual source/destination addresses on both sides; in tunnel mode only packets matching `local_ts ↔ remote_ts` are protected.
- On the box: `sudo swanctl --list-sas` (negotiated state), `setkey -D` / `setkey -DP` (kernel SAD/SPD).

## CLI

```bash
aifw vpn wg-add --name wg0 --interface wg0 --port 51820 --address 10.0.0.1/24
aifw vpn wg-peer-add --tunnel <id> --name laptop --pubkey <key> --endpoint 1.2.3.4:51820
aifw vpn ipsec-add --name office --remote 198.51.100.1 --psk <secret> \
  --local-ts 10.0.0.0/24 --remote-ts 10.1.0.0/24   # PSK; use UI/API for cert auth
aifw vpn ipsec-status
aifw vpn ipsec-start <uuid>
aifw vpn ipsec-stop <uuid>
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
| `GET` | `/api/v1/vpn/ipsec/tunnels` | List IPsec tunnels (secrets redacted) |
| `POST` | `/api/v1/vpn/ipsec/tunnels` | Create a tunnel (applies + loads charon) |
| `GET`/`PUT`/`DELETE` | `/api/v1/vpn/ipsec/tunnels/{id}` | Get / update / delete a tunnel |
| `POST` | `/api/v1/vpn/ipsec/tunnels/{id}/start` | Initiate the tunnel now |
| `POST` | `/api/v1/vpn/ipsec/tunnels/{id}/stop` | Terminate the IKE SA |
| `GET` | `/api/v1/vpn/ipsec/tunnels/{id}/status` | Live negotiated state from charon |
| `GET` | `/api/v1/vpn/ipsec/status` | Live state of all tunnels |
| `GET` | `/api/v1/vpn/ipsec` | List legacy read-only SA records (`legacy: true`) |
| `DELETE` | `/api/v1/vpn/ipsec/{id}` | Delete a legacy record |

## Configuration

| Field | Default | Notes |
|---|---|---|
| Anchor name | `aifw-vpn` | All WG/IPsec pass rules live here |
| `ike_proposal` (IPsec) | `aes256gcm16-prfsha256-ecp256` | swanctl proposal string, validated against a curated allowlist |
| `esp_proposal` (IPsec) | `aes256gcm16-ecp256` | AEAD + PFS group |
| `ike_lifetime_secs` / `esp_lifetime_secs` | `14400` / `3600` | Rekey times |
| `dpd_delay_secs` (IPsec) | `30` | `0` disables dead-peer detection |
| `persistent_keepalive` (WG) | unset | Set on the peer (typically `25`) so the tunnel survives NAT timeouts and HA failovers |
| `split_routes` (WG) | unset | Comma-separated CIDRs; falls back to the masked tunnel network |

## See also

- [Features overview &rarr;]({{ '/features/' | relative_url }})
- [Comparison with pfSense / OPNsense &rarr;]({{ '/compare/' | relative_url }})
- [Firewall rules &rarr;]({{ '/docs/firewall/' | relative_url }})
- [HA cluster &rarr;]({{ '/ha/' | relative_url }})
- Source: [`aifw-core/src/ipsec.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-core/src/ipsec.rs)
- Source: [`aifw-core/src/vpn.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-core/src/vpn.rs)
- Source: [`aifw-common/src/vpn.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-common/src/vpn.rs)

</article>
</div>
