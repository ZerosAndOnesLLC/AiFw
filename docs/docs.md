---
layout: default
title: AiFw Documentation
description: Configuration and administration guides for AiFw — WireGuard, IDS/IPS, NAT, DHCP, and more.
permalink: /docs/
---

<div class="content-page">
<article markdown="1">

# Documentation

## Getting started

- [Installation guide]({{ '/install' | relative_url }}) — ISO, USB, and update procedures
- [First-boot wizard](#first-boot) — initial configuration walkthrough
- [Web UI overview](#web-ui) — dashboard, navigation, and key pages

## Configuration guides

Detailed guides are being migrated from the repo. For now, refer to the [source `CLAUDE.md`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/CLAUDE.md) and [architecture notes](https://github.com/ZerosAndOnesLLC/AiFw) in the repository.

### Firewall

- Rules, aliases, scheduling
- Traffic shaping queues
- Rate limiting

### VPN

- WireGuard tunnels and peers
- IPsec SAs and policies
- Client config generation

### IDS / IPS

- Operating modes (IDS vs IPS vs disabled)
- Managing rulesets
- Writing Sigma rules
- Alert classification and suppression

### NAT

- Port forwarding
- 1:1 NAT
- NAT64/46 translation

### DHCP

- Subnet configuration
- Static reservations
- HA failover setup
- DDNS integration

### DNS

- Resolver configuration
- Host and domain overrides
- Access control lists

### High availability

- CARP virtual IPs
- pfsync state synchronization
- Cluster node management

### Reverse proxy

- TrafficCop configuration
- HTTP/TCP/UDP routing
- TLS certificates and ACME

### Authentication

- Local users and TOTP 2FA
- OAuth provider setup
- API keys
- RBAC roles and permissions

## API reference

- REST API — 300+ endpoints at `http://<ip>:8080/api/v1/`
- WebSocket — real-time metrics at `/api/v1/ws`
- Authentication — JWT, API key, OAuth flows

See the [endpoint inventory](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/CLAUDE.md#api-endpoints) in the repo.

## CLI reference

```bash
aifw rules          # rule management
aifw nat            # NAT rules
aifw vpn            # VPN tunnels and peers
aifw dhcp           # DHCP configuration
aifw dns            # DNS resolver
aifw update         # firmware and OS updates
aifw config         # backup, restore, versioning
aifw users          # user management
aifw status         # system status
aifw reload         # apply pending changes
```

## Architecture

AiFw is composed of several Rust crates:

```
aifw-common      shared types (rules, NAT, VPN, IDS)
aifw-pf          pf backend abstraction (ioctl on FreeBSD, mock elsewhere)
aifw-core        engines (rules, NAT, VPN, HA, shaping, audit, DB)
aifw-ids         IDS/IPS engine with Sigma + YARA support
aifw-conntrack   connection tracking
aifw-plugins     WASM + native plugin system
aifw-ai          AI/ML threat detection
aifw-metrics     metrics collection
aifw-api         Axum REST API + WebSocket
aifw-daemon      background worker
aifw-cli         command-line tool
aifw-tui         terminal UI
aifw-setup       first-boot wizard and installer
```

Everything is async via tokio. The web UI is a separate Next.js project that compiles to static HTML/CSS/JS — no Node.js runtime on the appliance.

## Companion services

AiFw depends on four companion services built from separate repos:

- **TrafficCop** — reverse proxy (HTTP/TCP/UDP)
- **rDHCP** — DHCP server with HA
- **rDNS** — DNS resolver
- **rTIME** — NTP/PTP time sync

These ship with the ISO and are managed by AiFw's service layer.

## Contributing

AiFw is MIT-licensed. Pull requests welcome at the [GitHub repo](https://github.com/ZerosAndOnesLLC/AiFw). Issues and discussions are open too.

</article>
</div>
