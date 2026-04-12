---
layout: default
title: Features — AiFw Firewall
description: Complete feature list for AiFw — stateful firewall, WireGuard, IPsec, IDS/IPS with Sigma and YARA rules, AI threat detection, NAT, DNS, DHCP, HA clustering, and more.
permalink: /features/
---

<div class="content-page">
<article markdown="1">

# Features

A complete inventory of what AiFw ships with today. All features are MIT-licensed and included in the free download — no paid tiers, no gated features.

## Firewall & filtering

- **Stateful packet filtering** via FreeBSD pf — scheduling, aliases, per-rule logging
- **IPv4 + IPv6** with both/dual-stack rule matching
- **Rule scheduling** — time-based activation (e.g., block social media during work hours)
- **Aliases** — named IP/port groups reusable across rules
- **VLAN support**, 802.1Q tagging
- **Static routing** with per-route metrics
- **Traffic shaping** — CoDel, HFSC, PRIQ queues
- **Rate limiting** with overload tables

## NAT

- **SNAT** (outbound source NAT)
- **DNAT / port forwarding** with reflection
- **Masquerading** (dynamic SNAT to interface address)
- **1:1 NAT** (binat)
- **NAT64** (IPv6 → IPv4)
- **NAT46** (IPv4 → IPv6) — unique to AiFw

## VPN

### WireGuard
- Tunnel creation with automatic keypair generation
- Peer management with allowed IPs, preshared keys, persistent keepalive
- Client config (`.conf`) generation per peer
- Next-available-IP assignment
- Split or full tunnel support
- Live tunnel status and transfer counters

### IPsec
- ESP, AH, ESP+AH protocols
- Tunnel and transport modes
- AES-256-GCM with HMAC-SHA256 by default
- Automatic SPI generation
- IKE (UDP 500, 4500) traffic rules

## IDS / IPS

- **Three modes** — Disabled, IDS (alert-only), IPS (inline drop)
- **Rule formats** — Suricata, Sigma, YARA
- **ET Open rule source integration** with auto-update
- **Alert management** — severity levels, acknowledgment, classification, analyst notes
- **Per-rule suppression** by source IP or destination IP
- **Flow tracking** with active flow counting
- **Hit count per rule** with last-hit timestamp
- **Payload inspection** with multi-pattern detection
- **Threshold-based detection**

## AI threat detection

Behavioral detectors running alongside signature-based IDS:

- Port scan detection
- DDoS attack detection
- Brute force detection
- Command & Control (C2) beacon detection
- DNS tunneling detection
- Anomaly detection
- Threat scoring with confidence 0.0–1.0

Auto-response actions include temporary IP blocks with configurable TTL, alert generation, and full audit trail of every decision.

## DNS

- Full recursive resolver (rDNS)
- Local host overrides (custom A/AAAA records)
- Domain overrides (custom zones)
- Access control lists
- DNSSEC validation
- Query logging
- Rebind protection, identity hiding

## DHCP

- DHCPv4 server with multiple subnets
- Static reservations (MAC → IP)
- Active lease tracking and release
- Pool statistics
- **HA failover** with peer state sync
- **DDNS** — automatic DHCP-to-DNS updates
- Configurable lease time, gateway, DNS per subnet

## Reverse proxy

Built-in TrafficCop reverse proxy:

- HTTP, TCP, and UDP routing
- Path and host-based HTTP routing
- Load balancing with health checks
- TLS termination
- Middleware chains
- ACME (Let's Encrypt) certificate resolvers

## High availability

- **CARP** virtual IPs with VHID, advskew, advbase tuning
- **pfsync** state table synchronization
- **Cluster node management** with health checks
- Config sync between nodes

## Geo-IP

- Country-based blocking/allowing (ISO 3166 alpha-2)
- Geo-IP lookup
- Per-rule enable/disable
- Multiple country rules with action override

## Certificate Authority

- Built-in CA generation
- Certificate issuance with subject, SANs, validity
- PEM export (cert + key)
- Certificate revocation with CRL
- PKCS#12 bundle generation

## Authentication

- **Local users** with bcrypt password hashing
- **TOTP 2FA** with recovery codes
- **OAuth / SSO** — unique to AiFw among FreeBSD firewalls
- **API keys** for programmatic access
- **JWT token sessions** with refresh tokens

## Authorization — RBAC

34 granular permissions including:

`dashboard:view` · `rules:read/write` · `nat:read/write` · `vpn:read/write` · `geoip:read/write` · `ids:read/write` · `dns:read/write` · `dhcp:read/write` · `aliases:read/write` · `interfaces:read/write` · `connections:view` · `logs:view` · `users:read/write` · `settings:read/write` · `plugins:read/write` · `updates:read/install` · `backup:read/write` · `system:reboot` · `proxy:read/write`

Built-in roles: **admin**, **operator**, **viewer**. Custom roles supported.

## Config management

- **Backup/restore** to/from JSON
- **Versioned config history** with diff and selective restore
- **Commit confirm** — every apply auto-reverts on timeout unless confirmed
- **OPNsense import** — migrate from existing OPNsense XML configs

## Plugin system <span class="badge-beta">Beta</span>

<div class="callout beta" markdown="0">
<span class="callout-icon">⚠️</span>
<div>
<strong>Experimental</strong>
The plugin system is under heavy development. APIs will change, built-in plugins haven't been production-tested, and WASM support is not yet implemented. Don't build production integrations yet.
</div>
</div>

- Native Rust plugins via the `Plugin` trait
- WASM plugin support (planned)
- Pre/post rule hooks with event-based triggers
- Plugin discovery from filesystem
- Per-plugin configuration and logs

See the full [plugin system documentation]({{ '/plugins' | relative_url }}) for details.

## Monitoring

- **WebSocket live dashboard** with 1m / 5m / 15m / 30m timeframes
- CPU, memory, disk I/O metrics
- Per-interface bandwidth and packet counters
- **NAT flow topology** — animated live traffic visualization per NIC
- **Memory breakdown** with process RSS, cache sizes, pf state count
- Blocked traffic tail from pflog
- Active connection tracking

## Updates

- **Self-update** via the web UI, CLI, or console
- Firmware update check against GitHub releases
- Download + checksum verification + install + restart
- **One-click rollback** to previous version
- OS and package updates via `pkg`/`freebsd-update`

## Interfaces

- **Web UI** — Next.js / React with static export (no Node.js on appliance)
- **REST API** — 300+ endpoints, Axum-based, WebSocket for live data
- **CLI** — `aifw` with 40+ subcommands
- **TUI** — interactive terminal UI for headless operation

## See also

- [How AiFw compares to pfSense / OPNsense →]({{ '/compare' | relative_url }})
- [Install guide →]({{ '/install' | relative_url }})
- [GitHub repository →](https://github.com/ZerosAndOnesLLC/AiFw)

</article>
</div>
