---
layout: default
title: Features — AiFw Firewall
description: Complete feature list for AiFw — stateful firewall, WireGuard, IPsec, IDS/IPS with Sigma and YARA rules, AI threat detection, multi-WAN with FIB isolation, NAT, DNS, DHCP, HA clustering, OPNsense importer, and more.
permalink: /features/
date: 2026-05-09
breadcrumb:
  - { title: "Features", url: "/features/" }
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "SoftwareApplication",
  "name": "AiFw",
  "description": "AiFw is an open-source AI-powered firewall for FreeBSD with WireGuard, IPsec, IDS/IPS, multi-WAN, HA clustering, and a modern web dashboard.",
  "url": "https://aifw.zerosandones.us/features/",
  "applicationCategory": "SecurityApplication",
  "operatingSystem": "FreeBSD",
  "offers": {"@type": "Offer", "price": "0", "priceCurrency": "USD"},
  "featureList": [
    "Stateful packet filtering via FreeBSD pf",
    "WireGuard and IPsec VPN",
    "Suricata IDS/IPS with Sigma and YARA rules",
    "Multi-WAN with FIB isolation, SLA-driven failover, leak detection",
    "HA clustering with CARP",
    "NAT including SNAT, DNAT, 1:1, NAT64, NAT46",
    "Geo-IP filtering",
    "DNS resolver and DHCP server",
    "OPNsense configuration importer",
    "REST API with 300+ routes and RBAC",
    "React-based web dashboard"
  ],
  "license": "https://opensource.org/licenses/MIT"
}
</script>

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

## Multi-WAN

Enterprise-grade multi-WAN built on FreeBSD FIBs and pf. Designed to match what Cisco IOS PBR + IP SLA and Juniper routing-instances + RPM offer, with a few features neither has.

- **FIB isolation** — each WAN lives in its own FreeBSD FIB, the same isolation primitive as Juniper routing-instances or Cisco VRFs.
- **Active health monitoring** — ICMP, TCP, HTTP, and DNS probes with hysteresis and MOS scoring on every probe kind.
- **Gateway groups** — failover, weighted load-balance, and MOS-weighted adaptive policies.
- **Policy routing** — match on 5-tuple + interface + DSCP + geo-IP. Steer to an instance, gateway, or group.
- **Blast-radius preview** — dry-run any config change to see which existing flows would be re-routed and whether management traffic would be stranded, before applying.
- **Per-flow visibility** — live pf state table joined to policy labels, with one-click force-migrate.
- **GitOps export/import** — `GET /api/v1/multiwan/config.yaml` returns the entire multi-WAN config; POST it back to apply.
- **Anomaly scoring** (optional) — SLA baseline deviation alerting when probes still pass but the latency profile shifted.

See the [multi-WAN setup guide]({{ '/multi-wan/' | relative_url }}) for FIB bootstrap, gateway monitoring, policy construction, and the pf rules emitted under `aifw-pbr`, `aifw-mwan-reply`, and `aifw-mwan-leak`.

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

Five behavioural detectors run alongside signature-based IDS, implemented in `aifw-ai/src/detectors/`:

1. **Port scan** — flags sources with >15 unique ports hit and >60% failed-connection ratio
2. **DDoS** — detects SYN floods and high connection rates (>50 conn/sec)
3. **Brute force** — concentrated auth attacks: 10+ connections across 1–5 ports with >70% failure rate
4. **C2 beacon** — low-variance periodic connections to single or few hosts
5. **DNS tunneling** — anomalous DNS traffic patterns consistent with tunneled data

Each detector produces a threat score (0.0–1.0 confidence) and severity classification. Auto-response actions include temporary IP blocks with configurable TTL, alert generation, and full audit trail of every decision.

## DNS

- Full recursive resolver (rDNS)
- Local host overrides (custom A/AAAA records)
- Domain overrides (custom zones)
- Access control lists
- DNSSEC validation
- Query logging
- Rebind protection, identity hiding

## DNS blocklists

- Source URL configuration with periodic auto-refresh
- Per-list hit counters and last-fetch metadata
- Allowlist override that beats blocklist rules
- Per-blocklist enable/disable, with no resolver restart required
- Compatible with common public blocklists (StevenBlack, OISD, etc.)

See the [DNS guide]({{ '/docs/dns/' | relative_url }}) for sources, refresh cadence, and allowlist examples.

## DHCP

- DHCPv4 server with multiple subnets
- Static reservations (MAC → IP)
- Active lease tracking and release
- Pool statistics
- **HA failover** with peer state sync
- **DDNS** — automatic DHCP-to-DNS updates
- Configurable lease time, gateway, DNS per subnet

## Reverse proxy &amp; ACME

Built-in TrafficCop reverse proxy — no HAProxy/Nginx package install:

- **HTTP routers** with path and host matching
- **TCP and UDP routers** with SNI matching
- **Services** with multiple backends, health checks, and load-balancing strategies
- **Middleware chains** — auth, rate limit, header rewrites, redirect, IP allowlist
- **TLS termination** with per-router certificate selection
- **ACME / Let's Encrypt automation** — issue, renew, and push certs to the local TLS store, a filesystem location, or a webhook destination

See the [reverse proxy guide]({{ '/docs/reverse-proxy/' | relative_url }}) for setup, ACME providers, middleware reference, and example configs.

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
- **OAuth / SSO** — first-class auth method, not a plugin. Built-in providers for Google, GitHub, generic OIDC. See the [auth &amp; RBAC guide]({{ '/docs/auth/' | relative_url }}) for setup, the full 37-permission RBAC matrix, and TOTP / API-key flows.
- **API keys** for programmatic access
- **JWT token sessions** with refresh tokens

## Authorization — RBAC

37 granular permissions including:

`dashboard:view` · `rules:read/write` · `nat:read/write` · `vpn:read/write` · `geoip:read/write` · `ids:read/write` · `dns:read/write` · `dhcp:read/write` · `aliases:read/write` · `interfaces:read/write` · `connections:view` · `logs:view` · `users:read/write` · `settings:read/write` · `plugins:read/write` · `updates:read/install` · `backup:read/write` · `system:reboot` · `proxy:read/write`

Built-in roles: **admin**, **operator**, **viewer**. Custom roles supported.

## Backup &amp; migration

- **JSON backup / restore** — entire config in one file, atomically replayable
- **S3 backup destination** — configurable bucket and prefix; rotation policy
- **OPNsense XML import** — recently rewritten end-to-end. Parse the XML, preview a diff of what'll change, apply atomically with rollback on failure
- **Versioned config history** — every change is snapshotted; diff and selective restore from the UI
- **Commit confirm** — every apply auto-reverts on timeout unless explicitly confirmed; default 300-second window

See the [backup &amp; migration guide]({{ '/docs/backup/' | relative_url }}) for the full migration workflow from OPNsense, S3 setup, and rollback procedures.

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

## Time service

- **NTP and PTP** via the rTIME companion service
- Stratum, drift, and peer health visible in the UI
- Per-peer enable/disable with key-authenticated peers supported
- Required for HA — both nodes must run synchronized time for CARP advertisement timing

## TLS inspection

- **JA3 / JA3S fingerprinting** of inbound and outbound flows
- **SNI filtering** — block by hostname before TLS handshake completes
- **Certificate validation** — chain trust, validity window, expected SANs
- **TLS version enforcement** — min/max version policy, cipher suite policy

## Updates

- **Self-update** via the web UI, CLI, or console
- Firmware update check against GitHub releases
- Download + checksum verification + install + restart
- **One-click rollback** to previous version
- OS and package updates via `pkg`/`freebsd-update`

## Interfaces

- **Web UI** — Next.js / React with static export (no Node.js on appliance)
- **REST API** — 300+ endpoints, Axum-based, WebSocket for live data. See the [API reference]({{ '/docs/api/' | relative_url }}).
- **CLI** — `aifw` with 17 subcommand groups. See the [CLI reference]({{ '/docs/cli/' | relative_url }}).
- **TUI** — interactive terminal UI for headless operation

## See also

- [How AiFw compares to pfSense / OPNsense →]({{ '/compare/' | relative_url }})
- [Install guide →]({{ '/install/' | relative_url }})
- [Documentation hub →]({{ '/docs/' | relative_url }})
- [FAQ →]({{ '/faq/' | relative_url }})
- [GitHub repository →](https://github.com/ZerosAndOnesLLC/AiFw)

</article>
</div>
