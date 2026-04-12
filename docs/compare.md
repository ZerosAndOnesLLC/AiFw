---
layout: default
title: AiFw vs pfSense vs OPNsense — Feature Comparison
description: Honest head-to-head comparison of AiFw, OPNsense, and pfSense. WireGuard, IDS/IPS, NAT, VPN, HA, and more — see what each firewall actually supports.
permalink: /compare/
---

<div class="content-page">
<article markdown="1">

# AiFw vs OPNsense vs pfSense

A fair, honest comparison. Where a competitor is stronger, we say so. This matrix is generated from reading the code — AiFw features are verified against the repo, OPNsense and pfSense from their official docs.

<div class="compare-wrapper" markdown="0">
<table class="compare">
<thead>
<tr><th>Feature</th><th>AiFw</th><th>OPNsense</th><th>pfSense</th></tr>
</thead>
<tbody>
<tr class="section-row"><td colspan="4">Firewall & filtering</td></tr>
<tr><td>Stateful packet filtering</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>Rule scheduling</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>Aliases (IP/port groups)</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>IPv6 support</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>VLAN support</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>Static routing</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>Multi-WAN / failover / LB</td><td class="partial">planned</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>Captive portal</td><td class="no">—</td><td class="yes">✓</td><td class="yes">✓</td></tr>

<tr class="section-row"><td colspan="4">NAT</td></tr>
<tr><td>SNAT (outbound)</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>DNAT / port forwarding</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>1:1 NAT (binat)</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>NAT64</td><td class="yes">✓</td><td class="partial">plugin</td><td class="yes">✓</td></tr>
<tr><td>NAT46</td><td class="yes">✓</td><td class="no">—</td><td class="no">—</td></tr>

<tr class="section-row"><td colspan="4">VPN</td></tr>
<tr><td>WireGuard</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>IPsec</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>OpenVPN</td><td class="no">—</td><td class="yes">✓</td><td class="yes">✓</td></tr>

<tr class="section-row"><td colspan="4">IDS / IPS</td></tr>
<tr><td>Suricata rules</td><td class="yes">✓</td><td class="yes">✓</td><td class="partial">pkg</td></tr>
<tr><td>Snort rules</td><td class="no">—</td><td class="no">—</td><td class="yes">✓</td></tr>
<tr><td>Sigma rules</td><td class="yes">✓</td><td class="no">—</td><td class="no">—</td></tr>
<tr><td>YARA rules</td><td class="yes">✓</td><td class="no">—</td><td class="no">—</td></tr>
<tr><td>AI/ML threat detection</td><td class="yes">✓</td><td class="no">—</td><td class="no">—</td></tr>

<tr class="section-row"><td colspan="4">DNS</td></tr>
<tr><td>DNS resolver</td><td class="yes">rDNS</td><td class="yes">Unbound</td><td class="yes">Unbound</td></tr>
<tr><td>Host/domain overrides</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>DNSSEC</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>Dynamic DNS client (WAN)</td><td class="no">—</td><td class="partial">plugin</td><td class="yes">✓</td></tr>

<tr class="section-row"><td colspan="4">DHCP</td></tr>
<tr><td>DHCPv4 server</td><td class="yes">rDHCP</td><td class="yes">Kea/ISC</td><td class="yes">Kea/ISC</td></tr>
<tr><td>Reservations</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>HA failover</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>DDNS</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>

<tr class="section-row"><td colspan="4">Traffic shaping</td></tr>
<tr><td>CoDel</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>HFSC</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>PRIQ</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>CBQ</td><td class="no">—</td><td class="yes">✓</td><td class="yes">✓</td></tr>

<tr class="section-row"><td colspan="4">High availability</td></tr>
<tr><td>CARP (virtual IPs)</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>pfsync (state sync)</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>Config sync</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>

<tr class="section-row"><td colspan="4">Reverse proxy</td></tr>
<tr><td>Built-in proxy</td><td class="yes">TrafficCop</td><td class="no">—</td><td class="no">—</td></tr>
<tr><td>HAProxy</td><td class="no">—</td><td class="partial">plugin</td><td class="partial">pkg</td></tr>

<tr class="section-row"><td colspan="4">Authentication</td></tr>
<tr><td>Local users</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>TOTP 2FA</td><td class="yes">✓</td><td class="yes">✓</td><td class="partial">RADIUS</td></tr>
<tr><td>LDAP</td><td class="no">—</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>RADIUS</td><td class="no">—</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>OAuth / SSO</td><td class="yes">✓</td><td class="no">—</td><td class="no">—</td></tr>
<tr><td>API keys</td><td class="yes">✓</td><td class="yes">✓</td><td class="partial">community</td></tr>
<tr><td>RBAC (granular perms)</td><td class="yes">34 perms</td><td class="yes">ACL</td><td class="partial">user/group</td></tr>

<tr class="section-row"><td colspan="4">Plugins & extensibility</td></tr>
<tr><td>Package/plugin system</td><td class="partial">beta</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>WASM plugins</td><td class="partial">planned</td><td class="no">—</td><td class="no">—</td></tr>

<tr class="section-row"><td colspan="4">Architecture</td></tr>
<tr><td>Web UI technology</td><td class="yes">React/Next.js</td><td class="partial">PHP</td><td class="partial">PHP</td></tr>
<tr><td>REST API</td><td class="yes">Rust/Axum</td><td class="yes">✓</td><td class="partial">community</td></tr>
<tr><td>CLI tool</td><td class="yes">✓</td><td class="partial">limited</td><td class="partial">limited</td></tr>
<tr><td>TUI (terminal UI)</td><td class="yes">✓</td><td class="no">—</td><td class="no">—</td></tr>
<tr><td>WebSocket live dashboard</td><td class="yes">✓</td><td class="no">—</td><td class="no">—</td></tr>

<tr class="section-row"><td colspan="4">Config management</td></tr>
<tr><td>Backup / restore</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>Versioning + diff</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
<tr><td>Commit confirm (auto-rollback)</td><td class="yes">✓</td><td class="no">—</td><td class="no">—</td></tr>
<tr><td>OPNsense config import</td><td class="yes">✓</td><td class="no">n/a</td><td class="no">—</td></tr>

<tr class="section-row"><td colspan="4">Certificate Authority</td></tr>
<tr><td>Built-in CA</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td></tr>
</tbody>
</table>
</div>

## Where AiFw wins

- **AI/ML threat detection** — 5 built-in behavioural detectors (port scan, DDoS, brute force, C2 beacon, DNS tunneling) with auto-response and TTL blocks. Implemented in `aifw-ai/src/detectors/`.
- **Sigma + YARA rule support** — modern rule formats neither OPNsense nor pfSense support. Full parsers in `aifw-ids/src/rules/`.
- **NAT46** — IPv4→IPv6 translation. Nobody else has this out of the box.
- **OAuth / SSO** — first-class auth method, not a plugin.
- **Commit confirm** — auto-rollback if you lock yourself out. Default 300-second timeout, cancellable via oneshot channel. Both competitors have this as a years-open feature request.
- **Modern React/Next.js UI** — static export, no Node.js runtime on the appliance. Not PHP.
- **WebSocket live dashboard** — per-second metrics push, not poll-every-30s.
- **257-endpoint REST API** — Axum-based, generated from structured route config.
- **Rust single-binary services** — the API process measures under 15 MB private RSS, not a PHP-FPM pool.

## Where AiFw is behind

Honesty matters. Things you'll miss if you switch:

- **No OpenVPN** — both competitors have it. If you need OpenVPN specifically, don't switch (yet).
- **No LDAP / RADIUS** — AiFw uses OAuth/SSO instead. Big companies often need LDAP.
- **No Multi-WAN failover / load balancing** — planned but not shipped.
- **No captive portal** — if you run a café/hotspot, stay put.
- **No dynamic DNS client** for WAN IP updates (DDNS is only DHCP→DNS integration).
- **No CBQ** traffic shaping (has CoDel, HFSC, PRIQ).
- **No Snort rules** — Suricata-compatible only.
- **No HAProxy / Nginx** — built-in TrafficCop instead.
- **Young project** — OPNsense and pfSense have years of community knowledge, mature plugin ecosystems, and forum Q&A. AiFw is new.

## Should you switch?

**Stay on pfSense/OPNsense if:**
- You rely on OpenVPN, captive portal, multi-WAN load balancing, or LDAP
- You value a large community for Q&A
- Your stack is already stable and you're not hitting any pain points

**Consider AiFw if:**
- You want modern, AI-assisted threat detection out of the box
- You've been burned by PHP-era admin interfaces
- You need OAuth/SSO without writing custom FreeRADIUS configs
- You care about commit-confirm safety
- You run this professionally and want reproducible, auditable Rust code

**Try both** — AiFw has an OPNsense XML config importer, so you can move a full config over without re-doing it by hand.

## See also

- [Full feature list →]({{ '/features' | relative_url }})
- [Installation guide →]({{ '/install' | relative_url }})
- [Source code →](https://github.com/ZerosAndOnesLLC/AiFw)

</article>
</div>
