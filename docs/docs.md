---
layout: default
title: AiFw documentation hub
description: Documentation hub for AiFw — install guides, networking (firewall, NAT, VPN, multi-WAN, DNS, DHCP, geo-IP), security (IDS, AI threats, auth/RBAC, plugins), and operations (HA, backup, reverse proxy, API, CLI, FAQ).
permalink: /docs/
date: 2026-05-09
breadcrumb:
  - { title: "Docs", url: "/docs/" }
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "CollectionPage",
  "name": "AiFw documentation hub",
  "description": "Documentation hub for the AiFw firewall.",
  "url": "https://aifw.zerosandones.us/docs/"
}
</script>

<div class="content-page">
<article markdown="1">

# Documentation

Quickstarts, reference, and ops guides for AiFw. Each page covers one subsystem.

<div class="docs-hub" markdown="0">

  <div class="docs-col">
    <h3>Get started</h3>
    <ul>
      <li><a href="{{ '/install/' | relative_url }}">Install</a> — ISO, USB image, hypervisors</li>
      <li><a href="{{ '/install/#first-boot-setup-wizard' | relative_url }}">First boot</a> — wizard walkthrough</li>
      <li><a href="{{ '/features/' | relative_url }}">Features overview</a></li>
      <li><a href="{{ '/compare/' | relative_url }}">Compare to pfSense / OPNsense</a></li>
    </ul>
  </div>

  <div class="docs-col">
    <h3>Networking</h3>
    <ul>
      <li><a href="{{ '/docs/firewall/' | relative_url }}">Firewall rules</a></li>
      <li><a href="{{ '/docs/nat/' | relative_url }}">NAT</a></li>
      <li><a href="{{ '/multi-wan/' | relative_url }}">Multi-WAN</a></li>
      <li><a href="{{ '/docs/vpn/' | relative_url }}">VPN — WireGuard &amp; IPsec</a></li>
      <li><a href="{{ '/docs/dns/' | relative_url }}">DNS resolver &amp; blocklists</a></li>
      <li><a href="{{ '/docs/dhcp/' | relative_url }}">DHCP</a></li>
      <li><a href="{{ '/docs/geoip/' | relative_url }}">Geo-IP</a></li>
    </ul>
  </div>

  <div class="docs-col">
    <h3>Security</h3>
    <ul>
      <li><a href="{{ '/docs/ids/' | relative_url }}">IDS / IPS</a></li>
      <li><a href="{{ '/docs/ids/#ai-threat-detection' | relative_url }}">AI threat detection</a> <span class="badge-beta">opt-in</span></li>
      <li><a href="{{ '/docs/auth/' | relative_url }}">Auth &amp; RBAC</a></li>
      <li><a href="{{ '/plugins/' | relative_url }}">Plugins</a> <span class="badge-beta">beta</span></li>
    </ul>
  </div>

  <div class="docs-col">
    <h3>Operations</h3>
    <ul>
      <li><a href="{{ '/ha/' | relative_url }}">HA cluster</a></li>
      <li><a href="{{ '/docs/backup/' | relative_url }}">Backup &amp; migration</a></li>
      <li><a href="{{ '/docs/reverse-proxy/' | relative_url }}">Reverse proxy &amp; ACME</a></li>
      <li><a href="{{ '/docs/api/' | relative_url }}">API reference</a></li>
      <li><a href="{{ '/docs/cli/' | relative_url }}">CLI reference</a></li>
      <li><a href="{{ '/faq/' | relative_url }}">FAQ</a></li>
    </ul>
  </div>

</div>

## Contributing

AiFw is MIT-licensed. Pull requests welcome at the [GitHub repo](https://github.com/ZerosAndOnesLLC/AiFw). Issues and discussions are open too.

</article>
</div>
