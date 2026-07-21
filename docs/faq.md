---
layout: default
title: FAQ — AiFw firewall
description: Frequently asked questions about AiFw — is it a fork? does it require AI? OPNsense migration? hardware requirements? production-ready? OpenVPN? help and support?
permalink: /faq/
date: 2026-05-09
breadcrumb:
  - { title: "FAQ", url: "/faq/" }
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "FAQPage",
  "mainEntity": [
    {
      "@type": "Question",
      "name": "Is AiFw a fork of OPNsense or pfSense?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "No. AiFw is a ground-up rewrite in Rust. It runs on FreeBSD and uses pf for packet filtering, but shares no PHP or codebase with OPNsense or pfSense. The user-space services, web UI, REST API, and CLI are all original Rust and Next.js code."
      }
    },
    {
      "@type": "Question",
      "name": "Does AiFw require AI features to work?",
      "acceptedAnswer": {
        "@type": "Answer",
        "text": "No. AiFw is a complete firewall, router, DHCP server, DNS resolver, IDS/IPS, reverse proxy, and NTP server without any AI features enabled. The five behavioural detectors in aifw-ai (port scan, DDoS, brute force, C2 beacon, DNS tunneling) are opt-in, experimental, and disabled by default."
      }
    },
    { "@type": "Question", "name": "Can I import my existing OPNsense config?", "acceptedAnswer": { "@type": "Answer", "text": "Yes. AiFw ships an OPNsense XML importer that parses your config, previews a diff of what will change, and applies atomically with rollback on failure. The importer was rewritten end-to-end in 2026 (PRs #230 and #248–#252)." } },
    { "@type": "Question", "name": "Does AiFw support Multi-WAN failover and load balancing?", "acceptedAnswer": { "@type": "Answer", "text": "Yes. AiFw ships an enterprise-grade multi-WAN system with FIB isolation per WAN, gateway groups (failover, weighted, MOS-weighted adaptive), policy routing on 5-tuple plus DSCP plus geo-IP, and blast-radius preview. See the multi-WAN guide." } },
    { "@type": "Question", "name": "What hardware do I need to run AiFw?", "acceptedAnswer": { "@type": "Answer", "text": "Minimum: 1 amd64 core, 1 GB RAM, 4 GB disk, one NIC. Recommended: 2+ cores with AES-NI, 4 GB+ RAM, 16 GB SSD, 2+ NICs. IDS workloads benefit from more RAM. arm64 is planned but not yet supported." } },
    { "@type": "Question", "name": "Is AiFw production-ready?", "acceptedAnswer": { "@type": "Answer", "text": "AiFw is in active development (beta). The core firewall, NAT, WireGuard, IDS, DHCP, DNS, multi-WAN, and HA subsystems are implemented and run on real appliances, but automated FreeBSD live-traffic validation is still being built, and some advertised surfaces (NAT64/46, CoDel shaping, OAuth login) are in development without a working data plane yet. See the feature maturity matrix for the per-feature state before depending on it in production." } },
    { "@type": "Question", "name": "How do I migrate from pfSense to AiFw?", "acceptedAnswer": { "@type": "Answer", "text": "Direct pfSense XML import is not supported. The recommended path is to export your pfSense config to OPNsense first (community tooling exists), then use AiFw's OPNsense importer. Or rebuild config from scratch — the AiFw web UI is fast." } },
    { "@type": "Question", "name": "Does AiFw have a paid version or paid tier?", "acceptedAnswer": { "@type": "Answer", "text": "No. Every feature is MIT-licensed and free. There is no paid tier, no gated features, and no telemetry or cloud dependency." } },
    { "@type": "Question", "name": "Where can I get help?", "acceptedAnswer": { "@type": "Answer", "text": "GitHub Discussions and Issues at https://github.com/ZerosAndOnesLLC/AiFw. The repo also includes detailed docs in CLAUDE.md and the docs/ directory." } },
    { "@type": "Question", "name": "How does AiFw compare to OPNsense and pfSense?", "acceptedAnswer": { "@type": "Answer", "text": "AiFw wins on Sigma+YARA rule support, AI threat detection, commit-confirm auto-rollback, modern React UI, multi-WAN with FIB isolation, OPNsense config import, and built-in reverse proxy with ACME. AiFw lags on OpenVPN, mobile/IKEv1 IPsec clients, inline IPS, LDAP/RADIUS, captive portal, DDNS WAN client, and project age. See the full comparison page." } },
    { "@type": "Question", "name": "Does AiFw support OpenVPN?", "acceptedAnswer": { "@type": "Answer", "text": "Not currently. AiFw supports WireGuard and IKEv2 site-to-site IPsec today. If OpenVPN specifically is a hard requirement, stay on pfSense or OPNsense." } },
    { "@type": "Question", "name": "Can I run AiFw in a VM (Proxmox, ESXi, KVM, bhyve)?", "acceptedAnswer": { "@type": "Answer", "text": "Yes. AiFw runs anywhere FreeBSD runs — bare metal, KVM, Proxmox, VMware ESXi, bhyve. AWS and DigitalOcean FreeBSD images are untested but should work." } },
    { "@type": "Question", "name": "Does AiFw work with WireGuard mobile clients?", "acceptedAnswer": { "@type": "Answer", "text": "Yes. AiFw generates per-peer .conf files you can scan as a QR code from the WireGuard mobile app. Persistent keepalive can be set per peer. The handshake status is shown live in the web UI." } },
    { "@type": "Question", "name": "How does HA failover work?", "acceptedAnswer": { "@type": "Answer", "text": "AiFw runs an active-passive pair using CARP (virtual IP) and pfsync (state-table sync), designed so TCP sessions survive a master failover and WireGuard reconnects within a few seconds with PersistentKeepalive set. These are design targets: automated two-node failover validation is still being built, so validate failover behavior in your own environment before relying on it. See the HA cluster guide." } },
    { "@type": "Question", "name": "Is the source code auditable / where do I read it?", "acceptedAnswer": { "@type": "Answer", "text": "Yes. The full source is at https://github.com/ZerosAndOnesLLC/AiFw under the MIT license. The codebase is Rust workspace crates plus a Next.js web UI. CLAUDE.md in the repo root has an architectural overview." } }
  ]
}
</script>

<div class="content-page">
<article markdown="1">

# Frequently asked questions

## Is AiFw a fork of OPNsense or pfSense?

No. AiFw is a ground-up rewrite in Rust. It runs on FreeBSD and uses pf for packet filtering, but shares no PHP or codebase with OPNsense or pfSense. The user-space services, web UI, REST API, and CLI are all original Rust and Next.js code.

## Does AiFw require AI features to work?

No. AiFw is a complete firewall, router, DHCP server, DNS resolver, IDS/IPS, reverse proxy, and NTP server without any AI features enabled. The five behavioural detectors in `aifw-ai` (port scan, DDoS, brute force, C2 beacon, DNS tunneling) are **opt-in, experimental, and disabled by default**. They will be developed further in future releases.

## Can I import my existing OPNsense config?

Yes. AiFw ships an OPNsense XML importer that parses your config, previews a diff of what'll change, and applies atomically with rollback on failure. The importer was rewritten end-to-end in 2026 (PRs #230 and #248–#252). See the [backup &amp; migration guide]({{ '/docs/backup/#opnsense-import' | relative_url }}).

## Does AiFw support Multi-WAN failover and load balancing?

Yes. AiFw ships an enterprise-grade multi-WAN system with **FIB isolation per WAN**, gateway groups (failover, weighted, MOS-weighted adaptive), policy routing on 5-tuple + DSCP + geo-IP, and **blast-radius preview** before apply. See the [multi-WAN guide]({{ '/multi-wan/' | relative_url }}).

## What hardware do I need to run AiFw?

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 1 amd64 core | 2+ cores, AES-NI |
| RAM | 1 GB | 4 GB+ (more for IDS) |
| Disk | 4 GB | 16 GB SSD |
| NIC | 1 | 2+ (WAN + LAN) |

arm64 (Raspberry Pi, Ampere) is planned but not yet supported. AiFw runs anywhere FreeBSD runs — bare metal, KVM, Proxmox, VMware ESXi, bhyve.

## Is AiFw production-ready?

AiFw is in **active development (beta)**. The core firewall, NAT, WireGuard, IDS, DHCP, DNS, multi-WAN, and HA subsystems are implemented and run on real appliances today, but automated FreeBSD live-traffic validation is still being built out, and some surfaces — **NAT64/46, CoDel shaping, OAuth login** — are in development without a working data plane yet. **AI threat detection is opt-in / experimental** and the **plugin system is in beta**. Check the [feature maturity matrix]({{ '/maturity/' | relative_url }}) for the per-feature state before depending on a specific feature in production.

## How do I migrate from pfSense to AiFw?

Direct pfSense XML import is not supported. The recommended path is to export your pfSense config to OPNsense first (community tooling exists), then use AiFw's [OPNsense importer]({{ '/docs/backup/#opnsense-import' | relative_url }}). Alternatively, rebuild config from scratch — the AiFw web UI is fast.

## Does AiFw have a paid version or paid tier?

No. Every feature is MIT-licensed and free. There is no paid tier, no gated features, and no telemetry or cloud dependency.

## Where can I get help?

GitHub Discussions and Issues at [https://github.com/ZerosAndOnesLLC/AiFw](https://github.com/ZerosAndOnesLLC/AiFw). The repo also includes detailed docs in `CLAUDE.md` and the `docs/` directory.

## How does AiFw compare to OPNsense and pfSense?

**AiFw wins on:** Sigma + YARA rule support, AI threat detection, commit-confirm auto-rollback, modern React UI, multi-WAN with FIB isolation, OPNsense config import, built-in reverse proxy + ACME.

**AiFw lags on:** OpenVPN, mobile/IKEv1 IPsec clients, inline IPS, LDAP/RADIUS, captive portal, DDNS WAN client, project age.

See the [full comparison]({{ '/compare/' | relative_url }}).

## Does AiFw support OpenVPN?

Not currently. AiFw supports **WireGuard** and **IKEv2 site-to-site IPsec** today. If OpenVPN specifically is a hard requirement, stay on pfSense or OPNsense.

## Can I run AiFw in a VM?

Yes. AiFw runs anywhere FreeBSD runs — bare metal, KVM, Proxmox, VMware ESXi, bhyve. AWS and DigitalOcean FreeBSD images are untested but should work.

## Does AiFw work with WireGuard mobile clients?

Yes. AiFw generates per-peer `.conf` files you can scan as a QR code from the WireGuard mobile app. Persistent keepalive can be set per peer. Handshake status is shown live in the web UI.

## How does HA failover work?

AiFw runs an active-passive pair using **CARP** (virtual IP) and **pfsync** (state-table sync), designed so TCP sessions survive a master failover and WireGuard reconnects within a few seconds when peers set `PersistentKeepalive`. Treat the timing numbers as **design targets**: automated two-node failover validation is still being built ([#534](https://github.com/ZerosAndOnesLLC/AiFw/issues/534)), so validate failover in your own environment before relying on it. See the [HA cluster guide]({{ '/ha/' | relative_url }}).

## Is the source code auditable / where do I read it?

Yes. The full source is at [github.com/ZerosAndOnesLLC/AiFw](https://github.com/ZerosAndOnesLLC/AiFw) under the MIT license. The codebase is Rust workspace crates plus a Next.js web UI. `CLAUDE.md` in the repo root has an architectural overview.

</article>
</div>
