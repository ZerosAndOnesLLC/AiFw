---
layout: default
title: Feature Maturity — AiFw firewall
description: Per-feature maturity matrix for AiFw — what is implemented, what is validated on FreeBSD, and what is still in development. Updated with each release.
permalink: /maturity/
date: 2026-07-19
breadcrumb:
  - { title: "Maturity", url: "/maturity/" }
---

<div class="content-page">
<article markdown="1">

# Feature maturity

AiFw is in **active development (beta)**. This matrix is the honest, per-feature answer to "does it work?" — a feature is not called supported just because its API, schema, or UI exists. Columns:

- **Control plane** — config model, API, UI, persistence implemented.
- **Data plane** — the FreeBSD kernel/service actually enforces it.
- **Auto test** — automated FreeBSD functional test exercises live traffic (the CI epic tracking this is [#533](https://github.com/ZerosAndOnesLLC/AiFw/issues/533); most rows are ⏳ until it lands).
- **Validated** — performance / multi-node validation with published, reproducible results.

✓ done · ⏳ not yet · ✗ not implemented

<div class="compare-wrapper" markdown="0">
<table class="compare">
<thead>
<tr><th>Feature</th><th>Control plane</th><th>Data plane</th><th>Auto test</th><th>Validated</th><th>Status</th></tr>
</thead>
<tbody>
<tr><td>Stateful filtering (pf)</td><td class="yes">✓</td><td class="yes">✓</td><td class="partial">⏳</td><td class="partial">⏳</td><td>Beta — daily-driven on real appliances</td></tr>
<tr><td>Rule scheduling</td><td class="yes">✓</td><td class="yes">✓</td><td class="partial">⏳</td><td class="partial">⏳</td><td>Enforced since v5.99.7 (windows compiled into pf, minute-tick reload)</td></tr>
<tr><td>Rule policy routing (route-to)</td><td class="yes">✓</td><td class="yes">✓</td><td class="partial">⏳</td><td class="partial">⏳</td><td>Since v5.100.0</td></tr>
<tr><td>SNAT / DNAT / masquerade / 1:1</td><td class="yes">✓</td><td class="yes">✓</td><td class="partial">⏳</td><td class="partial">⏳</td><td>Beta</td></tr>
<tr><td>NAT64 / NAT46</td><td class="yes">✓</td><td class="no">✗</td><td class="no">✗</td><td class="no">✗</td><td><strong>In development</strong> — current rules do not perform cross-family translation ([#531](https://github.com/ZerosAndOnesLLC/AiFw/issues/531))</td></tr>
<tr><td>WireGuard</td><td class="yes">✓</td><td class="yes">✓</td><td class="partial">⏳</td><td class="partial">⏳</td><td>Beta</td></tr>
<tr><td>IPsec</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td><td class="yes">✓</td><td>IKEv2 site-to-site (tunnel mode, PSK/X.509, NAT-T) via strongSwan; verified two-endpoint on FreeBSD incl. rekey, DPD, and reboot recovery ([#530](https://github.com/ZerosAndOnesLLC/AiFw/issues/530)). No IKEv1/AH/transport/mobile-EAP.</td></tr>
<tr><td>OAuth / SSO login</td><td class="yes">✓</td><td class="no">✗</td><td class="no">✗</td><td class="no">✗</td><td><strong>In development</strong> — provider config + authorize flow exist; token exchange not implemented ([#170](https://github.com/ZerosAndOnesLLC/AiFw/issues/170))</td></tr>
<tr><td>IDS (Suricata/Sigma/YARA subsets)</td><td class="yes">✓</td><td class="yes">✓</td><td class="partial">⏳</td><td class="partial">⏳</td><td>Beta — rule-language subsets, not full engine parity</td></tr>
<tr><td>IPS — reactive source blocking</td><td class="yes">✓</td><td class="yes">✓</td><td class="partial">⏳</td><td class="partial">⏳</td><td>Blocks the source after detection; the triggering packet is not stopped</td></tr>
<tr><td>IPS — inline prevention</td><td class="no">✗</td><td class="no">✗</td><td class="no">✗</td><td class="no">✗</td><td><strong>Planned</strong> — divert/netmap roadmap</td></tr>
<tr><td>Traffic shaping — CoDel</td><td class="yes">✓</td><td class="no">✗</td><td class="no">✗</td><td class="no">✗</td><td><strong>In development</strong> — real dummynet FQ-CoDel backend tracked in [#532](https://github.com/ZerosAndOnesLLC/AiFw/issues/532)</td></tr>
<tr><td>Geo-IP filtering</td><td class="yes">✓</td><td class="yes">✓</td><td class="partial">⏳</td><td class="partial">⏳</td><td>Beta</td></tr>
<tr><td>Multi-WAN (FIB, gateways, policies)</td><td class="yes">✓</td><td class="yes">✓</td><td class="partial">⏳</td><td class="partial">⏳</td><td>Beta — latency thresholds + dampening enforced since v5.100.0; needs environment-specific validation</td></tr>
<tr><td>HA (CARP / pfsync / replication)</td><td class="yes">✓</td><td class="yes">✓</td><td class="no">✗</td><td class="no">✗</td><td>Beta — automated two-node failover validation tracked in [#534](https://github.com/ZerosAndOnesLLC/AiFw/issues/534); quantitative claims are design targets until then</td></tr>
<tr><td>Backup / restore / OPNsense import</td><td class="yes">✓</td><td class="yes">✓</td><td class="partial">⏳</td><td class="partial">⏳</td><td>Beta — snapshot + strict apply with automatic rollback (since v5.99.7); not a single DB+kernel transaction</td></tr>
<tr><td>DHCP / DNS / NTP (companions)</td><td class="yes">✓</td><td class="yes">✓</td><td class="partial">⏳</td><td class="partial">⏳</td><td>Beta — builds pinned to reviewed revisions since v5.99.8</td></tr>
<tr><td>Reverse proxy + ACME (TrafficCop)</td><td class="yes">✓</td><td class="yes">✓</td><td class="partial">⏳</td><td class="partial">⏳</td><td>Beta</td></tr>
<tr><td>AI/ML threat detection</td><td class="yes">✓</td><td class="partial">⏳</td><td class="no">✗</td><td class="no">✗</td><td>Experimental, opt-in, disabled by default</td></tr>
<tr><td>Plugin system</td><td class="yes">✓</td><td class="partial">⏳</td><td class="no">✗</td><td class="no">✗</td><td>Beta — WASM planned</td></tr>
</tbody>
</table>
</div>

Rows marked ⏳ under **Auto test** work on real appliances today but are verified by unit/integration tests against a mock pf backend, not yet by automated live-traffic tests on FreeBSD. Closing that gap is the project's current top engineering priority ([#533](https://github.com/ZerosAndOnesLLC/AiFw/issues/533)).

Documentation on this site is kept in sync with this matrix — if a page and this table disagree, [file an issue](https://github.com/ZerosAndOnesLLC/AiFw/issues).

</article>
</div>
