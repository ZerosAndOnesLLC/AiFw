---
layout: default
title: "REST API reference — AiFw"
description: "Complete REST API reference for AiFw — auth (JWT, API key, WebSocket ticket), 300+ endpoints grouped by subsystem (rules, NAT, VPN, IDS, multi-WAN, HA, DNS, DHCP, etc.)."
permalink: /docs/api/
date: 2026-05-09
breadcrumb:
  - { title: "Docs", url: "/docs/" }
  - { title: "REST API", url: "/docs/api/" }
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "REST API reference — AiFw",
  "description": "Complete REST API reference for AiFw — auth (JWT, API key, WebSocket ticket), 300+ endpoints grouped by subsystem (rules, NAT, VPN, IDS, multi-WAN, HA, DNS, DHCP, etc.).",
  "author": { "@type": "Organization", "name": "ZerosAndOnesLLC" },
  "datePublished": "2026-05-09",
  "dateModified": "2026-05-09",
  "articleSection": "Reference"
}
</script>

<div class="content-page">
<article markdown="1">

# REST API reference

AiFw exposes a single Axum-based HTTP API. Every endpoint lives under one base URL:

```
http://<aifw-ip>:8080/api/v1/
```

The web UI in `aifw-ui/` is a thin static client over the same API &mdash; anything you can do in the UI you can do over HTTP. Roughly 300+ endpoints are grouped below by subsystem. Source of truth: [`aifw-api/src/main.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-api/src/main.rs).

## Authentication

Three credential types reach the API. Pick one per request.

### JWT bearer (interactive sessions)

```bash
# 1) Log in
TOKEN=$(curl -s -X POST https://aifw.local/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"..."}' | jq -r .access_token)

# 2) Use the token
curl https://aifw.local/api/v1/rules \
  -H "Authorization: Bearer $TOKEN"
```

The login response also returns a refresh token. Exchange it at `POST /api/v1/auth/refresh` to mint a new JWT without re-entering a password. If TOTP is enabled the login flow becomes two-step &mdash; see [Auth & RBAC]({{ '/docs/auth/' | relative_url }}).

### API key (scripts, CI, monitoring)

Create a key with a scoped permission set:

```bash
curl -X POST https://aifw.local/api/v1/auth/api-keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"prom-scraper","permissions":["dashboard:view","connections:view"]}'
```

Use the returned secret with the `ApiKey` scheme:

```bash
curl https://aifw.local/api/v1/metrics \
  -H "Authorization: ApiKey $AIFW_KEY"
```

The plaintext key is shown exactly once. Rotate by creating a new key and revoking the old one.

### WebSocket ticket (browser sockets / EventSource)

Browsers can&rsquo;t set custom headers on `WebSocket` or `EventSource` connections, so AiFw issues short-lived single-use tickets bound to the calling identity:

```bash
TICKET=$(curl -s -X POST https://aifw.local/api/v1/auth/ws-ticket \
  -H "Authorization: Bearer $TOKEN" | jq -r .ticket)
```

```javascript
// Open the socket within 30 seconds
const ws = new WebSocket(`wss://aifw.local/api/v1/ws?ticket=${ticket}`);
```

Tickets are 256 bits of entropy, **single-use**, and expire in **30 seconds**. They live only in process memory.

## Errors

Most endpoints return raw HTTP status codes &mdash; no JSON envelope:

| Status | Meaning |
|---|---|
| `200` / `201` / `204` | Success |
| `400` | Validation error in the request body |
| `401` | Missing or invalid credentials |
| `403` | Authenticated but lacks the required permission |
| `404` | Resource ID not found |
| `409` | Conflict (duplicate name, invariant violation) |
| `429` | Rate limit / login lockout |
| `500` | Unhandled internal error (check `journalctl -u aifw-api`) |

A handful of endpoints (auth, AI, IDS) return `{ "error": "<message>" }` JSON bodies alongside the status code. Treat the status code as authoritative.

## Pagination

List endpoints with potentially large result sets accept `?limit=<N>&offset=<M>` query parameters. Notable examples:

- `GET /api/v1/connections?limit=100&offset=0` &mdash; live pf state table
- `GET /api/v1/ids/suppressions?limit=200&offset=0` &mdash; suppression rules
- `GET /api/v1/ids/alerts?limit=500` &mdash; alert log
- `GET /api/v1/logs?limit=1000` &mdash; pf / audit / system logs
- `GET /api/v1/auth/audit?limit=200` &mdash; auth audit trail

Sensible defaults are applied when omitted; check the relevant subsystem doc for the cap.

---

## Auth

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/auth/login` | Username + password login |
| `POST` | `/api/v1/auth/totp/login` | Submit TOTP code after `/login` |
| `POST` | `/api/v1/auth/totp/setup` | Begin TOTP enrolment |
| `POST` | `/api/v1/auth/totp/verify` | Verify and activate TOTP |
| `POST` | `/api/v1/auth/totp/disable` | Disable TOTP for the current user |
| `POST` | `/api/v1/auth/refresh` | Exchange refresh token for a new JWT |
| `POST` | `/api/v1/auth/logout` | Revoke the current session |
| `POST` | `/api/v1/auth/register` | Self-service registration (if enabled) |
| `GET` | `/api/v1/auth/me` | Current user identity, role, perms |
| `POST` | `/api/v1/auth/ws-ticket` | Mint a 30-second WebSocket ticket |
| `GET`,&nbsp;`POST` | `/api/v1/auth/users` | List / create users |
| `GET`,&nbsp;`PUT`,&nbsp;`DELETE` | `/api/v1/auth/users/{id}` | Manage one user |
| `GET` | `/api/v1/auth/audit` | User audit log |
| `GET`,&nbsp;`POST` | `/api/v1/auth/roles` | List / create custom roles |
| `PUT`,&nbsp;`DELETE` | `/api/v1/auth/roles/{id}` | Update or remove a role |
| `GET` | `/api/v1/auth/permissions` | Enumerate every permission |
| `POST` | `/api/v1/auth/api-keys` | Create an API key |
| `GET`,&nbsp;`PUT` | `/api/v1/auth/settings` | Auth settings (lockout, refresh TTL, &hellip;) |
| `GET`,&nbsp;`POST` | `/api/v1/auth/oauth/providers` | List / create OAuth providers |
| `PUT`,&nbsp;`DELETE` | `/api/v1/auth/oauth/providers/{id}` | Manage one provider |
| `GET` | `/api/v1/auth/oauth/{provider}/authorize` | Begin OAuth login |
| `GET` | `/api/v1/auth/oauth/{provider}/callback` | OAuth provider callback |

## Status, metrics, logs

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/status` | Daemon + pf health snapshot |
| `GET` | `/api/v1/about` | Build / version / feature flags |
| `GET` | `/api/v1/metrics` | Current metrics snapshot |
| `GET` | `/api/v1/metrics/list` | Available metric series names |
| `GET` | `/api/v1/metrics/series` | Time-series data for one or more metrics |
| `GET` | `/api/v1/connections` | Live pf state table (paginated) |
| `GET` | `/api/v1/blocked` | Recently blocked traffic |
| `GET` | `/api/v1/logs` | Combined pf / audit / system logs |
| `GET` | `/api/v1/pending` | Pending unsaved configuration |
| `GET` | `/api/v1/pending/stream` | SSE stream of pending changes |
| `POST` | `/api/v1/reload` | Reload rules from DB and apply to pf |

## Rules &amp; aliases

| Method | Endpoint | Description |
|---|---|---|
| `GET`,&nbsp;`POST` | `/api/v1/rules` | List / create firewall rules |
| `GET`,&nbsp;`PUT`,&nbsp;`DELETE` | `/api/v1/rules/{id}` | Manage one rule |
| `PUT` | `/api/v1/rules/reorder` | Reorder all rules by priority |
| `GET` | `/api/v1/rules/system` | Read-only system / floating rules |
| `GET`,&nbsp;`PUT` | `/api/v1/rules/block-logging` | Toggle global block logging |
| `GET`,&nbsp;`POST` | `/api/v1/schedules` | List / create rule schedules |
| `PUT`,&nbsp;`DELETE` | `/api/v1/schedules/{id}` | Manage one schedule |
| `GET`,&nbsp;`POST` | `/api/v1/aliases` | List / create aliases (host/network/port bags) |
| `GET`,&nbsp;`PUT`,&nbsp;`DELETE` | `/api/v1/aliases/{id}` | Manage one alias |

## NAT

| Method | Endpoint | Description |
|---|---|---|
| `GET`,&nbsp;`POST` | `/api/v1/nat` | List / create NAT rules |
| `GET`,&nbsp;`PUT`,&nbsp;`DELETE` | `/api/v1/nat/{id}` | Manage one NAT rule |
| `PUT` | `/api/v1/nat/reorder` | Reorder NAT rules |
| `GET` | `/api/v1/nat/pf-output` | Compiled pf NAT anchor for inspection |

## VPN

| Method | Endpoint | Description |
|---|---|---|
| `GET`,&nbsp;`POST` | `/api/v1/vpn/wg` | List / create WireGuard tunnels |
| `GET`,&nbsp;`PUT`,&nbsp;`DELETE` | `/api/v1/vpn/wg/{id}` | Manage one WG tunnel |
| `POST` | `/api/v1/vpn/wg/{id}/start` | Bring up the tunnel |
| `POST` | `/api/v1/vpn/wg/{id}/stop` | Take the tunnel down |
| `GET` | `/api/v1/vpn/wg/{id}/status` | Tunnel + peer handshake status |
| `GET`,&nbsp;`POST` | `/api/v1/vpn/wg/{id}/peers` | List / create peers |
| `GET` | `/api/v1/vpn/wg/{id}/peers/next-ip` | Suggest the next free peer IP |
| `GET`,&nbsp;`PUT`,&nbsp;`DELETE` | `/api/v1/vpn/wg/{tid}/peers/{pid}` | Manage one peer |
| `GET` | `/api/v1/vpn/wg/{tid}/peers/{pid}/config` | Render peer config (for QR / file) |
| `GET`,&nbsp;`POST` | `/api/v1/vpn/ipsec` | List / create IPsec SAs |
| `PUT`,&nbsp;`DELETE` | `/api/v1/vpn/ipsec/{id}` | Manage one IPsec SA |

## IDS / IPS

| Method | Endpoint | Description |
|---|---|---|
| `GET`,&nbsp;`PUT` | `/api/v1/ids/config` | IDS engine config (mode, interfaces) |
| `POST` | `/api/v1/ids/reload` | Reload Suricata rulesets |
| `GET` | `/api/v1/ids/stats` | Live engine + alert counters |
| `GET`,&nbsp;`DELETE` | `/api/v1/ids/alerts` | List (paginated) / purge alerts |
| `GET` | `/api/v1/ids/alerts/buffer-stats` | In-memory alert ring stats |
| `GET` | `/api/v1/ids/alerts/{id}` | One alert with full payload |
| `PUT` | `/api/v1/ids/alerts/{id}/acknowledge` | Acknowledge an alert |
| `PUT` | `/api/v1/ids/alerts/{id}/classify` | Classify (true / false positive) |
| `GET`,&nbsp;`POST` | `/api/v1/ids/rulesets` | List / install rulesets (ET Open, &hellip;) |
| `PUT`,&nbsp;`DELETE` | `/api/v1/ids/rulesets/{id}` | Enable / disable / remove a ruleset |
| `GET` | `/api/v1/ids/rules` | List individual SIDs (paginated) |
| `GET` | `/api/v1/ids/rules/search` | Full-text search across SIDs |
| `GET`,&nbsp;`PUT` | `/api/v1/ids/rules/{id}` | Read / override one SID |
| `GET`,&nbsp;`POST` | `/api/v1/ids/suppressions` | List / create suppression rules |
| `DELETE` | `/api/v1/ids/suppressions/{id}` | Remove a suppression |

## AI analysis

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/ai/analyze` | Run on-demand LLM threat analysis |
| `GET` | `/api/v1/ai/audit-log` | History of AI calls + verdicts |

## Multi-WAN

| Method | Endpoint | Description |
|---|---|---|
| `GET`,&nbsp;`POST` | `/api/v1/multiwan/instances` | Routing instances (FIBs) |
| `GET`,&nbsp;`PUT`,&nbsp;`DELETE` | `/api/v1/multiwan/instances/{id}` | Manage one instance |
| `GET`,&nbsp;`POST` | `/api/v1/multiwan/instances/{id}/members` | Interfaces in an instance |
| `DELETE` | `/api/v1/multiwan/instances/{id}/members/{iface}` | Remove an interface |
| `GET` | `/api/v1/multiwan/fibs` | Kernel FIB enumeration |
| `POST` | `/api/v1/multiwan/enable-fibs` | Enable additional FIBs in kernel |
| `GET`,&nbsp;`POST` | `/api/v1/multiwan/gateways` | Gateways with live health |
| `GET`,&nbsp;`PUT`,&nbsp;`DELETE` | `/api/v1/multiwan/gateways/{id}` | Manage one gateway |
| `GET` | `/api/v1/multiwan/gateways/{id}/sla` | SLA history for a gateway |
| `GET` | `/api/v1/multiwan/gateways/{id}/events` | Probe / state-change events |
| `POST` | `/api/v1/multiwan/gateways/{id}/probe-now` | Force an immediate probe |
| `GET`,&nbsp;`POST` | `/api/v1/multiwan/groups` | Gateway groups (failover / load-balance) |
| `GET`,&nbsp;`PUT`,&nbsp;`DELETE` | `/api/v1/multiwan/groups/{id}` | Manage one group |
| `GET` | `/api/v1/multiwan/groups/{id}/active` | Currently active group member |
| `GET`,&nbsp;`POST` | `/api/v1/multiwan/groups/{id}/members` | Group members |
| `DELETE` | `/api/v1/multiwan/groups/{id}/members/{gw}` | Remove a member |
| `GET`,&nbsp;`POST` | `/api/v1/multiwan/policies` | Policy-routing rules |
| `GET`,&nbsp;`PUT`,&nbsp;`DELETE` | `/api/v1/multiwan/policies/{id}` | Manage one policy |
| `PUT` | `/api/v1/multiwan/policies/reorder` | Reorder policies |
| `POST` | `/api/v1/multiwan/policies/{id}/duplicate` | Clone a policy |
| `PUT` | `/api/v1/multiwan/policies/{id}/toggle` | Enable / disable a policy |
| `GET`,&nbsp;`POST` | `/api/v1/multiwan/leaks` | Leak-prevention rules |
| `DELETE` | `/api/v1/multiwan/leaks/{id}` | Remove a leak rule |
| `POST` | `/api/v1/multiwan/leaks/seed-mgmt` | Seed management-escape leaks |
| `GET` | `/api/v1/multiwan/flows` | Live pf flows with FIB / interface |
| `POST` | `/api/v1/multiwan/flows/{label}/migrate` | Migrate active flows to a new gateway |
| `POST` | `/api/v1/multiwan/preview` | Dry-run policy compilation |
| `POST` | `/api/v1/multiwan/apply` | Compile + apply all multi-WAN anchors |
| `GET` | `/api/v1/multiwan/config.yaml` | Export full multi-WAN config as YAML |
| `POST` | `/api/v1/multiwan/apply-yaml` | Import multi-WAN config from YAML |

## DNS

| Method | Endpoint | Description |
|---|---|---|
| `GET`,&nbsp;`PUT` | `/api/v1/dns` | Top-level DNS forwarder config |
| `GET` | `/api/v1/dns/stats` | Resolver query / hit / NXDOMAIN counters |
| `GET` | `/api/v1/dns/stream` | SSE stream of live DNS metrics |
| `GET`,&nbsp;`POST` | `/api/v1/dns/blocklists` | List / add blocklist sources |
| `GET`,&nbsp;`PUT`,&nbsp;`DELETE` | `/api/v1/dns/blocklists/{id}` | Manage one source |
| `POST` | `/api/v1/dns/blocklists/{id}/refresh` | Refresh a single source now |
| `POST` | `/api/v1/dns/blocklists/refresh-all` | Refresh every enabled source |
| `GET`,&nbsp;`PUT` | `/api/v1/dns/blocklists/enabled` | Toggle blocklist enforcement |
| `GET`,&nbsp;`PUT` | `/api/v1/dns/blocklists/schedule` | Refresh schedule (cron-ish) |
| `GET`,&nbsp;`POST` | `/api/v1/dns/customblocks` | Manual block list |
| `DELETE` | `/api/v1/dns/customblocks/{id}` | Remove a custom block |
| `GET`,&nbsp;`POST` | `/api/v1/dns/whitelist` | Allow-list overrides |
| `DELETE` | `/api/v1/dns/whitelist/{id}` | Remove a whitelist entry |
| `GET`,&nbsp;`PUT` | `/api/v1/dns/resolver/config` | rDNS resolver configuration |
| `POST` | `/api/v1/dns/resolver/apply` | Write + reload resolver config |
| `GET` | `/api/v1/dns/resolver/status` | rDNS service status |
| `POST` | `/api/v1/dns/resolver/start` | Start rDNS |
| `POST` | `/api/v1/dns/resolver/stop` | Stop rDNS |
| `POST` | `/api/v1/dns/resolver/restart` | Restart rDNS |
| `GET` | `/api/v1/dns/resolver/logs` | Tail rDNS logs |
| `GET`,&nbsp;`POST` | `/api/v1/dns/resolver/hosts` | Local A / AAAA host records |
| `PUT`,&nbsp;`DELETE` | `/api/v1/dns/resolver/hosts/{id}` | Manage one host record |
| `GET`,&nbsp;`POST` | `/api/v1/dns/resolver/domains` | Conditional forwarding domains |
| `PUT`,&nbsp;`DELETE` | `/api/v1/dns/resolver/domains/{id}` | Manage one domain |
| `GET`,&nbsp;`POST` | `/api/v1/dns/resolver/acls` | Resolver ACLs (which clients may query) |
| `PUT`,&nbsp;`DELETE` | `/api/v1/dns/resolver/acls/{id}` | Manage one ACL |

## DHCP

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/dhcp/status` | rDHCP service status |
| `POST` | `/api/v1/dhcp/start` | Start rDHCP |
| `POST` | `/api/v1/dhcp/stop` | Stop rDHCP |
| `POST` | `/api/v1/dhcp/restart` | Restart rDHCP |
| `GET` | `/api/v1/dhcp/logs` | Tail rDHCP logs |
| `GET` | `/api/v1/dhcp/metrics` | Lease + pool counters |
| `GET` | `/api/v1/dhcp/pool-stats` | Per-pool utilisation |
| `GET`,&nbsp;`PUT` | `/api/v1/dhcp/v4/config` | DHCPv4 server config |
| `POST` | `/api/v1/dhcp/v4/apply` | Write config + restart rDHCP |
| `GET`,&nbsp;`POST` | `/api/v1/dhcp/v4/subnets` | Subnets / pools |
| `PUT`,&nbsp;`DELETE` | `/api/v1/dhcp/v4/subnets/{id}` | Manage one subnet |
| `GET`,&nbsp;`POST` | `/api/v1/dhcp/v4/reservations` | Static MAC&rarr;IP reservations |
| `PUT`,&nbsp;`DELETE` | `/api/v1/dhcp/v4/reservations/{id}` | Manage one reservation |
| `GET` | `/api/v1/dhcp/v4/leases` | Active leases |
| `DELETE` | `/api/v1/dhcp/v4/leases/{ip}` | Release a lease by IP |
| `GET`,&nbsp;`PUT` | `/api/v1/dhcp/ddns` | DHCP&rarr;DNS update config |
| `GET`,&nbsp;`PUT` | `/api/v1/dhcp/ha/config` | rDHCP HA pair configuration |
| `GET` | `/api/v1/dhcp/ha/status` | HA peer state |

## Geo-IP

| Method | Endpoint | Description |
|---|---|---|
| `GET`,&nbsp;`POST` | `/api/v1/geoip` | List / create geo-IP rules |
| `PUT`,&nbsp;`DELETE` | `/api/v1/geoip/{id}` | Manage one rule |
| `GET` | `/api/v1/geoip/lookup/{ip}` | Country / ASN lookup for one IP |

## Reverse proxy (TrafficCop control plane)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/reverse-proxy/status` | TrafficCop process status |
| `POST` | `/api/v1/reverse-proxy/start` | Start TrafficCop |
| `POST` | `/api/v1/reverse-proxy/stop` | Stop TrafficCop |
| `POST` | `/api/v1/reverse-proxy/restart` | Restart TrafficCop |
| `GET` | `/api/v1/reverse-proxy/logs` | Tail TrafficCop logs |
| `POST` | `/api/v1/reverse-proxy/validate` | Dry-run validate generated config |
| `POST` | `/api/v1/reverse-proxy/apply` | Generate, write, reload |
| `GET`,&nbsp;`PUT` | `/api/v1/reverse-proxy/config` | Global reverse-proxy config |
| `GET`,&nbsp;`POST` | `/api/v1/reverse-proxy/entrypoints` | Listening entrypoints |
| `PUT`,&nbsp;`DELETE` | `/api/v1/reverse-proxy/entrypoints/{id}` | Manage one entrypoint |
| `GET`,&nbsp;`POST` | `/api/v1/reverse-proxy/http/routers` | HTTP routers |
| `PUT`,&nbsp;`DELETE` | `/api/v1/reverse-proxy/http/routers/{id}` | Manage one HTTP router |
| `GET`,&nbsp;`POST` | `/api/v1/reverse-proxy/http/services` | HTTP backend services |
| `PUT`,&nbsp;`DELETE` | `/api/v1/reverse-proxy/http/services/{id}` | Manage one HTTP service |
| `GET`,&nbsp;`POST` | `/api/v1/reverse-proxy/http/middlewares` | HTTP middlewares (rate-limit, auth, &hellip;) |
| `PUT`,&nbsp;`DELETE` | `/api/v1/reverse-proxy/http/middlewares/{id}` | Manage one middleware |
| `GET`,&nbsp;`POST` | `/api/v1/reverse-proxy/tcp/routers` | Raw TCP routers |
| `PUT`,&nbsp;`DELETE` | `/api/v1/reverse-proxy/tcp/routers/{id}` | Manage one TCP router |
| `GET`,&nbsp;`POST` | `/api/v1/reverse-proxy/tcp/services` | TCP backend services |
| `PUT`,&nbsp;`DELETE` | `/api/v1/reverse-proxy/tcp/services/{id}` | Manage one TCP service |
| `GET`,&nbsp;`POST` | `/api/v1/reverse-proxy/udp/routers` | UDP routers |
| `PUT`,&nbsp;`DELETE` | `/api/v1/reverse-proxy/udp/routers/{id}` | Manage one UDP router |
| `GET`,&nbsp;`POST` | `/api/v1/reverse-proxy/udp/services` | UDP backend services |
| `PUT`,&nbsp;`DELETE` | `/api/v1/reverse-proxy/udp/services/{id}` | Manage one UDP service |
| `GET`,&nbsp;`POST` | `/api/v1/reverse-proxy/tls/certs` | TLS certificate pool |
| `PUT`,&nbsp;`DELETE` | `/api/v1/reverse-proxy/tls/certs/{id}` | Manage one cert |
| `GET`,&nbsp;`POST` | `/api/v1/reverse-proxy/tls/options` | TLS option profiles |
| `PUT`,&nbsp;`DELETE` | `/api/v1/reverse-proxy/tls/options/{id}` | Manage one TLS profile |
| `GET`,&nbsp;`POST` | `/api/v1/reverse-proxy/cert-resolvers` | ACME cert resolver wiring |
| `PUT`,&nbsp;`DELETE` | `/api/v1/reverse-proxy/cert-resolvers/{id}` | Manage one resolver |

## ACME &amp; CA

| Method | Endpoint | Description |
|---|---|---|
| `GET`,&nbsp;`POST` | `/api/v1/acme/account` | Read / register the ACME account |
| `GET`,&nbsp;`POST` | `/api/v1/acme/certs` | List / issue certificates |
| `GET`,&nbsp;`PUT`,&nbsp;`DELETE` | `/api/v1/acme/certs/{id}` | Manage one cert |
| `GET` | `/api/v1/acme/certs/{id}/cert.pem` | Download cert PEM |
| `GET` | `/api/v1/acme/certs/{id}/key.pem` | Download private key PEM |
| `POST` | `/api/v1/acme/certs/{id}/renew` | Force renewal |
| `POST` | `/api/v1/acme/certs/{id}/publish` | Push cert to configured targets |
| `GET`,&nbsp;`POST` | `/api/v1/acme/certs/{cert_id}/targets` | Per-cert export targets |
| `PUT`,&nbsp;`DELETE` | `/api/v1/acme/export-targets/{id}` | Manage one export target |
| `GET`,&nbsp;`POST` | `/api/v1/acme/dns-providers` | DNS-01 providers |
| `PUT`,&nbsp;`DELETE` | `/api/v1/acme/dns-providers/{id}` | Manage one DNS provider |
| `POST` | `/api/v1/acme/dns-providers/{id}/test` | Verify provider credentials |
| `GET`,&nbsp;`POST` | `/api/v1/ca` | View / generate the local CA |
| `GET` | `/api/v1/ca/cert.pem` | Download CA cert |
| `GET` | `/api/v1/ca/crl` | Download CRL |
| `GET`,&nbsp;`POST` | `/api/v1/ca/certs` | List / issue local certs |
| `GET`,&nbsp;`DELETE` | `/api/v1/ca/certs/{id}` | Manage one cert |
| `GET` | `/api/v1/ca/certs/{id}/cert.pem` | Download cert PEM |
| `GET` | `/api/v1/ca/certs/{id}/key.pem` | Download key PEM |
| `POST` | `/api/v1/ca/certs/{id}/revoke` | Revoke a cert |

## Plugins

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/plugins` | Installed plugins + status |
| `GET` | `/api/v1/plugins/discover` | Scan plugin directory for new bundles |
| `POST` | `/api/v1/plugins/toggle` | Enable / disable a plugin |
| `GET` | `/api/v1/plugins/{name}/logs` | Tail one plugin&rsquo;s logs |
| `GET`,&nbsp;`PUT` | `/api/v1/plugins/{name}/config` | Plugin-specific config |

## Backup &amp; configuration

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/config/history` | Versioned config history |
| `GET` | `/api/v1/config/version` | Current active version |
| `GET` | `/api/v1/config/diff` | Diff two versions |
| `GET` | `/api/v1/config/check` | Validate the active config |
| `GET` | `/api/v1/config/export` | Export config as JSON |
| `POST` | `/api/v1/config/import` | Import config from JSON |
| `POST` | `/api/v1/config/import-preview` | Dry-run import |
| `POST` | `/api/v1/config/save` | Snapshot the current config |
| `POST` | `/api/v1/config/restore` | Restore a previous version |
| `POST` | `/api/v1/config/restore-preview` | Preview a restore |
| `GET`,&nbsp;`PUT` | `/api/v1/config/retention` | Snapshot retention policy |
| `POST` | `/api/v1/config/commit-confirm` | Begin a commit-confirm window |
| `POST` | `/api/v1/config/commit-confirm/confirm` | Confirm before timeout |
| `GET` | `/api/v1/config/commit-confirm/status` | Time remaining + pending revert |
| `POST` | `/api/v1/config/import-opnsense` | Import an OPNsense `config.xml` |
| `POST` | `/api/v1/config/preview-opnsense` | Preview an OPNsense import |
| `GET`,&nbsp;`PUT` | `/api/v1/backup/s3/config` | S3 backup destination |
| `GET` | `/api/v1/backup/s3/list` | List backups in S3 |
| `POST` | `/api/v1/backup/s3/test` | Test S3 credentials / connectivity |
| `POST` | `/api/v1/backup/s3/import` | Restore from an S3 backup |

## Networking (interfaces, routes, VLANs, DDNS)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/interfaces` | List interfaces |
| `GET` | `/api/v1/interfaces/detailed` | Interfaces with per-iface stats |
| `GET`,&nbsp;`PUT` | `/api/v1/interfaces/config/{name}` | Interface configuration |
| `GET` | `/api/v1/interfaces/{name}/stats` | Live counters for one interface |
| `GET`,&nbsp;`PUT` | `/api/v1/interfaces/{name}/role` | Read / set the iface role (wan/lan/&hellip;) |
| `GET` | `/api/v1/interfaces/roles` | Enumerate role assignments |
| `GET`,&nbsp;`POST` | `/api/v1/vlans` | List / create VLANs |
| `PUT`,&nbsp;`DELETE` | `/api/v1/vlans/{id}` | Manage one VLAN |
| `GET`,&nbsp;`POST` | `/api/v1/routes` | Static routes |
| `PUT`,&nbsp;`DELETE` | `/api/v1/routes/{id}` | Manage one static route |
| `GET` | `/api/v1/routes/system` | Kernel routing table (`netstat -rn`) |
| `GET`,&nbsp;`POST` | `/api/v1/ddns/records` | Dynamic-DNS records |
| `PUT`,&nbsp;`DELETE` | `/api/v1/ddns/records/{id}` | Manage one DDNS record |
| `POST` | `/api/v1/ddns/records/{id}/update` | Force update a DDNS record |
| `GET`,&nbsp;`PUT` | `/api/v1/ddns/config` | Global DDNS config |

## System

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/system/info` | OS / hardware / uptime |
| `GET`,&nbsp;`PUT` | `/api/v1/system/general` | Hostname, domain, timezone |
| `GET`,&nbsp;`PUT` | `/api/v1/system/banner` | Login banner |
| `GET`,&nbsp;`PUT` | `/api/v1/system/ssh` | SSH server config |
| `GET`,&nbsp;`PUT` | `/api/v1/system/console` | Console / serial config |
| `GET` | `/api/v1/system/timezones` | Available timezones |

## Settings

| Method | Endpoint | Description |
|---|---|---|
| `GET`,&nbsp;`PUT` | `/api/v1/settings/tls` | API TLS cert / key paths |
| `GET`,&nbsp;`PUT` | `/api/v1/settings/valkey` | Valkey / metrics backend config |
| `GET`,&nbsp;`PUT` | `/api/v1/settings/pf-tuning` | pf state-table + timeout tuning |
| `GET`,&nbsp;`PUT` | `/api/v1/settings/ai` | AI provider + model config |
| `GET` | `/api/v1/settings/ai/models` | Discover available models |
| `POST` | `/api/v1/settings/ai/test` | Test AI provider credentials |
| `GET`,&nbsp;`PUT` | `/api/v1/settings/dashboard-history` | Dashboard widget retention |
| `GET`,&nbsp;`PUT` | `/api/v1/settings/ids-alerts` | IDS alert ring / retention |
| `GET`,&nbsp;`PUT` | `/api/v1/settings/syslog` | Remote syslog forwarding (server, transport, format, categories) |
| `POST` | `/api/v1/settings/syslog/test` | Send one test message (body = draft config, optional) |
| `GET` | `/api/v1/settings/syslog/status` | Delivery counters per AiFw process (API row live, daemon/IDS refreshed on their 60s poll) |
| `GET`,&nbsp;`PUT` | `/api/v1/settings/log-rotation` | Rotation policy for AiFw service logs (size cap, generations kept, compression) plus per-log sizes; `PUT` regenerates `/usr/local/etc/newsyslog.conf.d/aifw.conf` and runs one pass |
| `POST` | `/api/v1/settings/log-rotation/rotate` | Rotate now — `{"path": …}` force-rotates one managed log, empty body runs a normal pass |
| `GET`,&nbsp;`PUT` | `/api/v1/settings/{section}` | Generic key/value settings store |
| `GET`,&nbsp;`PUT` | `/api/v1/notify/smtp/config` | SMTP notification settings |
| `POST` | `/api/v1/notify/smtp/test` | Send a test email |

## Time service (rTIME)

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/time/status` | NTP / PTP service status |
| `GET`,&nbsp;`PUT` | `/api/v1/time/config` | rTIME configuration |
| `POST` | `/api/v1/time/apply` | Write config + restart |
| `POST` | `/api/v1/time/start` | Start rTIME |
| `POST` | `/api/v1/time/stop` | Stop rTIME |
| `POST` | `/api/v1/time/restart` | Restart rTIME |
| `GET` | `/api/v1/time/logs` | Tail rTIME logs |
| `GET`,&nbsp;`POST` | `/api/v1/time/sources` | Time sources (NTP / PTP peers) |
| `PUT`,&nbsp;`DELETE` | `/api/v1/time/sources/{id}` | Manage one source |

## Updates

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/updates/status` | Pending update + last-check info |
| `POST` | `/api/v1/updates/check` | Trigger an update check now |
| `GET` | `/api/v1/updates/history` | Past update runs |
| `POST` | `/api/v1/updates/install` | Install OS / package updates |
| `GET`,&nbsp;`PUT` | `/api/v1/updates/schedule` | Auto-update schedule |
| `POST` | `/api/v1/updates/reboot` | Reboot the appliance |
| `POST` | `/api/v1/updates/shutdown` | Shut the appliance down |
| `GET` | `/api/v1/updates/aifw/status` | AiFw firmware version + tarball state |
| `POST` | `/api/v1/updates/aifw/check` | Check GitHub for a new release |
| `POST` | `/api/v1/updates/aifw/install` | Download + install latest tarball |
| `POST` | `/api/v1/updates/aifw/install-local` | Install from a local tarball |
| `POST` | `/api/v1/updates/aifw/rollback` | Rollback to the previous version |
| `POST` | `/api/v1/updates/aifw/restart` | Restart services to activate an install |
| `POST` | `/api/v1/updates/aifw/reboot` | Full reboot after install |

## WebSocket &amp; SSE

A single WebSocket endpoint multiplexes live data:

```
GET /api/v1/ws?ticket=<ticket>
```

Connect with a [WebSocket ticket](#websocket-ticket-browser-sockets--eventsource). Once open, the server pushes a periodic JSON payload with the per-tick metrics broadcast to every connected client &mdash; status, traffic counters, top talkers, IDS alert deltas, and connection-table summaries. The throttling and broadcast model is described in [`aifw-api/src/ws.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-api/src/ws.rs).

Two endpoints stream Server-Sent Events for incremental UI updates:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/dns/stream` | Live DNS query / block events |
| `GET` | `/api/v1/pending/stream` | Pending unsaved-changes notifications |

## See also

- [CLI reference &rarr;]({{ '/docs/cli/' | relative_url }})
- [Auth &amp; RBAC &rarr;]({{ '/docs/auth/' | relative_url }})
- [Backup &amp; migration &rarr;]({{ '/docs/backup/' | relative_url }})
- Source: [`aifw-api/src/main.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-api/src/main.rs)

</article>
</div>
