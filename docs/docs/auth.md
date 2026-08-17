---
layout: default
title: "Auth & RBAC — AiFw users, OAuth, TOTP, API keys"
description: "Configure local users, TOTP 2FA, OAuth/SSO providers (Google, GitHub, OIDC), API keys, and the 37-permission RBAC matrix on AiFw."
permalink: /docs/auth/
date: 2026-05-09
breadcrumb:
  - { title: "Docs", url: "/docs/" }
  - { title: "Auth & RBAC", url: "/docs/auth/" }
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "Auth & RBAC — AiFw users, OAuth, TOTP, API keys",
  "description": "Configure local users, TOTP 2FA, OAuth/SSO providers (Google, GitHub, OIDC), API keys, and the 37-permission RBAC matrix on AiFw.",
  "author": { "@type": "Organization", "name": "ZerosAndOnesLLC" },
  "datePublished": "2026-05-09",
  "dateModified": "2026-05-09",
  "articleSection": "Security"
}
</script>

<div class="content-page">
<article markdown="1">

# Auth &amp; RBAC

Three credential types reach the API &mdash; **JWT bearer tokens**, **API keys**, and short-lived **WebSocket tickets**. Three built-in roles &mdash; **admin**, **operator**, and **viewer** &mdash; cover most deployments, and custom roles with arbitrary subsets of the 37 granular permissions are supported. Local accounts use bcrypt; OAuth / OIDC providers federate the rest.

## Local users

Local users live in SQLite with bcrypt-hashed passwords. Create them via the UI (**Users &rarr; Add user**) or the API:

```bash
curl -X POST https://aifw.local/api/v1/auth/users \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "correct horse battery staple",
    "email": "alice@example.com",
    "role": "operator"
  }'
```

Login returns a JWT plus a refresh token:

```bash
curl -X POST https://aifw.local/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "..."}'
```

## TOTP 2FA

Each user can enrol a TOTP authenticator (Google Authenticator, Authy, 1Password, Bitwarden, &hellip;).

1. `POST /api/v1/auth/totp/setup` &mdash; returns the otpauth URI and QR-code data.
2. User scans, enters the 6-digit code into `POST /api/v1/auth/totp/verify`.
3. Recovery codes are issued in the same response &mdash; store them somewhere offline.

When 2FA is enabled, login becomes a two-step flow:

```bash
# 1) Username + password — returns a TOTP challenge token
curl -X POST https://aifw.local/api/v1/auth/login \
  -d '{"username": "alice", "password": "..."}'

# 2) Submit the 6-digit code to complete login
curl -X POST https://aifw.local/api/v1/auth/totp/login \
  -d '{"challenge": "<token>", "code": "123456"}'
```

Disable from `POST /api/v1/auth/totp/disable` (requires a fresh password challenge).

## OAuth / SSO

Three provider types are built in:

| Provider | `provider_type` | Notes |
|---|---|---|
| Google | `google` | Pre-configured auth + token URLs |
| GitHub | `github` | Pre-configured auth + token URLs |
| Generic OIDC | `oidc` | Supply your own auth / token / userinfo URLs (Okta, Auth0, Keycloak, Azure AD, &hellip;) |

Add a provider:

```bash
curl -X POST https://aifw.local/api/v1/auth/oauth/providers \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Google Workspace",
    "provider_type": "google",
    "client_id": "...apps.googleusercontent.com",
    "client_secret": "...",
    "scopes": "openid email profile",
    "enabled": true
  }'
```

Redirect URI to register with the provider:

```
https://aifw.local/api/v1/auth/oauth/{provider}/callback
```

Login flow uses `/api/v1/auth/oauth/{provider}/authorize` &rarr; provider consent &rarr; callback &rarr; AiFw mints a JWT for the matched (or auto-provisioned) local user.

## API keys

API keys carry an explicit permission set independent of any user role. Use them for scripts, CI, monitoring, and integrations.

```bash
curl -X POST https://aifw.local/api/v1/auth/api-keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "metrics scraper",
    "permissions": ["dashboard:view", "connections:view"],
    "expires_at": "2027-01-01T00:00:00Z"
  }'
```

Authenticate by sending the key as a bearer-style header:

```
Authorization: ApiKey <key>
```

Rotate by creating a new key and revoking the old one. Keys are listed by name + creation date; the secret is shown exactly once on creation.

## WebSocket auth

Browsers can&rsquo;t set custom headers on `WebSocket` or `EventSource` connections, so AiFw issues short-lived single-use tickets bound to the authenticated user:

```bash
# Issue a ticket — requires a normal Bearer JWT
curl -X POST https://aifw.local/api/v1/auth/ws-ticket \
  -H "Authorization: Bearer $TOKEN"
# => { "ticket": "<opaque hex>" }
```

```javascript
// Open the socket within 30 seconds
const ws = new WebSocket(`wss://aifw.local/ws?ticket=${ticket}`);
```

Tickets are 256 bits of entropy, single-use, and expire in **30 seconds**. They live only in process memory &mdash; on restart everything reconnects anyway. See [`aifw-api/src/auth/ws_ticket.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-api/src/auth/ws_ticket.rs).

## RBAC

### Built-in roles

- **admin** &mdash; every permission. Full read + write + system control.
- **operator** &mdash; everything except `users:write`, `settings:write`, `updates:install`, `system:reboot`, and `ha:manage`. Day-to-day rule / NAT / VPN editing without account or platform-level changes.
- **viewer** &mdash; read-only. All `*:read` and `*:view` permissions except `users:read`, `settings:read`, and `backup:read` (those leak too much).
- **system** &mdash; `ha:manage` only. Held by the locked `aifw-daemon` service account behind the daemon-loopback and inbound cluster-peer API keys; it cannot be assigned to people (the API refuses it and the UI hides it). Before this role existed the service account inherited `admin` from a column default, so a leaked daemon key could mint administrators.

Custom roles are arbitrary subsets of the permission set below. Create with `POST /api/v1/auth/roles`.

### Permission catalogue (37 permissions)

The canonical list lives in [`aifw-common/src/permission.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-common/src/permission.rs). Permissions are stored as a 64-bit bitmask in the JWT claims for cheap server-side checks.

**Dashboard &amp; observability**

| Permission | Description |
|---|---|
| `dashboard:view` | View the main dashboard widgets and overview |
| `connections:view` | View the live connection / state table |
| `logs:view` | View pf logs, audit logs, and system logs |

**Filtering &amp; NAT**

| Permission | Description |
|---|---|
| `rules:read` | List firewall rules |
| `rules:write` | Create, update, delete, reorder firewall rules |
| `nat:read` | List NAT rules (port-forward, redirect, outbound) |
| `nat:write` | Manage NAT rules |
| `aliases:read` | List aliases |
| `aliases:write` | Manage aliases (address / network / port bags) |

**VPN, Geo-IP, IDS**

| Permission | Description |
|---|---|
| `vpn:read` | List WireGuard tunnels, peers, IPsec SAs |
| `vpn:write` | Manage VPN configuration |
| `geoip:read` | List geo-IP rules and country bans |
| `geoip:write` | Manage geo-IP rules; refresh GeoLite2 data |
| `ids:read` | View IDS / IPS alerts, rules, suppressions |
| `ids:write` | Change IDS mode, manage rulesets and suppressions |

**Network services**

| Permission | Description |
|---|---|
| `dns:read` | View DNS resolver / forwarder configuration |
| `dns:write` | Manage DNS forwarders, blocklists, overrides |
| `dhcp:read` | View DHCP leases and scopes |
| `dhcp:write` | Manage DHCP scopes, static reservations, options |
| `interfaces:read` | View interface configuration and status |
| `interfaces:write` | Configure interfaces, IP addressing, VLANs |

**Multi-WAN &amp; reverse proxy**

| Permission | Description |
|---|---|
| `multiwan:read` | View multi-WAN instances, gateways, groups, policies |
| `multiwan:write` | Manage multi-WAN policy, SLA, leak detection |
| `proxy:read` | View reverse proxy routers, services, middlewares |
| `proxy:write` | Manage reverse proxy + ACME / TLS configuration |

**Identity &amp; settings**

| Permission | Description |
|---|---|
| `users:read` | List users, roles, and audit log |
| `users:write` | Create / update / delete users, roles, API keys |
| `settings:read` | Read system settings (TLS, time, OAuth, &hellip;) |
| `settings:write` | Modify system settings, OAuth providers, AI config |

**Plugins**

| Permission | Description |
|---|---|
| `plugins:read` | List installed plugins and their status |
| `plugins:write` | Install, enable, disable, remove plugins |

**Updates, backup, system**

| Permission | Description |
|---|---|
| `updates:read` | Check for and view available system updates |
| `updates:install` | Apply system updates / firmware |
| `backup:read` | Read configuration history and backups |
| `backup:write` | Create, restore, import / export configuration |
| `system:reboot` | Reboot or shutdown the appliance |
| `ha:manage` | Manage high-availability cluster (demote, snapshot, failover) |

## API endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/v1/auth/login` | Username + password login |
| `POST` | `/api/v1/auth/totp/login` | Submit TOTP code after `/login` |
| `POST` | `/api/v1/auth/refresh` | Exchange a refresh token for a new JWT |
| `POST` | `/api/v1/auth/logout` | Revoke the current session |
| `POST` | `/api/v1/auth/register` | Self-service registration (if enabled) |
| `GET` | `/api/v1/auth/me` | Current user identity, role, perms |
| `POST` | `/api/v1/auth/totp/setup` | Begin TOTP enrolment |
| `POST` | `/api/v1/auth/totp/verify` | Verify and activate TOTP |
| `POST` | `/api/v1/auth/totp/disable` | Disable TOTP |
| `POST` | `/api/v1/auth/ws-ticket` | Mint a 30-second WebSocket ticket |
| `GET` `/` `POST` | `/api/v1/auth/users` | List / create users |
| `GET` `/` `PUT` `/` `DELETE` | `/api/v1/auth/users/{id}` | Manage one user |
| `GET` | `/api/v1/auth/audit` | User audit log |
| `GET` `/` `POST` | `/api/v1/auth/roles` | List / create custom roles |
| `PUT` `/` `DELETE` | `/api/v1/auth/roles/{id}` | Update or remove a role |
| `GET` | `/api/v1/auth/permissions` | Enumerate every permission |
| `POST` | `/api/v1/auth/api-keys` | Create an API key |
| `GET` `/` `PUT` | `/api/v1/auth/settings` | Auth settings (lockout, refresh TTL, &hellip;) |
| `GET` `/` `POST` | `/api/v1/auth/oauth/providers` | List / create OAuth providers |
| `PUT` `/` `DELETE` | `/api/v1/auth/oauth/providers/{id}` | Manage one provider |
| `GET` | `/api/v1/auth/oauth/{provider}/authorize` | Begin OAuth login |
| `GET` | `/api/v1/auth/oauth/{provider}/callback` | OAuth provider callback |

## See also

- [API reference &rarr;]({{ '/docs/api/' | relative_url }})
- [IDS / IPS &rarr;]({{ '/docs/ids/' | relative_url }})
- [Backup &amp; migration &rarr;]({{ '/docs/backup/' | relative_url }})
- Source: [`aifw-api/src/auth/`](https://github.com/ZerosAndOnesLLC/AiFw/tree/main/aifw-api/src/auth)
- Source: [`aifw-common/src/permission.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-common/src/permission.rs)

</article>
</div>
