---
layout: default
title: "Reverse proxy & ACME — AiFw TrafficCop and Let's Encrypt"
description: "Run HTTP, TCP, and UDP reverse proxies on AiFw with TrafficCop. Configure routers, services, middlewares, TLS, and ACME / Let's Encrypt automation."
permalink: /docs/reverse-proxy/
date: 2026-05-09
breadcrumb:
  - { title: "Docs", url: "/docs/" }
  - { title: "Reverse proxy & ACME", url: "/docs/reverse-proxy/" }
---

<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "TechArticle",
  "headline": "Reverse proxy & ACME — AiFw TrafficCop and Let's Encrypt",
  "description": "Run HTTP, TCP, and UDP reverse proxies on AiFw with TrafficCop. Configure routers, services, middlewares, TLS, and ACME / Let's Encrypt automation.",
  "author": { "@type": "Organization", "name": "ZerosAndOnesLLC" },
  "datePublished": "2026-05-09",
  "dateModified": "2026-05-09",
  "articleSection": "Operations"
}
</script>

<div class="content-page">
<article markdown="1">

# Reverse proxy &amp; ACME

AiFw ships **TrafficCop** as the data plane and the AiFw API as the control plane. No `pkg install haproxy`, no separate Nginx config, no Caddy sidecar &mdash; routers, services, middlewares, TLS certs, and Let&rsquo;s Encrypt automation are all first-class objects in the same SQLite database that holds the firewall rules.

## Architecture

| Plane | Component | Responsibility |
|---|---|---|
| Control | `aifw-api` | REST API, SQLite storage, dynamic config emission, ACME orchestration |
| Data | `trafficcop` | The actual proxy &mdash; listens on entrypoints, terminates TLS, forwards requests |

The control plane writes routers / services / middlewares to SQLite, then emits a dynamic config (a JSON / YAML blob in TrafficCop&rsquo;s native shape) that the daemon reloads in place. TrafficCop is shipped as a companion service in [`freebsd/manifest.json`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/freebsd/manifest.json) and starts under the `aifw` user alongside the API.

## Entrypoints

An **entrypoint** is a listening socket. Bind addresses look like `:80`, `:443`, or `1.2.3.4:8443`.

```bash
curl -X POST https://aifw.local/api/v1/reverse-proxy/entrypoints \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "websecure",
    "address": ":443",
    "enabled": true,
    "config_json": "{}"
  }'
```

Routers reference entrypoints by name, so one router can listen on multiple ports / interfaces.

## HTTP routers

A router pairs a **rule** with an **entrypoint set**, a **service** to forward to, optional **middlewares**, and optional **TLS**.

```bash
curl -X POST https://aifw.local/api/v1/reverse-proxy/http/routers \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "blog",
    "rule": "Host(`blog.example.com`)",
    "service": "blog-backend",
    "entry_points": "[\"websecure\"]",
    "middlewares": "[\"redirect-https\", \"rate-limit\"]",
    "priority": 100,
    "tls_json": "{\"certResolver\": \"letsencrypt\"}",
    "enabled": true
  }'
```

Match expressions support `Host(...)`, `PathPrefix(...)`, `Path(...)`, `HeaderRegexp(...)`, `Method(...)`, and boolean combinations. Higher `priority` wins on overlap.

## TCP &amp; UDP routers

TCP routers can match on SNI for TLS-passthrough or TLS-terminating workloads:

```json
{ "rule": "HostSNI(`db.example.com`)", "service": "postgres-pool" }
```

UDP routers match on entrypoint only &mdash; no per-packet routing rules &mdash; and forward to UDP services (DNS-over-UDP backends, game servers, &hellip;).

## Services

A service is a backend pool. Default `service_type` is `loadBalancer`; the `config_json` payload carries the server list, scheme, sticky-session config, health checks, and per-server weight.

```json
{
  "name": "blog-backend",
  "service_type": "loadBalancer",
  "config_json": {
    "servers": [
      { "url": "http://10.0.0.10:8080" },
      { "url": "http://10.0.0.11:8080" }
    ],
    "passHostHeader": true,
    "healthCheck": { "path": "/healthz", "interval": "10s", "timeout": "3s" }
  }
}
```

Health checks pull failing backends out of rotation automatically. Sticky sessions use a hashed cookie on the client.

## Middlewares

Middlewares are chained per-router. The `middleware_type` discriminator selects the behaviour and the `config_json` carries its parameters.

| Type | What it does |
|---|---|
| `rateLimit` | Token-bucket rate limit per source IP |
| `inFlightReq` | Cap concurrent in-flight requests |
| `ipAllowList` | Allow only listed source CIDRs |
| `ipDenyList` | Deny listed source CIDRs |
| `basicAuth` | HTTP Basic auth against an embedded user list |
| `digestAuth` | HTTP Digest auth |
| `forwardAuth` | Delegate auth to an external HTTP endpoint |
| `jwt` | Validate JWT bearer tokens against a JWKS |
| `headers` | Add / remove / overwrite request &amp; response headers |
| `passTLSClientCert` | Forward client cert info to the backend |
| `contentType` | Force or override `Content-Type` |
| `compress` | gzip / brotli response compression |
| `redirectScheme` | Force HTTP &rarr; HTTPS |
| `redirectRegex` | Regex-based URL rewrite + redirect |
| `stripPrefix` | Remove a path prefix before forwarding |
| `stripPrefixRegex` | Regex variant of stripPrefix |
| `addPrefix` | Prepend a path prefix |
| `replacePath` | Replace the entire path |
| `replacePathRegex` | Regex path replacement |
| `retry` | Retry idempotent requests on backend error |
| `circuitBreaker` | Open the circuit when backend errors spike |
| `buffering` | Request / response body buffering with limits |
| `chain` | Compose multiple middlewares into one |
| `grpcWeb` | gRPC-Web protocol bridge |
| `errors` | Custom error pages from a separate service |

## TLS &amp; cert resolvers

TLS certs live under `/api/v1/reverse-proxy/tls/certs` &mdash; pasted PEM, ACME-issued, or pushed by an external automation. TLS options (`/tls/options`) cover min version, cipher suites, and client-cert requirements per router.

A **cert resolver** is a strategy that resolves a hostname to a cert at request time. The built-in `letsencrypt` resolver uses ACME (see below); manual resolvers point at a stored cert by name.

## ACME / Let&rsquo;s Encrypt

AiFw issues and renews certs against any RFC 8555 ACME server. Defaults are tuned for Let&rsquo;s Encrypt prod and staging.

Configure your account:

```bash
curl -X PUT https://aifw.local/api/v1/acme/account \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "directory_url": "https://acme-v02.api.letsencrypt.org/directory",
    "email": "ops@example.com"
  }'
```

Request a cert (DNS-01 via a configured DNS provider, or HTTP-01 via a routed entrypoint):

```bash
curl -X POST https://aifw.local/api/v1/acme/certs \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "domains": ["example.com", "*.example.com"],
    "challenge": "dns-01",
    "dns_provider_id": 1
  }'
```

Renewals run automatically; trigger one early with `POST /api/v1/acme/certs/{id}/renew`.

### Push targets

Issued certs can be pushed to one or more **export targets** so they reach the workloads that need them:

| Kind | What happens |
|---|---|
| `local-tls-store` | Drop into AiFw&rsquo;s `/usr/local/etc/aifw/tls/` and reload `aifw_api` |
| `file` | Write cert / key / chain to a file path with configurable owner + mode |
| `webhook` | `POST` cert + key as JSON to a URL with optional auth header |

Configure under `/api/v1/acme/certs/{cert_id}/targets`. See [`aifw-core/src/acme_export.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-core/src/acme_export.rs).

## API endpoints

### Reverse proxy

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/reverse-proxy/status` | Daemon status, entrypoint / router counts |
| `GET` `/` `PUT` | `/api/v1/reverse-proxy/config` | Global config (log level, access log, metrics) |
| `POST` | `/api/v1/reverse-proxy/validate` | Dry-run validation of a candidate config |
| `GET` | `/api/v1/reverse-proxy/logs` | Tail the proxy access / error logs |
| `GET` `/` `POST` | `/api/v1/reverse-proxy/entrypoints` | List / create entrypoints |
| `PUT` `/` `DELETE` | `/api/v1/reverse-proxy/entrypoints/{id}` | Manage one entrypoint |
| `GET` `/` `POST` | `/api/v1/reverse-proxy/http/routers` | HTTP routers |
| `PUT` `/` `DELETE` | `/api/v1/reverse-proxy/http/routers/{id}` | Manage one HTTP router |
| `GET` `/` `POST` | `/api/v1/reverse-proxy/http/services` | HTTP services |
| `PUT` `/` `DELETE` | `/api/v1/reverse-proxy/http/services/{id}` | Manage one HTTP service |
| `GET` `/` `POST` | `/api/v1/reverse-proxy/http/middlewares` | HTTP middlewares |
| `PUT` `/` `DELETE` | `/api/v1/reverse-proxy/http/middlewares/{id}` | Manage one middleware |
| `GET` `/` `POST` | `/api/v1/reverse-proxy/tcp/routers` | TCP routers |
| `PUT` `/` `DELETE` | `/api/v1/reverse-proxy/tcp/routers/{id}` | Manage one TCP router |
| `GET` `/` `POST` | `/api/v1/reverse-proxy/tcp/services` | TCP services |
| `PUT` `/` `DELETE` | `/api/v1/reverse-proxy/tcp/services/{id}` | Manage one TCP service |
| `GET` `/` `POST` | `/api/v1/reverse-proxy/udp/routers` | UDP routers |
| `GET` `/` `POST` | `/api/v1/reverse-proxy/udp/services` | UDP services |
| `GET` | `/api/v1/reverse-proxy/tls/certs` | List stored TLS certs |
| `GET` | `/api/v1/reverse-proxy/tls/options` | List TLS option profiles |
| `GET` | `/api/v1/reverse-proxy/cert-resolvers` | List cert resolvers (incl. ACME) |

### ACME

| Method | Endpoint | Description |
|---|---|---|
| `GET` `/` `PUT` | `/api/v1/acme/account` | ACME account (directory URL, email, key) |
| `GET` `/` `POST` | `/api/v1/acme/certs` | List / request certs |
| `GET` `/` `DELETE` | `/api/v1/acme/certs/{id}` | Inspect or remove a cert |
| `POST` | `/api/v1/acme/certs/{id}/renew` | Force renewal now |
| `POST` | `/api/v1/acme/certs/{id}/publish` | Re-run all export targets |
| `GET` | `/api/v1/acme/certs/{id}/cert.pem` | Download the public cert |
| `GET` | `/api/v1/acme/certs/{id}/key.pem` | Download the private key |
| `GET` `/` `POST` | `/api/v1/acme/dns-providers` | DNS-01 provider credentials |
| `PUT` `/` `DELETE` | `/api/v1/acme/dns-providers/{id}` | Manage one DNS provider |
| `POST` | `/api/v1/acme/dns-providers/{id}/test` | Test DNS provider credentials |
| `GET` `/` `POST` | `/api/v1/acme/certs/{cert_id}/targets` | Export targets for a cert |
| `DELETE` | `/api/v1/acme/export-targets/{id}` | Remove an export target |

## See also

- [Features overview &rarr;]({{ '/features/' | relative_url }})
- [Auth &amp; RBAC &rarr;]({{ '/docs/auth/' | relative_url }}) (the `proxy:read` / `proxy:write` perms gate these endpoints)
- Source: [`aifw-api/src/reverse_proxy.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-api/src/reverse_proxy.rs)
- Source: [`aifw-api/src/acme.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-api/src/acme.rs)
- Source: [`aifw-core/src/acme_export.rs`](https://github.com/ZerosAndOnesLLC/AiFw/blob/main/aifw-core/src/acme_export.rs)

</article>
</div>
