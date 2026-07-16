# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

AiFw is an open-source (MIT) AI-powered firewall for FreeBSD, built in Rust on top of `pf`. All features are free. AI/ML threat detection is optional — it works as a traditional firewall without it.

## Build & Test Commands

```bash
# Rust
cargo check                    # type check (must pass with zero warnings before commit)
cargo build --release          # release binaries
cargo test                     # run all tests (~273 tests)
cargo test test_login          # run a single test by name
cargo test --package aifw-core # run tests for one crate

# Web UI
cd aifw-ui
npm ci                         # install dependencies
npm run build                  # static export to aifw-ui/out/
npm run dev                    # dev server on :3000
npm run lint                   # ESLint
```

Release binaries: `target/release/{aifw,aifw-daemon,aifw-api,aifw-tui,aifw-setup}`

## Version Management

All components share one version. Bump BOTH before every commit:

| File | Field |
|------|-------|
| `Cargo.toml` (root) | `[workspace.package] version` |
| `aifw-ui/package.json` | `"version"` |

Increment: major=breaking, minor=features, patch=fixes.

## Architecture

### Crate Dependency Flow

```
aifw-common (shared types: rules, NAT, VPN, TLS, geo-IP, HA, IDS, metrics)
    ↑
aifw-pf (PfBackend trait + mock/ioctl implementations)
    ↑
aifw-core (engines: rules, NAT, VPN, geo-IP, HA, shaping, audit, DB)
    ↑
aifw-conntrack / aifw-plugins / aifw-ai / aifw-ids / aifw-metrics
    ↑
aifw-api (Axum REST API) / aifw-daemon / aifw-cli / aifw-tui / aifw-setup
```

### PfBackend: Cross-Platform Development

The `PfBackend` trait (`aifw-pf/src/backend.rs`) abstracts pf operations. Backend selection is **compile-time** via `#[cfg(target_os)]`, not feature flags:

- **Linux/WSL** (`mock.rs`): `PfMock` — in-memory rule storage for development/testing
- **FreeBSD** (`ioctl.rs`): `PfIoctl` — real pfctl commands via sudo

`aifw_pf::create_backend()` returns the correct implementation automatically. All development and testing works on Linux/WSL with the mock backend.

### Engine Pattern

All core engines (`aifw-core/src/`) follow the same structure:

```rust
pub struct XEngine {
    pool: SqlitePool,           // database handle
    pf: Arc<dyn PfBackend>,     // shared pf backend
    anchor: String,             // pf anchor name (e.g., "aifw", "aifw-nat")
}
```

Engines: `RuleEngine` (engine.rs), `NatEngine` (nat.rs), `AliasEngine` (alias.rs), `GeoIpEngine` (geoip.rs), `VpnEngine` (vpn.rs), `ShapingEngine` (shaping.rs), `HaEngine` / `ClusterEngine` (ha.rs), plus the multiwan family (`InstanceEngine`, `GatewayEngine`, `GroupEngine`, `PolicyEngine`, `LeakEngine`, `PreflightEngine`, `SlaEngine`) under `multiwan/`.

Each engine has its own `migrate()` method that creates its SQLite tables. Migrations are **inline SQL** in Rust code (no separate migration files).

### Database Layer

Central type: `Database` struct in `aifw-core/src/db.rs` wrapping `SqlitePool`.

- `Database::new(path)` — file-based SQLite
- `Database::new_in_memory()` — for tests
- Production path: `/var/db/aifw/aifw.db`

### API Architecture

**Router** (`aifw-api/src/main.rs` → `build_router()`): Three-tier routing:

1. **Public routes** — `/auth/login`, `/auth/register`, OAuth callbacks (no auth)
2. **Admin routes** — user management, config import/export, updates (`require_admin` middleware)
3. **Protected routes** — everything else (`auth_middleware` only)

**Auth middleware** (`aifw-api/src/auth/mod.rs`) extracts identity from:
- `Authorization: Bearer <JWT>` header
- `Authorization: ApiKey <key>` header
- `?ticket=<id>` query param (WebSocket/SSE) — single-use, 30-second
  ticket issued by `POST /auth/ws-ticket` (see `auth::ws_ticket`).

**AppState** holds all engines as `Arc<T>`, shared `Arc<dyn PfBackend>`, and `SqlitePool`. Passed to handlers via Axum's `State` extractor.

### Test Patterns

Tests use in-memory SQLite and mock pf:
```rust
let db = Database::new_in_memory().await.unwrap();
let pf: Arc<dyn PfBackend> = Arc::new(aifw_pf::PfMock::new());
let engine = RuleEngine::new(db, pf);
```

API integration tests use `axum_test::TestServer` with `create_app_state_in_memory()`.

### pf Anchors

AiFw rules live in isolated pf anchors (`aifw`, `aifw-nat`, `aifw-vpn`, `aifw-geoip`, etc.), never touching system pf config.

## Web UI

Next.js 15 with `output: "export"` (static HTML, no Node.js on appliance). Tailwind CSS 4, TypeScript. Served by the API via `--ui-dir` flag on port 8080.

### UI Page Structure (#428)

Pages stay presentational; an ESLint `max-lines` guard caps `src/app/**/page.tsx` at 1000 lines. Layer resource code as:

- `src/lib/api/<resource>.ts` — TypeScript types + typed API functions wrapping the `api` client from `src/lib/api.ts` (no React here)
- `src/hooks/use<Resource>.ts` — per-resource hooks owning state, loading, CRUD actions, and feedback (`useFeedback` for the success/error banner)
- `src/app/<route>/components/` — route-local presentational components (props in, callbacks out; no fetching)

## External Components

`freebsd/manifest.json` is the single source of truth listing all components. AiFw depends on companion services built from separate repos:
- **TrafficCop** — reverse proxy
- **rDHCP** — DHCP server
- **rDNS** — DNS resolver
- **rTIME** — NTP/PTP time sync

The deploy script and CI pipeline build these from sibling directories or clone from GitHub.

## FreeBSD Deployment

### ISO Build (CI)
Push tag `v*` → `.github/workflows/build-iso.yml` builds UI on Linux, compiles Rust in FreeBSD VM, produces ISO + USB IMG.

### Local Build
```bash
sudo sh freebsd/build-local.sh [version]   # on FreeBSD — full build + ISO
```

### Deploy to Test VM
```bash
ssh root@172.29.69.159 "cd /root/AiFw && sh freebsd/deploy.sh"
```
Deploy script: pulls latest, builds Rust + UI, stops services, copies binaries to `/usr/local/sbin/`, UI to `/usr/local/share/aifw/ui/`, restarts services.

## Boot Flow

1. ISO boots → auto-login → `aifw-console` menu (OPNsense-style)
2. First boot: `aifw_firstboot` rc.d script runs `aifw-setup` wizard
3. Setup: root password, hostname, network, admin account, 2FA, firewall policy
4. Services start as `aifw` user (UID 470) — daemon + API on port 8080

## API Endpoints

Base: `http://<ip>:8080/api/v1/`

- **Rules**: `GET/POST /rules`, `GET/PUT/DELETE /rules/{id}`, `PUT /rules/reorder`
- **NAT**: `GET/POST /nat`, `PUT/DELETE /nat/{id}`
- **VPN**: `GET/POST /vpn/wg`, `PUT/DELETE /vpn/wg/{id}`, peers at `/vpn/wg/{id}/peers`; IPsec at `/vpn/ipsec`
- **Geo-IP**: `GET/POST /geoip`, `PUT/DELETE /geoip/{id}`, `GET /geoip/lookup/{ip}`
- **Auth**: `/auth/login`, `/auth/totp/*`, `/auth/refresh`, `/auth/logout`, `/auth/users`, `/auth/api-keys`, `/auth/oauth/*`
- **Status**: `GET /status`, `/connections`, `/metrics`, `/logs`, `POST /reload`
- **IDS**: `GET/PUT /ids/config`, `POST /ids/reload`, `GET /ids/alerts`, `GET/PUT /ids/alerts/{id}`, `PUT /ids/alerts/{id}/acknowledge`, `GET/POST /ids/rulesets`, `PUT/DELETE /ids/rulesets/{id}`, `GET /ids/rules`, `GET/PUT /ids/rules/{id}`, `GET/POST /ids/suppressions` (paginated via `?limit=&offset=`), `DELETE /ids/suppressions/{id}`, `GET /ids/stats`
- **DNS**: `GET/PUT /dns`
- **Multiwan**: `GET/POST /multiwan/instances`, gateways/groups/policies/leak/preflight/sla under `/multiwan/{gateways,groups,policies,leak,preflight,sla}` — load-balancing, SLA-driven failover, leak detection. Implementation in `aifw-core/src/multiwan/` + `aifw-api/src/multiwan.rs`.
- **Reverse proxy** (control plane for the external TrafficCop daemon): HTTP/TCP/UDP routers, services, middlewares, TLS certs under `/reverse-proxy/*`. Implementation in `aifw-api/src/reverse_proxy.rs`; data plane is the `trafficcop` service shipped via `freebsd/manifest.json`.
- **ACME**: `GET/POST /acme/certs`, providers, exports under `/acme/*` — Let's Encrypt cert issuance + push to local TLS store / file / webhook.

## Code Rules

- `cargo check` must pass with zero warnings before commit
- `npm run build` must succeed (static export)
- No paid crates (ask first)
- Run `cargo test` before pushing

## Error Handling Policy (#188)

- **Library crates** (`aifw-common`, `aifw-core`, `aifw-pf`, `aifw-ids`, etc.) use `thiserror` with a crate-local `Error` enum and `Result<T> = std::result::Result<T, Error>`. `aifw_common::AifwError` is the cross-crate fallback when a per-crate enum doesn't yet exist.
- **Binary crates** (`aifw-api`, `aifw-cli`, `aifw-daemon`, `aifw-setup`) use `anyhow::Result` at the edges and convert to `StatusCode` / `String` errors in handler boundaries.
- **No `.unwrap()` in non-test production code.** Use `?` for propagation, `.expect("clear reason")` only when the call is **provably infallible** (with the invariant explained in the message), or refactor the function to return `Result`.
- **No silent `.ok()` or `let _ = ...` on fallible operations** unless the failure is truly unactionable. At minimum log via `tracing::warn!` so the failure is visible.
- A workspace-level test (`aifw-setup::sudoers_tests` pattern) gates regressions: when adding new sweep-style discipline, write a test that asserts the bad pattern doesn't reappear.
