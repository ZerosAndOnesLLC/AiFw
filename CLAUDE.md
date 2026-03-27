# AiFw — AI-Powered Firewall for FreeBSD

Open-source (Apache-2.0) firewall built in Rust on FreeBSD's `pf`. All features are free.

## Project Structure

```
AiFw/
├── aifw-common/        # Shared types (rules, NAT, VPN, TLS, geo-IP, HA, metrics)
├── aifw-pf/            # pf backend (trait + FreeBSD ioctl / Linux mock)
├── aifw-core/          # Engines: rules, NAT, VPN, TLS, geo-IP, HA, shaping, audit, DB
├── aifw-conntrack/     # Connection tracking, pflog parsing
├── aifw-plugins/       # Plugin framework (native Rust + WASM)
├── aifw-ai/            # ML threat detection (5 detectors) + auto-response
├── aifw-metrics/       # RRD ring buffer metrics
├── aifw-api/           # Axum REST API (JWT auth, serves static UI via --ui-dir)
├── aifw-tui/           # ratatui terminal UI
├── aifw-daemon/        # Main firewall daemon
├── aifw-cli/           # CLI tool (clap)
├── aifw-setup/         # Interactive setup wizard (first boot)
├── aifw-ui/            # Next.js web UI (static export, served by API)
└── freebsd/            # ISO/IMG build scripts and overlay files
```

## Version Management

All components MUST share the same version. When bumping versions, update ALL of these:

| File | Field | Example |
|------|-------|---------|
| `Cargo.toml` (root) | `[workspace.package] version` | `version = "1.0.0"` |
| `aifw-ui/package.json` | `"version"` | `"version": "1.0.0"` |

The workspace Cargo.toml controls version for all 12 Rust crates. The console menu reads version dynamically from `/usr/local/share/aifw/version` (written during ISO build).

Increment: major=breaking, minor=features, patch=fixes.

## Build Commands

### Rust (all crates)
```bash
cargo check          # type check
cargo build --release # release binaries
cargo test           # run all tests (273 tests)
```

Release binaries: `target/release/{aifw,aifw-daemon,aifw-api,aifw-tui,aifw-setup}`

### Web UI (static export)
```bash
cd aifw-ui
npm ci
npm run build        # outputs to aifw-ui/out/
```

The API serves the static build via `--ui-dir /usr/local/share/aifw/ui`.

## FreeBSD ISO Build

### GitHub Actions (automated)
Push a tag like `v1.0.0` to trigger `.github/workflows/build-iso.yml`:
1. Builds UI static export on Linux runner
2. Spins up FreeBSD 15 VM via `vmactions/freebsd-vm`
3. Compiles Rust natively inside the VM
4. Runs `freebsd/build-iso.sh` to produce ISO + USB IMG + SHA256 checksums
5. Creates GitHub Release with all artifacts

### Local build on FreeBSD
```bash
sudo sh freebsd/build-local.sh [version]
```
This single script: installs deps (rustup, node, wireguard-tools), builds UI, compiles Rust, stages binaries, and runs `freebsd/build-iso.sh`. Output in `/usr/obj/aifw-iso/output/`.

### Build scripts
- `freebsd/build-local.sh` — one-step local build (run on FreeBSD)
- `freebsd/build-iso.sh` — ISO assembly (fetches FreeBSD base/kernel, stages filesystem, builds ISO+IMG)
- `freebsd/overlay/` — files baked into the ISO:
  - `usr/local/etc/rc.d/aifw_firstboot` — runs setup wizard on first boot
  - `usr/local/sbin/aifw-console` — OPNsense-style numbered console menu
  - `usr/local/sbin/aifw-install` — install-to-disk (ZFS/UFS choice)

## Boot Flow

1. ISO boots → auto-login on ttyv0 → `aifw-console` menu
2. First boot: `aifw_firstboot` rc.d script detects no config, runs `aifw-setup`
3. Setup wizard: root password, hostname, hardware detection, network config, admin account, 2FA, firewall policy
4. After setup: services start immediately (daemon + API), pf rules loaded
5. Menu option 14: install to disk (ZFS/UFS → partition → clone → reboot)

## Services

All services run as the `aifw` user (UID 470), not root. Device access to `/dev/pf` and `/dev/bpf*` is granted via `devfs.rules`.

| Service | rc.d script | Created by |
|---------|------------|------------|
| `aifw_firstboot` | ISO overlay | Runs setup on first boot |
| `aifw_daemon` | `aifw-setup` (apply.rs) | Firewall daemon |
| `aifw_api` | `aifw-setup` (apply.rs) | REST API + Web UI (port 8080) |

The API serves the web UI on the same port (8080) via the `--ui-dir` flag.

## API Endpoints

Base: `http://<ip>:8080/api/v1/`

### Core
- `GET/POST /rules`, `GET/PUT/DELETE /rules/{id}` — firewall rules CRUD
- `PUT /rules/reorder` — reorder rules by priority
- `GET/POST /nat`, `PUT/DELETE /nat/{id}` — NAT rules CRUD
- `GET/PUT /dns` — DNS nameserver config
- `GET /status`, `GET /connections`, `POST /reload`, `GET /metrics`, `GET /logs`

### VPN
- `GET/POST /vpn/wg`, `PUT/DELETE /vpn/wg/{id}` — WireGuard tunnels
- `GET/POST /vpn/wg/{id}/peers`, `DELETE /vpn/wg/{tid}/peers/{pid}` — WG peers
- `GET/POST /vpn/ipsec`, `DELETE /vpn/ipsec/{id}` — IPsec SAs

### Geo-IP
- `GET/POST /geoip`, `PUT/DELETE /geoip/{id}` — country rules
- `GET /geoip/lookup/{ip}` — IP country lookup

### Auth
- `POST /auth/login`, `/auth/totp/login`, `/auth/refresh`, `/auth/logout`
- `POST /auth/users`, `/auth/api-keys`
- `POST /auth/totp/setup`, `/auth/totp/verify`, `/auth/totp/disable`
- `GET/PUT /auth/settings`
- OAuth2: `/auth/oauth/providers`, `/auth/oauth/{provider}/authorize`, `/auth/oauth/{provider}/callback`

## Architecture Notes

- **pf anchors**: AiFw rules live in isolated pf anchors (aifw, aifw-nat, aifw-vpn, aifw-geoip, etc.), never touching system pf config
- **Cross-platform dev**: Linux/WSL with mock pf backend for development; FreeBSD with real ioctl for production
- **SQLite**: all state stored in `/var/db/aifw/aifw.db`
- **Static UI**: Next.js with `output: "export"` — no Node.js needed on the appliance
- **Config**: versioned JSON at `/usr/local/etc/aifw/aifw.conf`

## Code Rules

- `cargo check` must pass with zero warnings before commit
- No paid crates
- Run tests before pushing: `cargo test`
- UI: `npm run build` must succeed (static export)
