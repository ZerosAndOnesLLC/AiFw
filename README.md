# AiFw

High-performance firewall for FreeBSD built in Rust on top of pf. Optional AI-assisted IDS alert triage. All features free and open source.

> **AI is not required.** AiFw is a full-featured firewall, router, DHCP server, DNS resolver, IDS/IPS, reverse proxy, and NTP server that works perfectly without any AI features enabled. You get stateful packet filtering, NAT, VPN, Geo-IP blocking, Suricata-compatible intrusion detection, traffic shaping, and a complete web UI — all without AI. There is no cloud dependency and no telemetry.

> **What "AI" means here today.** The shipping AI feature is **LLM-assisted alert triage**: point Settings → AI at a provider (OpenAI, Anthropic, Ollama, …) and critical/high IDS alerts get reviewed and classified on the Threats page; leave it unset and nothing is called. The `aifw-ai` crate — heuristic prototypes for port-scan / DDoS / brute-force / C2-beacon / DNS-tunnel detection — is **not wired into the daemon or API**: nothing on the appliance runs those detectors and there is no setting that enables them (#171). It is kept out of the default build (`cargo build --workspace` or `-p aifw-ai` compiles it) until it has a real data path.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![FreeBSD](https://img.shields.io/badge/FreeBSD-15.x-red.svg)](https://www.freebsd.org/)
[![Rust](https://img.shields.io/badge/Rust-2024-orange.svg)](https://www.rust-lang.org/)

## Screenshots

<p align="center">
  <img src="screenshots/01-dashboard.png" alt="Dashboard with health status, metrics, charts" width="48%">
  <img src="screenshots/03-rules.png" alt="Firewall Rules" width="48%">
</p>
<p align="center">
  <img src="screenshots/07-ids-dashboard.png" alt="IDS/IPS Dashboard" width="48%">
  <img src="screenshots/05-blocked.png" alt="Blocked Traffic" width="48%">
</p>
<p align="center">
  <img src="screenshots/09-dns.png" alt="DNS Resolver" width="48%">
  <img src="screenshots/10-dhcp.png" alt="DHCP Server" width="48%">
</p>
<p align="center">
  <img src="screenshots/18-roles.png" alt="Role-Based Access Control" width="48%">
  <img src="screenshots/15-reverse-proxy.png" alt="Reverse Proxy" width="48%">
</p>
<p align="center">
  <img src="screenshots/16-time.png" alt="NTP/PTP Time Service" width="48%">
  <img src="screenshots/12-interfaces.png" alt="Network Interfaces" width="48%">
</p>

### Live Demos

| Demo | Preview |
|------|---------|
| Dashboard — live metrics, charts, health status | ![Dashboard](screenshots/vid-01-dashboard-live.gif) |
| Firewall Rules — browsing rule table | ![Rules](screenshots/vid-02-rules-browse.gif) |
| Blocked Traffic — real-time feed | ![Blocked](screenshots/vid-03-blocked-live.gif) |
| Connections — live state table | ![Connections](screenshots/vid-04-connections-live.gif) |
| IDS/IPS — engine overview and stats | ![IDS](screenshots/vid-05-ids-overview.gif) |

<details>
<summary>All 20 screenshots</summary>

| # | Page | Screenshot |
|---|------|-----------|
| 1 | Dashboard | <img src="screenshots/01-dashboard.png" width="300"> |
| 2 | Traffic Analytics | <img src="screenshots/02-traffic.png" width="300"> |
| 3 | Firewall Rules | <img src="screenshots/03-rules.png" width="300"> |
| 4 | NAT / Port Forward | <img src="screenshots/04-nat.png" width="300"> |
| 5 | Blocked Traffic | <img src="screenshots/05-blocked.png" width="300"> |
| 6 | Live Connections | <img src="screenshots/06-connections.png" width="300"> |
| 7 | IDS Dashboard | <img src="screenshots/07-ids-dashboard.png" width="300"> |
| 8 | IDS Rulesets | <img src="screenshots/08-ids-rulesets.png" width="300"> |
| 9 | DNS Resolver | <img src="screenshots/09-dns.png" width="300"> |
| 10 | DHCP Server | <img src="screenshots/10-dhcp.png" width="300"> |
| 11 | DHCP Subnets | <img src="screenshots/11-dhcp-subnets.png" width="300"> |
| 12 | Interfaces | <img src="screenshots/12-interfaces.png" width="300"> |
| 13 | VPN (WireGuard/IPsec) | <img src="screenshots/13-vpn.png" width="300"> |
| 14 | Geo-IP Filtering | <img src="screenshots/14-geoip.png" width="300"> |
| 15 | Reverse Proxy | <img src="screenshots/15-reverse-proxy.png" width="300"> |
| 16 | Time Service (NTP) | <img src="screenshots/16-time.png" width="300"> |
| 17 | User Management | <img src="screenshots/17-users.png" width="300"> |
| 18 | Roles & Permissions | <img src="screenshots/18-roles.png" width="300"> |
| 19 | Settings | <img src="screenshots/19-settings.png" width="300"> |
| 20 | System Updates | <img src="screenshots/20-updates.png" width="300"> |

</details>

## Features

- **Stateful packet filtering** via FreeBSD's pf with anchor isolation
- **NAT** — SNAT, DNAT/RDR, masquerade, binat, NAT bypass (`no nat`), `static-port` on outbound rules, NAT64/NAT46 (real cross-family translation via pf af-to, FreeBSD 15+, with DNS64 in the resolver)
- **Connection tracking** — real-time state table monitoring, top talkers, protocol breakdown
- **Rate limiting & traffic shaping** — HFSC/PriQ queues, per-IP overload tables, SYN flood protection (CoDel via dummynet FQ-CoDel in development, #532)
- **AI-assisted alert triage** *(optional)* — an LLM provider you configure reviews critical/high IDS alerts and classifies them (Threats page); off unless a provider is set. Behavioural ML detectors (`aifw-ai`) exist only as unwired prototypes — see the note above.
- **VPN integration** — WireGuard tunnels + peers, and IKEv2 site-to-site IPsec (tunnel mode, PSK or X.509 auth, NAT-T) powered by strongSwan
- **Geo-IP filtering** — country-based block/allow with GeoLite2 CSV, CIDR aggregation
- **TLS inspection** — JA3/JA3S fingerprinting, SNI filtering, cert validation, version enforcement
- **Plugin system** — native Rust + WASM sandboxed plugins with 7 hook points
- **High availability (active-passive pair)** — Two AiFw nodes share a CARP virtual IP and pfsync state. Reboot the master and TCP sessions survive on the standby with no operator intervention. Setup via the UI in <15 minutes. See [docs/ha.md](docs/ha.md) for setup, ops, and failure modes.
- **Remote syslog** — forward pf packet logs, IDS alerts, and app logs to a syslog server/SIEM (UDP/TCP, BSD or RFC 5424, per-category toggles, optional local-storage off)
- **Secrets sealed at rest** — WireGuard/IPsec keys, CARP and integration credentials, TOTP seeds and cluster keys are AES-256-GCM encrypted in the database under a master key kept outside it (`/var/db/aifw/secrets.key`); legacy plaintext rows are sealed automatically on the first start after upgrade
- **Log rotation** — one size-based newsyslog policy (cap, generations, compression) for every AiFw service log, with per-log sizes and rotate-now in Settings → Logging and `aifw logrotate`
- **Metrics engine** — RRD-style ring buffers (1s/1m/1h/1d tiers), optional PostgreSQL backend
- **REST API** — Axum with JWT auth, API keys, full CRUD for all resources
- **Terminal UI** — ratatui dashboard with 5 tabs
- **Web UI** — NextJS with 11 pages, real-time charts, dark theme

## Architecture

```
AiFw/
├── aifw-common/        # Shared types (rules, NAT, VPN, TLS, geo-IP, HA, metrics)
├── aifw-pf/            # pf backend trait + mock (Linux) / ioctl (FreeBSD)
├── aifw-core/          # Engines: rules, NAT, VPN, TLS, geo-IP, HA, shaping, audit
├── aifw-conntrack/     # Connection tracking, pflog parsing, stats
├── aifw-plugins/       # Plugin framework (native + WASM) + 3 example plugins
├── aifw-ai/            # Heuristic ML-detector prototypes — NOT wired into any binary (#171)
├── aifw-metrics/       # RRD ring buffer metrics engine
├── aifw-api/           # Axum REST API server (JWT + API key auth)
├── aifw-tui/           # ratatui terminal UI
├── aifw-daemon/        # Main firewall daemon
├── aifw-cli/           # CLI tool
└── aifw-ui/            # NextJS web interface
```

### Design Principles

- **pf anchors** — AiFw rules live in dedicated pf anchors, never touching system pf config
- **Trait-based pf abstraction** — `PfBackend` trait with mock (Linux dev) and ioctl (FreeBSD) implementations
- **Async everywhere** — Tokio runtime throughout
- **SQLite storage** — rules, config, audit logs persisted via sqlx
- **No paid crates** — all dependencies are free and open source

## Quick Start

```bash
# Build
cargo build --release

# Initialize database
aifw init --db /var/db/aifw/aifw.db

# Start the daemon
aifw-daemon --db /var/db/aifw/aifw.db --interface em0

# Start the API server
aifw-api --db /var/db/aifw/aifw.db --listen 0.0.0.0:8080

# Start the TUI
aifw-tui --db /var/db/aifw/aifw.db

# Start the web UI
cd aifw-ui && npm install && npm run dev
```

## CLI Usage

```bash
# Rules
aifw rules add --action pass --direction in --proto tcp --dst-port 443 --label "allow-https"
aifw rules add --action block --direction in --proto tcp --dst-port 22 --src 10.0.0.0/8
aifw rules list
aifw rules remove <uuid>

# NAT
aifw nat add --type snat --interface em0 --src 192.168.1.0/24 --redirect 203.0.113.1
aifw nat add --type dnat --interface em0 --proto tcp --dst-port 80 --redirect 192.168.1.10 --redirect-port 8080
aifw nat list

# Rate limiting
aifw ratelimit add --name ssh-protect --proto tcp --max-conn 5 --window 30 --table bruteforce --dst-port 22
aifw queue add --name voip --interface em0 --type priq --bandwidth 100Mb --class voip

# VPN
aifw vpn wg-add --name wg0 --interface wg0 --port 51820 --address 10.0.0.1/24
aifw vpn wg-peer-add --tunnel <id> --name laptop --pubkey <key> --endpoint 1.2.3.4:51820
aifw vpn ipsec-add --name office --remote 198.51.100.1 --psk <secret> --local-ts 10.0.0.0/24 --remote-ts 10.1.0.0/24

# Geo-IP
aifw geoip add --country CN --action block
aifw geoip add --country US --action allow
aifw geoip lookup 1.2.3.4

# Status & reload
aifw status
aifw reload
```

## REST API

All endpoints under `/api/v1/` with JWT Bearer or ApiKey authentication.

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/auth/login` | Get JWT token |
| POST | `/auth/users` | Create user |
| POST | `/auth/api-keys` | Create API key |
| GET/POST | `/rules` | List / create rules |
| GET/DELETE | `/rules/{id}` | Get / delete rule |
| GET/POST | `/nat` | List / create NAT rules |
| DELETE | `/nat/{id}` | Delete NAT rule |
| GET | `/status` | Firewall status |
| GET | `/connections` | Live connection table |
| POST | `/reload` | Reload all rules into pf |
| GET | `/metrics` | System metrics |
| GET | `/logs` | Audit log |

## Web UI

NextJS application with 11 pages:

- **Dashboard** — key metrics, sparkline charts, protocol/threat breakdowns
- **Traffic** — bandwidth, PPS, bytes with time range selector (5m–30d)
- **Rules / NAT** — full CRUD with inline forms
- **Connections** — auto-refreshing live state table
- **Threats** — AI detection timeline, severity scoring, auto-response history *(WIP — AI module is experimental)*
- **Geo-IP** — country rules, IP lookup
- **VPN** — WireGuard tunnels + peers, IKEv2 IPsec site-to-site tunnels
- **Cluster** — CARP VIPs, pfsync, node health, health checks
- **Logs** — filterable audit log with color-coded actions
- **Settings** — metrics backend (local/PostgreSQL), API, TLS policy

## Development

Development happens in WSL/Linux. The mock pf backend enables full compilation and testing without FreeBSD.

```bash
cargo build          # Build all Rust crates
cargo test           # Run all 216 tests
cargo check          # Fast type check

cd aifw-ui
npm install          # Install UI dependencies
npm run dev          # Start dev server on :3000
```

The toolchain is pinned in `rust-toolchain.toml` (stable, with `rustfmt` +
`clippy`) and formatting in `rustfmt.toml`, so every contributor and CI run
use the same compiler and style. After cloning, install the git hooks once:

```bash
sh scripts/install-hooks.sh   # pre-commit runs fmt --check + clippy -D warnings
```

The hook mirrors CI's fast gates; skip a single run with `git commit --no-verify`.

### Runtime tuning & diagnostics

The long-running binaries (`aifw-api`, `aifw-daemon`, `aifw-ids`) build their
tokio runtime explicitly with a floor of 4 worker threads (`max(4, cores)`,
capped at 32) so a 2-vCPU appliance's periodic tasks don't fully subscribe the
scheduler; override with `AIFW_WORKER_THREADS=<n>`. They use
[mimalloc](https://github.com/microsoft/mimalloc) as the process allocator
(cargo feature `mimalloc`, on by default; `--no-default-features` builds with
the system malloc). `GET /api/v1/metrics` reports the API runtime's
`worker_threads`, `alive_tasks` and `global_queue_depth` — a queue depth that
stays above zero means the workers can't keep up. For task-level diagnostics
build with tokio-console support and pass `--tokio-console`
(serves on 127.0.0.1:6669):

```bash
RUSTFLAGS="--cfg tokio_unstable" cargo build --release -p aifw-api --features tokio-console
aifw-api --tokio-console ...   # then: tokio-console http://127.0.0.1:6669
```

## Target Environment

- **OS**: FreeBSD 15.x
- **Kernel**: GENERIC with pf enabled
- **Required**: `/dev/pf` accessible (root or dedicated group)
- **pf**: `pf_enable="YES"` in `/etc/rc.conf`

## License

MIT — all features free and open source.
