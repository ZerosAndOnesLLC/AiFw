# AiFw

High-performance, AI-powered firewall for FreeBSD built in Rust on top of pf. All features free and open source.

## Features

- **Stateful packet filtering** via FreeBSD's pf with anchor isolation
- **NAT** — SNAT, DNAT/RDR, masquerade, binat, NAT64/NAT46
- **Connection tracking** — real-time state table monitoring, top talkers, protocol breakdown
- **Rate limiting & traffic shaping** — CoDel/HFSC/PriQ queues, per-IP overload tables, SYN flood protection
- **AI/ML threat detection** — port scan, DDoS, brute force, C2 beacon, DNS tunnel detection with auto-response
- **VPN integration** — WireGuard tunnels + peers, IPsec SAs with pf rule generation
- **Geo-IP filtering** — country-based block/allow with GeoLite2 CSV, CIDR aggregation
- **TLS inspection** — JA3/JA3S fingerprinting, SNI filtering, cert validation, version enforcement
- **Plugin system** — native Rust + WASM sandboxed plugins with 7 hook points
- **High availability** — CARP virtual IPs, pfsync state sync, cluster node management, health checks
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
├── aifw-ai/            # ML threat detection (5 detectors) + auto-response
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
aifw vpn ipsec-add --name office --src 203.0.113.1 --dst 198.51.100.1

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
- **Threats** — AI detection timeline, severity scoring, auto-response history
- **Geo-IP** — country rules, IP lookup
- **VPN** — WireGuard tunnels + peers, IPsec SAs
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

## Target Environment

- **OS**: FreeBSD 14+
- **Kernel**: GENERIC with pf enabled
- **Required**: `/dev/pf` accessible (root or dedicated group)
- **pf**: `pf_enable="YES"` in `/etc/rc.conf`

## License

Apache-2.0 — all features free and open source.
