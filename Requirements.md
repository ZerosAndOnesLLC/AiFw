# AiFw — Requirements

## System Requirements

### Production (FreeBSD)

| Component | Requirement |
|-----------|-------------|
| **OS** | FreeBSD 14.0 or later |
| **Kernel** | GENERIC with pf enabled |
| **pf** | `pf_enable="YES"` in `/etc/rc.conf` |
| **Device** | `/dev/pf` accessible (run as root or `pf` group member) |
| **CPU** | 2+ cores recommended (AI detectors run in background) |
| **RAM** | 512 MB minimum, 2 GB recommended |
| **Disk** | 100 MB for binaries + SQLite DB, more for metrics retention |
| **Network** | At least one managed interface |

### Development (Linux / WSL)

| Component | Requirement |
|-----------|-------------|
| **OS** | Any Linux (WSL2 works) |
| **Rust** | 1.85+ (edition 2024) |
| **SQLite** | Bundled via sqlx (no system install needed) |
| **Node.js** | 18+ (for web UI development) |
| **npm** | 9+ |

### Optional

| Component | When Needed |
|-----------|-------------|
| **PostgreSQL 15+** | If using `postgres` metrics backend |
| **FreeBSD VM** | For pf integration testing |
| **MaxMind GeoLite2 CSV** | For geo-IP filtering (free license key from MaxMind) |

## Rust Dependencies

All dependencies are free and open source. No paid crates.

### Core

| Crate | Version | Purpose |
|-------|---------|---------|
| `tokio` | 1.x | Async runtime |
| `sqlx` | 0.8 | SQLite database (compile-time checked queries) |
| `serde` / `serde_json` | 1.x | Serialization |
| `chrono` | 0.4 | Date/time handling |
| `uuid` | 1.x | Unique identifiers |
| `thiserror` | 2.x | Error types |
| `tracing` | 0.1 | Structured logging |
| `async-trait` | 0.1 | Async trait methods |
| `clap` | 4.x | CLI argument parsing |

### API Server

| Crate | Version | Purpose |
|-------|---------|---------|
| `axum` | 0.8 | HTTP framework |
| `tower` / `tower-http` | 0.5 / 0.6 | Middleware (CORS, tracing) |
| `jsonwebtoken` | 9.x | JWT authentication |
| `argon2` | 0.5 | Password hashing |

### Terminal UI

| Crate | Version | Purpose |
|-------|---------|---------|
| `ratatui` | 0.29 | Terminal UI framework |
| `crossterm` | 0.28 | Cross-platform terminal I/O |

### Web UI (NextJS)

| Package | Version | Purpose |
|---------|---------|---------|
| `next` | 15.x | React framework |
| `react` | 19.x | UI library |
| `tailwindcss` | 4.x | Utility CSS |
| `recharts` | 2.x | Charts (available, sparklines are SVG) |
| `lucide-react` | 0.500+ | Icons |

## Build Instructions

### Rust Crates

```bash
# Clone
git clone https://github.com/ZerosAndOnesLLC/AiFw.git
cd AiFw

# Build all crates (debug)
cargo build

# Build release binaries
cargo build --release

# Run all tests (216 tests)
cargo test

# Type check only (fast)
cargo check

# Build with PostgreSQL metrics support
cargo build --release -p aifw-metrics --features postgres
```

Release binaries are placed in `target/release/`:
- `aifw` — CLI tool
- `aifw-daemon` — main firewall daemon
- `aifw-api` — REST API server
- `aifw-tui` — terminal UI

### Web UI

```bash
cd aifw-ui

# Install dependencies
npm install

# Development server (http://localhost:3000)
npm run dev

# Production build
npm run build

# Production server
npm start
```

Set `NEXT_PUBLIC_API_URL` to point to the API server (default: `http://localhost:8080`).

## FreeBSD Deployment

### 1. Enable pf

```bash
# /etc/rc.conf
pf_enable="YES"
pflog_enable="YES"
```

### 2. Install binaries

```bash
# Copy release binaries
cp target/release/aifw /usr/local/bin/
cp target/release/aifw-daemon /usr/local/sbin/
cp target/release/aifw-api /usr/local/sbin/
```

### 3. Initialize

```bash
# Create database directory
mkdir -p /var/db/aifw

# Initialize database
aifw init --db /var/db/aifw/aifw.db

# Create admin user (via API)
aifw-api --db /var/db/aifw/aifw.db &
curl -X POST http://localhost:8080/api/v1/auth/users \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"changeme"}'
```

### 4. Start services

```bash
# Daemon (manages pf rules)
aifw-daemon --db /var/db/aifw/aifw.db --interface em0 &

# API server
aifw-api --db /var/db/aifw/aifw.db --listen 0.0.0.0:8080 --jwt-secret "your-secret" &

# Web UI (or serve from S3/CDN)
cd aifw-ui && npm start &
```

### 5. Configure firewall

```bash
# Add basic rules
aifw rules add --action pass --direction in --proto tcp --dst-port 443 --label "allow-https"
aifw rules add --action pass --direction in --proto tcp --dst-port 80 --label "allow-http"
aifw rules add --action block --direction in --label "default-deny"

# Add NAT for LAN
aifw nat add --type masquerade --interface em0 --src 192.168.1.0/24

# Enable rate limiting
aifw ratelimit add --name ssh-protect --proto tcp --dst-port 22 --max-conn 5 --window 30 --table bruteforce

# Block countries
aifw geoip add --country CN --action block
aifw geoip add --country RU --action block

# Apply all rules
aifw reload
```

## High Availability Setup

### Primary node

```bash
# CARP virtual IP
aifw cluster carp-add --vhid 1 --ip 10.0.0.100 --prefix 24 --interface em0 --password secret --advskew 0

# pfsync
aifw cluster pfsync --interface em1 --peer 10.0.0.2

# Add secondary node
aifw cluster node-add --name fw-secondary --address 10.0.0.2 --role secondary
```

### Secondary node

```bash
# Same config but with advskew 100 (lower priority)
aifw cluster carp-add --vhid 1 --ip 10.0.0.100 --prefix 24 --interface em0 --password secret --advskew 100
aifw cluster pfsync --interface em1 --peer 10.0.0.1
```

## Metrics Storage Configuration

### Local (default)

No configuration needed. In-memory ring buffers with 4-tier consolidation:

| Tier | Resolution | Retention | Points |
|------|-----------|-----------|--------|
| Realtime | 1 second | 5 minutes | 300 |
| Minute | 1 minute | 24 hours | 1,440 |
| Hour | 1 hour | 30 days | 720 |
| Day | 1 day | 1 year | 365 |

### PostgreSQL

```bash
# Start API with postgres metrics
aifw-api --db /var/db/aifw/aifw.db \
  --metrics-backend postgres \
  --metrics-postgres-url "postgresql://aifw:password@localhost/aifw_metrics"
```

## Network Ports

| Port | Service | Protocol |
|------|---------|----------|
| 8080 | REST API | TCP |
| 3000 | Web UI (dev) | TCP |
| 51820 | WireGuard (default) | UDP |
| 500, 4500 | IPsec IKE | UDP |
