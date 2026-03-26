# AiFw — FreeBSD AI-Powered Firewall

## Overview

High-performance, AI-powered firewall for FreeBSD built in Rust on top of pf. All features free and open source.

## Architecture

```
AiFw/
├── aifw-common/        # Shared types and utilities
├── aifw-pf/            # pf integration layer (libpf/ioctl)
├── aifw-core/          # Core firewall engine (rules, NAT, state)
├── aifw-conntrack/     # Connection tracking
├── aifw-api/           # REST API server (Axum)
├── aifw-ai/            # AI/ML threat detection (ONNX)
├── aifw-plugins/       # Plugin system (native Rust + WASM)
├── aifw-daemon/        # Main daemon binary
├── aifw-cli/           # CLI tool
├── aifw-tui/           # Terminal UI (ratatui)
├── aifw-ui/            # NextJS Web UI
└── xtask/              # Build tooling
```

### Core Design

- **pf backend**: All packet filtering through FreeBSD's pf via `/dev/pf` ioctl interface
- **Userspace management**: Rust daemon manages pf rules, anchors, and tables programmatically
- **pf anchors**: AiFw rules live in dedicated anchors to avoid conflicting with system pf config
- **Async runtime**: Tokio throughout
- **Storage**: SQLite (sqlx) for rules, config, audit logs
- **Metrics**: Prometheus endpoint

---

## Development Workflow

Development happens in **WSL (Linux)** with Claude Code. The FreeBSD VM is only needed for pf integration testing.

### Platform Separation

- **`aifw-pf`** — the only FreeBSD-specific crate. Uses `#[cfg(target_os = "freebsd")]` for real pf ioctl calls. On non-FreeBSD, compiles with a **mock/stub backend** that implements the same trait interface, enabling full development and unit testing on Linux.
- **All other crates** — portable Rust, no OS-specific dependencies. Developed and compiled in WSL.

### Trait-Based Abstraction

```rust
// aifw-pf/src/lib.rs
pub trait PfBackend: Send + Sync {
    async fn add_rule(&self, anchor: &str, rule: &PfRule) -> Result<()>;
    async fn remove_rule(&self, anchor: &str, id: u32) -> Result<()>;
    async fn flush_rules(&self, anchor: &str) -> Result<()>;
    async fn get_states(&self) -> Result<Vec<PfState>>;
    async fn add_table_entry(&self, table: &str, addr: IpAddr) -> Result<()>;
    async fn get_stats(&self) -> Result<PfStats>;
    // ...
}

#[cfg(target_os = "freebsd")]
pub struct PfIoctl { /* real /dev/pf implementation */ }

#[cfg(not(target_os = "freebsd"))]
pub struct PfMock { /* in-memory mock for dev/testing */ }
```

### Day-to-Day Workflow

1. **Write code** in WSL with Claude Code (`~/dev/AiFw/`)
2. **Compile + unit test** locally (`cargo build`, `cargo test`) — works on Linux via mock backend
3. **Push to git** or sync to FreeBSD VM
4. **Integration test on FreeBSD VM** — compile with real pf backend, run against live pf
5. **SSH deploy script** (`xtask deploy-test`) — automate build + test on VM

### FreeBSD VM Setup

- FreeBSD 15+ on Hyper-V
- SSH access configured (key-based)
- Rust toolchain installed
- pf enabled in `/etc/rc.conf` (`pf_enable="YES"`)
- Shared project via git clone or NFS mount
- Test script: `cargo test --features freebsd-integration`

### Sync Script (xtask)

```
cargo xtask test-freebsd          # rsync + build + test on VM
cargo xtask test-freebsd --quick  # rsync + test only (skip rebuild if unchanged)
```

---

## Phases

### Phase 1 — Foundation
- [x] Project scaffolding (workspace, crates)
- [x] aifw-common: shared types (rules, protocols, addresses, actions)
- [x] aifw-pf: pf ioctl bindings
  - [x] Open/close `/dev/pf`
  - [x] Add/remove rules via anchors
  - [x] Read pf state and statistics
  - [x] Table management (add/remove/flush addresses)
- [x] aifw-core: rule engine
  - [x] Rule CRUD (in-memory + SQLite persistence)
  - [x] Rule validation
  - [x] Rule ordering and priority
  - [x] pf rule generation (translate AiFw rules to pf syntax)
- [x] aifw-daemon: basic daemon
  - [x] Start/stop, attach to interface
  - [x] Load rules from config/DB and push to pf
  - [x] Signal handling (reload, shutdown)
  - [x] Logging (tracing)
- [x] aifw-cli: basic CLI
  - [x] `aifw init` — initialize config and DB
  - [x] `aifw rules add/remove/list`
  - [x] `aifw status`
  - [x] `aifw reload`
- [x] Unit + integration tests
- [x] README

### Phase 2 — Stateful Inspection & Connection Tracking
- [x] aifw-conntrack: connection tracking
  - [x] Track TCP/UDP/ICMP connections via pf state table
  - [x] Connection state queries (list, count, search)
  - [x] State table statistics
  - [x] Automatic state expiry monitoring
- [x] Stateful rule support
  - [x] `keep state`, `modulate state`, `synproxy state`
  - [x] State policy options (if-bound, floating)
  - [x] Adaptive timeouts
- [x] Logging and audit
  - [x] pflog interface integration
  - [x] Structured log parsing and storage
  - [x] Audit trail for rule changes

### Phase 3 — NAT
- [x] SNAT (source NAT / outbound NAT)
- [x] DNAT (port forwarding / RDR)
- [x] Masquerading (dynamic outbound NAT)
- [x] NAT64 / NAT46
- [x] Bidirectional NAT (binat)
- [x] NAT rule management via CLI and API

### Phase 4 — REST API
- [x] aifw-api: Axum-based API server
  - [x] JWT authentication
  - [x] User management (argon2 password hashing)
  - [x] API key support
- [x] Endpoints
  - [x] `POST/GET/PUT/DELETE /api/v1/rules`
  - [x] `GET /api/v1/status`
  - [x] `GET /api/v1/connections`
  - [x] `POST /api/v1/reload`
  - [x] `GET/POST /api/v1/nat`
  - [x] `GET /api/v1/metrics`
  - [x] `GET /api/v1/logs`
- [x] Rate limiting
- [x] CORS configuration
- [ ] OpenAPI docs

### Phase 5 — Rate Limiting & Traffic Shaping
- [x] pf queue integration (ALTQ / CoDel)
- [x] Per-IP rate limiting via pf tables + overload
- [x] Bandwidth throttling
- [x] Priority queues (VoIP, interactive, bulk)
- [x] SYN flood protection (synproxy)
- [x] Rule-based rate limit configuration

### Phase 6 — TUI
- [x] aifw-tui: ratatui-based terminal UI
  - [x] Dashboard (traffic stats, connection count, top talkers)
  - [x] Rule management (add/edit/delete/reorder)
  - [x] Live connection table
  - [x] Log viewer with filtering
  - [x] NAT status
  - [x] Interface statistics

### Phase 7 — VPN Integration
- [ ] WireGuard integration (FreeBSD native wg)
  - [ ] Tunnel creation/management
  - [ ] Peer management
  - [ ] Key generation
  - [ ] pf rules for VPN traffic
- [ ] IPsec integration (FreeBSD native)
  - [ ] SA/SP management
  - [ ] IKEv2 support
- [ ] VPN status monitoring

### Phase 8 — Geo-IP Filtering
- [ ] MaxMind GeoLite2 database integration
- [ ] Country-based allow/block rules
- [ ] Automatic database updates
- [ ] pf table population by country
- [ ] Geo-IP lookup API endpoint
- [ ] CIDR aggregation for efficient table loading

### Phase 9 — Plugin System
- [ ] aifw-plugins: plugin framework
  - [ ] Native Rust plugin API (trait-based)
  - [ ] WASM sandboxed plugins (wasmtime)
  - [ ] Plugin lifecycle (load, init, execute, unload)
  - [ ] Plugin configuration
- [ ] Hook points
  - [ ] Pre/post rule evaluation
  - [ ] Connection events (new, established, closed)
  - [ ] Log events
  - [ ] API request hooks
- [ ] Example plugins
  - [ ] IP reputation checker
  - [ ] Custom logging plugin
  - [ ] Webhook notifier

### Phase 10 — AI/ML Threat Detection
- [ ] aifw-ai: ML inference engine
  - [ ] ONNX runtime integration
  - [ ] Feature extraction from traffic patterns
  - [ ] Model loading and hot-reload
- [ ] Detection capabilities
  - [ ] Anomaly detection (unusual traffic patterns)
  - [ ] Port scan detection
  - [ ] DDoS detection and auto-mitigation
  - [ ] Brute force detection
  - [ ] C2 beacon detection
  - [ ] DNS tunneling detection
- [ ] Training pipeline
  - [ ] Traffic feature collection
  - [ ] Baseline learning (normal traffic profile)
  - [ ] Model export to ONNX
- [ ] Auto-response
  - [ ] Dynamic rule insertion for detected threats
  - [ ] Configurable response actions (block, rate-limit, alert)
  - [ ] Threat score and confidence thresholds
  - [ ] Auto-expiry of temporary blocks

### Phase 11 — TLS Inspection
- [ ] TLS handshake analysis (no MITM, metadata only)
  - [ ] JA3/JA3S fingerprinting
  - [ ] Certificate validation
  - [ ] SNI-based filtering
- [ ] Optional MITM proxy mode (explicit opt-in)
  - [ ] CA certificate generation
  - [ ] Dynamic certificate minting
  - [ ] Transparent proxy via pf RDR
- [ ] TLS version enforcement (block TLS < 1.2)

### Phase 12 — High Availability & Clustering
- [ ] CARP (Common Address Redundancy Protocol)
  - [ ] Virtual IP management
  - [ ] Failover configuration
- [ ] pfsync integration
  - [ ] State table synchronization between nodes
  - [ ] Dedicated sync interface
- [ ] Configuration sync
  - [ ] Rule replication across cluster nodes
  - [ ] Consensus-based config changes
- [ ] Health checks and monitoring

### Phase 13 — Web UI
- [ ] aifw-ui: NextJS web interface
  - [ ] Dashboard with real-time traffic visualization
  - [ ] Rule management (drag-and-drop ordering)
  - [ ] Connection table (live updating)
  - [ ] NAT configuration
  - [ ] VPN management
  - [ ] Geo-IP map visualization
  - [ ] AI threat alerts and history
  - [ ] Log viewer with search/filter
  - [ ] User/API key management
  - [ ] Cluster status (HA)
  - [ ] System settings

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Language | Rust (userspace), C (pf ioctl FFI if needed) |
| Async | Tokio |
| Web API | Axum |
| Database | SQLite (sqlx) |
| TUI | ratatui + crossterm |
| Web UI | NextJS |
| AI/ML | ONNX Runtime (ort) |
| Plugins | wasmtime (WASM) + native Rust |
| Metrics | Prometheus |
| Auth | JWT + argon2 |
| VPN | WireGuard (native), IPsec (native) |
| HA | CARP + pfsync (FreeBSD native) |

## Target Environment

- **OS**: FreeBSD 14+
- **Kernel**: GENERIC with pf enabled
- **Required**: `/dev/pf` accessible (root or dedicated group)
- **Development**: FreeBSD VM on Hyper-V

## License

Apache-2.0 — all features free and open source.
