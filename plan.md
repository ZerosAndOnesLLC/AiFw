# AiFw IDS/IPS Engine — Implementation Plan

## Context

AiFw is a Rust-based AI-powered firewall for FreeBSD built on pf. It currently has ML-based threat detection (port scan, DDoS, brute force, C2, DNS tunnel) via connection tracking features, but lacks **signature-based intrusion detection** — the ability to inspect packet payloads against known threat signatures (ET Open, Sigma, YARA rulesets).

This plan adds a full IDS/IPS engine (`aifw-ids`) that provides deep packet inspection with multi-format rule support, integrates with the existing AI detectors for correlated threat intelligence, and is configurable via the existing UI/API.

**Target**: Maximum achievable throughput — line-rate on any hardware. Zero-copy, zero-alloc hot path, SIMD-accelerated matching, batch processing. The hardware should be the bottleneck, not the software.

---

## Phase 1: Foundation — Core Types & Crate Scaffold

**Goal**: Create the `aifw-ids` crate with shared types in `aifw-common`, database schema, and basic configuration.

### 1.1 — Common Types (`aifw-common/src/ids.rs`)
Add IDS-specific types to the shared crate:
- `IdsMode` enum: `Ids` (alert only), `Ips` (inline block), `Disabled`
- `IdsAlert` struct: id, timestamp, signature_id, signature_msg, severity (1-4), src/dst IP:port, protocol, action (alert/drop/reject), payload_excerpt, rule_source (et_open/sigma/yara/custom), flow_id, metadata
- `IdsRuleset` struct: id, name, source_url, rule_format (suricata/sigma/yara), enabled, auto_update, last_updated, rule_count
- `IdsRule` struct: id, sid, ruleset_id, raw_text, enabled, action_override, hit_count
- `IdsConfig` struct: mode, home_net, external_net, interfaces, enabled_rulesets, alert_retention_days, eve_log_enabled, syslog_target
- `IdsStats` struct: packets_inspected, alerts_total, drops_total, bytes_per_sec, packets_per_sec, active_flows
- Re-export from `aifw-common/src/lib.rs`

### 1.2 — Crate Scaffold (`aifw-ids/`)
Create workspace member with this structure:
```
aifw-ids/
├── Cargo.toml
└── src/
    ├── lib.rs           # IdsEngine public API
    ├── config.rs        # Runtime configuration
    ├── capture/
    ���   ├── mod.rs       # CaptureBackend trait
    ��   ├── bpf.rs       # FreeBSD BPF (production)
    │   ├── netmap.rs    # FreeBSD netmap (high-perf)
    │   ├── dpdk.rs      # DPDK kernel bypass (max throughput, optional)
    │   └─�� pcap.rs      # libpcap (cross-platform dev)
    ├── decode/
    │   └── mod.rs       # Packet decoding via etherparse
    ├── flow/
    │   └── mod.rs       # Flow tracking table
    ├── protocol/
    │   ├── mod.rs       # ProtocolParser trait + registry
    │   ├── http.rs
    │   ├── tls.rs
    │   ├── dns.rs
    │   ├── ssh.rs
    │   └── smtp.rs
    ├── rules/
    │   ├── mod.rs       # RuleDatabase + compiled ruleset
    │   ├── suricata.rs  # ET Open / Suricata rule parser
    │   ├── sigma.rs     # Sigma rule support
    │   └── yara.rs      # YARA rule support
    ├── detect/
    │   ├── mod.rs       # DetectionEngine orchestrator
    │   ├── multi_pattern.rs  # Aho-Corasick multi-pattern matcher
    │   └── regex.rs     # Hyperscan regex matcher
    ├── action/
    │   └── mod.rs       # Verdict: pass/alert/drop/reject → pf
    └── output/
        ├── mod.rs       # AlertOutput trait
        ├── eve.rs       # EVE JSON file output
        ├── sqlite.rs    # SQLite alert storage
        ├── syslog.rs    # Remote syslog forwarding
        └── websocket.rs # Real-time WS streaming
```

### 1.3 — Database Schema
Inline migrations in `aifw-ids` (following existing pattern):
```sql
-- IDS configuration
CREATE TABLE IF NOT EXISTS ids_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Rulesets (ET Open, Sigma, YARA, Custom)
CREATE TABLE IF NOT EXISTS ids_rulesets (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    source_url TEXT,
    rule_format TEXT NOT NULL,  -- 'suricata', 'sigma', 'yara'
    enabled INTEGER NOT NULL DEFAULT 1,
    auto_update INTEGER NOT NULL DEFAULT 1,
    update_interval_hours INTEGER NOT NULL DEFAULT 24,
    last_updated TEXT,
    rule_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Individual rules (parsed from rulesets)
CREATE TABLE IF NOT EXISTS ids_rules (
    id TEXT PRIMARY KEY,
    ruleset_id TEXT NOT NULL REFERENCES ids_rulesets(id),
    sid INTEGER,              -- signature ID (Suricata rules)
    rule_text TEXT NOT NULL,   -- raw rule
    msg TEXT,                  -- human-readable message
    severity INTEGER DEFAULT 3,
    enabled INTEGER NOT NULL DEFAULT 1,
    action_override TEXT,      -- NULL = use rule default
    hit_count INTEGER NOT NULL DEFAULT 0,
    last_hit TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ids_rules_sid ON ids_rules(sid);
CREATE INDEX IF NOT EXISTS idx_ids_rules_ruleset ON ids_rules(ruleset_id);

-- Alerts
CREATE TABLE IF NOT EXISTS ids_alerts (
    id TEXT PRIMARY KEY,
    timestamp TEXT NOT NULL,
    signature_id INTEGER,
    signature_msg TEXT NOT NULL,
    severity INTEGER NOT NULL,
    src_ip TEXT NOT NULL,
    src_port INTEGER,
    dst_ip TEXT NOT NULL,
    dst_port INTEGER,
    protocol TEXT NOT NULL,
    action TEXT NOT NULL,       -- 'alert', 'drop', 'reject'
    rule_source TEXT NOT NULL,  -- 'et_open', 'sigma', 'yara', 'custom'
    flow_id TEXT,
    payload_excerpt TEXT,
    metadata TEXT,              -- JSON blob
    acknowledged INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_ids_alerts_ts ON ids_alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_ids_alerts_src ON ids_alerts(src_ip);
CREATE INDEX IF NOT EXISTS idx_ids_alerts_sid ON ids_alerts(signature_id);
CREATE INDEX IF NOT EXISTS idx_ids_alerts_sev ON ids_alerts(severity);

-- Suppressions (silence noisy rules per IP/subnet)
CREATE TABLE IF NOT EXISTS ids_suppressions (
    id TEXT PRIMARY KEY,
    sid INTEGER NOT NULL,
    suppress_type TEXT NOT NULL,  -- 'src', 'dst', 'both'
    ip_cidr TEXT,                 -- NULL = suppress globally
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
```

### 1.4 — Cargo.toml Dependencies
```toml
[dependencies]
aifw-common = { path = "../aifw-common" }
aifw-pf = { path = "../aifw-pf" }
tokio = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
sqlx = { workspace = true }
chrono = { workspace = true }
uuid = { workspace = true }
tracing = { workspace = true }
thiserror = { workspace = true }
async-trait = { workspace = true }

# Packet capture & parsing
etherparse = "0.16"
pcap = "2"

# Pattern matching
aho-corasick = "1"
hyperscan = "0.4"        # Hyperscan FFI bindings
regex = "1"

# Protocol parsing
httparse = "1"
dns-parser = "0.8"

# Rule formats
yara = "0.28"            # YARA bindings

# Output
syslog = "7"

# Performance
crossbeam = "0.8"        # lock-free channels & queues
dashmap = "6"            # concurrent hashmap for flow table
bumpalo = "3"            # arena allocator
```

**Files to modify**: `Cargo.toml` (workspace members), `aifw-common/src/lib.rs`, `aifw-common/src/ids.rs` (new)

---

## Phase 2: Packet Capture & Decode Pipeline

**Goal**: Capture packets from network interfaces and decode them into structured data with zero-copy where possible.

### 2.1 — Capture Backend Trait (`capture/mod.rs`)
```rust
#[async_trait]
pub trait CaptureBackend: Send + Sync {
    async fn open(interface: &str, config: &CaptureConfig) -> Result<Self> where Self: Sized;
    fn next_packet(&mut self) -> Option<RawPacket>;  // non-async, hot path
    fn stats(&self) -> CaptureStats;
}
```
- `RawPacket`: timestamp + byte slice (zero-copy reference to mmap'd ring buffer)
- `CaptureConfig`: snaplen, promiscuous, buffer_size, bpf_filter

### 2.2 — pcap Backend (`capture/pcap.rs`)
- libpcap-based capture for development on Linux/WSL
- Compile-time default on non-FreeBSD via `#[cfg(not(target_os = "freebsd"))]`
- Supports BPF pre-filter strings

### 2.3 — netmap Backend (`capture/netmap.rs`)
- FreeBSD netmap for production high-speed capture
- Zero-copy via mmap'd ring buffers
- `#[cfg(target_os = "freebsd")]` only
- Inline mode support (IPS): receive on one ring, verdict on another
- Multi-ring support: one ring per worker thread (RSS distribution)

### 2.4 — DPDK Backend (`capture/dpdk.rs`) [Optional]
- Kernel-bypass packet capture for maximum throughput
- Hugepage memory — zero TLB misses
- Poll-mode driver — zero interrupt overhead
- Zero syscalls per packet
- Multi-queue: one RX queue per worker thread
- Enabled via `--features dpdk` cargo feature flag
- Not required for development or standard deployments

### 2.5 — Packet Decoder (`decode/mod.rs`)
- Uses `etherparse` for zero-allocation parsing
- Outputs `DecodedPacket` struct:
  ```rust
  pub struct DecodedPacket<'a> {
      pub timestamp: i64,
      pub eth: Option<EthernetHeader>,
      pub ip: Option<IpHeader>,
      pub transport: Option<TransportHeader>,
      pub payload: &'a [u8],       // zero-copy slice
      pub packet_len: usize,
  }
  ```
- Handles: Ethernet → IPv4/IPv6 → TCP/UDP/ICMP → payload extraction
- VLAN tag stripping, GRE/MPLS tunnel decap

**Files**: `aifw-ids/src/capture/`, `aifw-ids/src/decode/mod.rs`

---

## Phase 3: Flow Tracking

**Goal**: Track bidirectional flows (connections) with lock-free concurrency for multi-core processing.

### 3.1 — Flow Table (`flow/mod.rs`)
- `DashMap<FlowKey, Flow>` — concurrent hashmap, no global lock
- `FlowKey`: (src_ip, dst_ip, src_port, dst_port, protocol) — canonical ordering so both directions map to same flow
- `Flow` struct:
  ```rust
  pub struct Flow {
      pub id: Uuid,
      pub state: FlowState,          // New, Established, Closing, Closed
      pub pkts_toserver: u64,
      pub pkts_toclient: u64,
      pub bytes_toserver: u64,
      pub bytes_toclient: u64,
      pub start_ts: i64,
      pub last_ts: i64,
      pub app_proto: Option<AppProto>,  // Detected protocol (HTTP, TLS, DNS, etc.)
      pub app_state: Option<Box<dyn AppLayerState>>,  // Protocol-specific parsed state
  }
  ```
- TCP state tracking: SYN → SYN-ACK → ESTABLISHED → FIN
- Flow timeout/expiry with configurable timeouts per protocol
- Flow recycling: pre-allocate flow pool, reuse instead of alloc/free

### 3.2 — Stream Reassembly
- TCP stream reassembly for content inspection across packet boundaries
- Per-flow reassembly buffer (bounded, configurable max depth)
- Gap handling: track missing segments, reassemble when filled
- Direction-aware: separate toserver/toclient buffers

**Files**: `aifw-ids/src/flow/mod.rs`

---

## Phase 4: Protocol Parsers

**Goal**: Application-layer protocol detection and parsing, providing structured data for rule matching.

### 4.1 — Protocol Parser Trait (`protocol/mod.rs`)
```rust
pub trait ProtocolParser: Send + Sync {
    fn name(&self) -> &str;
    fn default_ports(&self) -> &[u16];
    fn probe(&self, payload: &[u8], direction: Direction) -> ProbeResult;  // Quick check
    fn parse(&self, flow: &mut Flow, payload: &[u8], direction: Direction) -> ParseResult;
}
```
- Auto-detection: try `probe()` on unknown flows, assign `app_proto` on match
- Port-based hint: try expected parser first based on dst_port

### 4.2 — HTTP Parser (`protocol/http.rs`)
- Uses `httparse` crate (zero-alloc HTTP/1.1 parsing)
- Extracts: method, URI, host, user-agent, content-type, response code
- Populates sticky buffers: `http.method`, `http.uri`, `http.host`, `http.user_agent` (Suricata keyword compatibility)
- Request/response pairing per transaction

### 4.3 — TLS Parser (`protocol/tls.rs`)
- ClientHello parsing: SNI, JA3 fingerprint, ALPN, cipher suites
- ServerHello: JA3S fingerprint, certificate chain
- Integrates with existing `aifw-core/src/tls.rs` JA3 types
- Sticky buffers: `tls.sni`, `tls.ja3`, `tls.version`

### 4.4 — DNS Parser (`protocol/dns.rs`)
- Query/response parsing: qname, qtype, rdata, rcode
- Sticky buffers: `dns.query`, `dns.opcode`
- Feeds into existing DNS tunnel detector in `aifw-ai`

### 4.5 — SSH Parser (`protocol/ssh.rs`)
- Banner extraction, key exchange detection
- Sticky buffers: `ssh.software`, `ssh.proto`

### 4.6 — SMTP Parser (`protocol/smtp.rs`)
- Command/response parsing, MAIL FROM/RCPT TO extraction
- Sticky buffers: `smtp.mail_from`, `smtp.rcpt_to`, `smtp.helo`

**Files**: `aifw-ids/src/protocol/`

---

## Phase 5: Rule Engine — Suricata Rule Parser

**Goal**: Parse and compile ET Open / Suricata-format rules into an optimized in-memory representation.

### 5.1 — Suricata Rule Parser (`rules/suricata.rs`)
Parse the Suricata rule format:
```
action proto src_addr src_port -> dst_addr dst_port (options;)
```

**Rule header parsing**:
- action: alert, drop, reject, pass
- proto: tcp, udp, icmp, ip, http, dns, tls, ssh, smtp
- addresses: $HOME_NET, $EXTERNAL_NET, IP ranges, CIDR, negation (!)
- ports: single, range, list, negation, any
- direction: `->` (to server), `<>` (bidirectional)

**Rule option keywords to support (priority order)**:

| Category | Keywords |
|----------|----------|
| **Meta** | msg, sid, rev, classtype, priority, reference, metadata |
| **Payload** | content, nocase, depth, offset, distance, within, fast_pattern, pcre |
| **Flow** | flow (established, to_server, to_client, stateless) |
| **HTTP** | http_method, http_uri, http_host, http_user_agent, http_header, http_cookie, http_content_type, http_response_body |
| **TLS** | tls.sni, tls.version, ja3.hash |
| **DNS** | dns.query, dns.opcode |
| **IP** | ipopts, ip_proto, ttl, itype, icode |
| **Threshold** | threshold (type limit/threshold/both, track by_src/by_dst, count, seconds) |
| **Flowbits** | flowbits (set, isset, unset, toggle, noalert) |

### 5.2 — Rule Compilation (`rules/mod.rs`)
- Parse raw rule text → `ParsedRule` intermediate
- Extract all `content` keywords → feed to Aho-Corasick builder
- Extract all `pcre` keywords → feed to Hyperscan compiler
- Build `CompiledRuleset`:
  ```rust
  pub struct CompiledRuleset {
      pub rules: Vec<CompiledRule>,
      pub content_matcher: AhoCorasick,          // all content strings
      pub content_to_rules: Vec<Vec<usize>>,     // content match → rule indices
      pub regex_db: Option<hyperscan::Database>,  // all pcre patterns compiled together
      pub regex_to_rules: Vec<Vec<usize>>,        // regex match → rule indices
  }
  ```
- `fast_pattern` keyword selects which content goes to the prefilter
- Rules without content/pcre are added to a linear scan list (rare, kept small)

### 5.3 — Variable Expansion
- `$HOME_NET`, `$EXTERNAL_NET`, `$HTTP_SERVERS`, `$DNS_SERVERS`, etc.
- Configurable via `IdsConfig`, stored in `ids_config` table
- Expanded at rule compile time, re-compile on config change

**Files**: `aifw-ids/src/rules/suricata.rs`, `aifw-ids/src/rules/mod.rs`

---

## Phase 6: Rule Engine — Sigma & YARA

**Goal**: Add Sigma (log-based detection) and YARA (payload pattern matching) rule support.

### 6.1 — Sigma Rules (`rules/sigma.rs`)
- Parse Sigma YAML format using `serde_yaml`
- Map Sigma detection logic (keywords, conditions, modifiers) to internal matcher
- Sigma fields map to: network events, flow metadata, protocol fields
- Sigma rules are lower volume than ET Open — linear evaluation is fine
- Support Sigma modifiers: `contains`, `startswith`, `endswith`, `re`, `all`, `base64`

### 6.2 — YARA Rules (`rules/yara.rs`)
- Use `yara` crate (bindings to libyara)
- Compile YARA rules into a scanner
- Run scanner against reassembled stream content / file extracts
- YARA is heavier — only triggered post-prefilter or on file extraction
- Useful for: malware payloads, document exploits, binary pattern matching

### 6.3 — Unified Rule Database (`rules/mod.rs`)
- `RuleDatabase` manages all three formats
- Each format compiles independently
- Shared `RuleMatch` output type regardless of source format:
  ```rust
  pub struct RuleMatch {
      pub rule_id: String,
      pub sid: Option<u32>,
      pub msg: String,
      pub severity: u8,
      pub source: RuleSource,  // EtOpen, Sigma, Yara, Custom
      pub action: RuleAction,  // Alert, Drop, Reject, Pass
      pub metadata: HashMap<String, String>,
  }
  ```

**Files**: `aifw-ids/src/rules/sigma.rs`, `aifw-ids/src/rules/yara.rs`

---

## Phase 7: Detection Engine

**Goal**: Multi-stage detection pipeline optimized for throughput.

### 7.1 — Detection Pipeline (`detect/mod.rs`)
The hot path — every packet flows through this:

```
1. Prefilter (Aho-Corasick)
   - Run all content strings against payload in ONE pass
   - Returns: set of candidate rule indices
   
2. Rule Evaluation (per candidate)
   - Check flow direction (to_server/to_client)
   - Check protocol match
   - Check address/port match
   - Check content position constraints (depth, offset, distance, within)
   - Check pcre via Hyperscan (only for rules that passed content match)
   - Check threshold/rate tracking
   - Check flowbits state
   
3. Sigma Evaluation (if flow has app-layer data)
   - Evaluate Sigma rules against parsed protocol fields
   
4. YARA Scan (if triggered)
   - Only on reassembled streams or extracted files
   - Not run on every packet
   
5. Verdict
   - Highest-priority matching rule determines action
   - Pass > Drop > Reject > Alert (in priority)
```

### 7.2 — Aho-Corasick Multi-Pattern Matcher (`detect/multi_pattern.rs`)
- Build automaton from all `content` keywords across all rules
- Use `aho_corasick::AhoCorasick` with `MatchKind::Standard`
- Case-insensitive patterns get lowercased at build time, payload lowered at match time only for those rules
- `fast_pattern` designated contents are preferred for the prefilter
- Rebuild on rule reload (background thread, swap with Arc)

### 7.3 — Hyperscan Regex Matcher (`detect/regex.rs`)
- Compile all `pcre` patterns into single Hyperscan database
- Stream mode for patterns that span packet boundaries
- Block mode for per-packet patterns
- Fallback to `regex` crate if Hyperscan unavailable (feature flag)
- Each pattern tagged with rule index for match → rule resolution

### 7.4 — Threshold Tracking
- Per-rule, per-IP rate tracking for `threshold` keyword
- `DashMap<(sid, IpAddr), ThresholdState>` — lock-free
- `type limit`: alert once per time window
- `type threshold`: alert after N hits
- `type both`: alert once after N hits per window
- Automatic expiry of stale entries

### 7.5 — Flowbits
- Per-flow bit flags: `set`, `isset`, `unset`, `toggle`
- Stored in `Flow.flowbits: HashSet<String>`
- Enables multi-rule correlation (rule A sets a bit, rule B checks it)

**Files**: `aifw-ids/src/detect/`

---

## Phase 8: Action Engine & pf Integration

**Goal**: Execute verdicts — alert, drop, reject — with direct pf integration.

### 8.1 — Action Engine (`action/mod.rs`)
- `Verdict` enum: `Pass`, `Alert(RuleMatch)`, `Drop(RuleMatch)`, `Reject(RuleMatch)`
- IDS mode: all verdicts become alerts (log only)
- IPS mode: Drop/Reject verdicts modify packets in the capture backend (netmap inline mode)
- Reject: send TCP RST or ICMP unreachable via raw socket

### 8.2 — pf Integration
- Use existing `PfBackend` trait for table operations
- Auto-block: on Drop verdict, add src_ip to `aifw-ids-block` pf table
- Rate-limit: on repeated alerts from same source, add to `aifw-ids-ratelimit` table
- Tables managed by IDS engine, cleaned up on expiry
- Integrates with existing `AutoResponder` from `aifw-ai` — IDS alerts can trigger the same response actions (temp block, perm block, rate limit)

### 8.3 — AI Correlation
- IDS `RuleMatch` events fed to `aifw-ai` detectors as additional evidence
- New `ThreatType::SignatureMatch` variant in `aifw-ai/src/types.rs`
- AI score boosted when both signature + behavioral detection fire for same source
- Example: ET Open malware signature + C2 beacon pattern from same IP → critical

**Files**: `aifw-ids/src/action/mod.rs`, `aifw-ai/src/types.rs` (add variant)

---

## Phase 9: Alert Output Pipeline

**Goal**: Multi-output alert pipeline with EVE JSON compatibility, SQLite storage, syslog, and WebSocket streaming.

### 9.1 — Alert Output Trait (`output/mod.rs`)
```rust
#[async_trait]
pub trait AlertOutput: Send + Sync {
    async fn emit(&self, alert: &IdsAlert) -> Result<()>;
    async fn flush(&self) -> Result<()>;
}
```
- `AlertPipeline`: holds `Vec<Box<dyn AlertOutput>>`, fans out to all outputs
- Async, non-blocking — uses channel to decouple detection from output
- Bounded channel (crossbeam) — if output can't keep up, oldest alerts dropped with counter

### 9.2 — EVE JSON Output (`output/eve.rs`)
- Suricata-compatible EVE JSON format (one JSON object per line)
- Fields: timestamp, event_type, src_ip, src_port, dest_ip, dest_port, proto, alert.signature_id, alert.signature, alert.severity, alert.category, alert.action, flow_id, app_proto, http/tls/dns metadata
- File rotation: configurable max size + max files
- Output path: `/var/log/aifw/eve.json` (FreeBSD), configurable

### 9.3 — SQLite Output (`output/sqlite.rs`)
- Batch inserts (accumulate N alerts or T milliseconds, then bulk INSERT)
- Automatic retention: delete alerts older than `alert_retention_days`
- Powers the UI alert viewer
- Uses existing `Database` pattern from `aifw-core`

### 9.4 — Syslog Output (`output/syslog.rs`)
- RFC 5424 syslog over UDP/TCP/TLS
- Configurable remote target (ip:port)
- Severity mapping: IDS severity 1 → syslog Emergency, 2 → Alert, 3 → Warning, 4 → Info
- Facility: `LOG_AUTH` or configurable

### 9.5 — WebSocket Output (`output/websocket.rs`)
- Broadcasts alerts to connected WebSocket clients via `tokio::sync::broadcast`
- Integrates with existing `aifw-api` WebSocket infrastructure
- JSON format matching the SQLite alert schema
- Client can filter by severity, source IP, signature ID

**Files**: `aifw-ids/src/output/`

---

## Phase 10: Rule Management & Auto-Update

**Goal**: Download, update, and manage rulesets via the API with automatic updates.

### 10.1 — Ruleset Manager (`rules/manager.rs`)
- Download rulesets from URLs (ET Open: `https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules`)
- Parse downloaded rules, store in `ids_rules` table
- Compile into `CompiledRuleset` and hot-swap (Arc swap)
- Background update task: check for updates per `update_interval_hours`
- Support for: ET Open (free), Abuse.ch, custom rule URLs

### 10.2 — Rule CRUD
- Enable/disable individual rules by SID
- Override rule action (e.g., change alert → drop)
- Add suppression (silence a rule for specific IP/subnet)
- Add custom rules (raw Suricata/Sigma/YARA text)
- Bulk operations: enable/disable entire ruleset, category

### 10.3 — Hot Reload
- Rule changes compile new `CompiledRuleset` in background
- Swap into detection engine via `Arc::swap` — zero downtime
- No packet loss during rule reload

**Files**: `aifw-ids/src/rules/manager.rs`

---

## Phase 11: Multi-Core Pipeline Architecture

**Goal**: Maximize throughput with per-core run-to-completion and zero cross-core contention.

### 11.1 — Worker Architecture
```
                    ┌─────────────────────────────────┐
                    │      Control Plane (tokio)       │
                    │  Rule reload, config, API, output│
                    └──────────────┬──────────────────┘
                                   │ Arc<CompiledRuleset>
                    ┌──────────────▼──────────────────┐
        ┌───────────┤      Shared State (lock-free)    ├──────────┐
        │           │  FlowTable, ThresholdMap, Config  │          │
        │           └──────────────────────────────────┘          │
        │                                                          │
   ┌────▼─────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
   │ Worker 0 │  │ Worker 1 │  │ Worker 2 │  │ Worker N │
   │ (Core 0) │  │ (Core 1) │  │ (Core 2) │  │ (Core N) │
   │ capture  │  │ capture  │  │ capture  │  │ capture  │
   │ decode   │  │ decode   │  │ decode   │  │ decode   │
   │ flow     │  │ flow     │  │ flow     │  │ flow     │
   │ detect   │  │ detect   │  │ detect   │  │ detect   │
   │ verdict  │  │ verdict  │  │ verdict  │  │ verdict  │
   └──────────┘  └──────────┘  └──────────┘  └──────────┘
        │              │              │              │
        └──────────────┴──────┬───────┴──────────────┘
                              │ crossbeam channel
                    ┌─────────▼───────────┐
                    │   Alert Pipeline    │
                    │ EVE/SQLite/Syslog/WS│
                    └─────────────────────┘
```

### 11.2 — Implementation
- Each worker is a dedicated OS thread (not tokio task) — pinned to CPU core via `core_affinity`
- RSS (Receive Side Scaling) or netmap multi-ring distributes packets across workers by flow hash
- Workers share: `Arc<CompiledRuleset>`, `Arc<DashMap<FlowKey, Flow>>`, `Arc<DashMap<ThresholdKey, ThresholdState>>`
- Workers produce alerts into a `crossbeam::channel::bounded` — consumed by async output pipeline
- Arena allocator (`bumpalo`) per worker — allocate per batch, reset after batch

### 11.3 — Maximum Throughput Design Principles
Every design decision optimizes for line-rate operation:

**Zero-copy pipeline**:
- Packets are mmap'd from capture backend — never copied between stages
- `DecodedPacket` holds `&[u8]` slices into the original mmap'd buffer
- Protocol parsers reference payload slices, never allocate strings
- Alert metadata is the only allocation in the hot path

**Batch processing**:
- Workers process packets in batches of 64 (configurable)
- Batch amortizes per-packet overhead (function calls, branch mispredicts)
- Better CPU cache utilization — sequential memory access pattern
- Prefetch next batch while processing current (`_mm_prefetch` via `std::arch`)

**SIMD acceleration**:
- `memchr` crate for fast byte scanning (AVX2/SSE4.2 on x86, NEON on ARM)
- Aho-Corasick Teddy algorithm uses SIMD for small pattern sets
- Hyperscan uses AVX2/AVX-512 for regex matching
- Protocol probing: vectorized magic byte detection

**Compiler optimization**:
- `#[inline(always)]` on hot path functions (decode, flow lookup, prefilter)
- `likely`/`unlikely` branch hints via `std::intrinsics` or `cold` attributes
- LTO (Link-Time Optimization) enabled in release profile
- PGO (Profile-Guided Optimization) build target using captured traffic
- `target-cpu=native` for production builds

**Memory design**:
- Per-worker `bumpalo` arena — allocate per batch, reset after batch (zero free calls)
- Pre-allocated flow table — sized at startup, no runtime growth
- Pre-allocated reassembly buffers — pool of fixed-size buffers
- `SmallVec` for rule match candidates (stack-allocated for typical case)
- Avoid `HashMap` in hot path — use perfect hashing or direct indexing

**Scaling**:
- Linear scaling with CPU cores — no shared mutable state between workers
- RSS/Flow Director distributes packets by flow hash at NIC level
- Each worker owns its netmap/AF_PACKET ring — no contention
- Alert output is the only cross-worker channel (bounded, non-blocking, lossy under pressure)

**DPDK backend** (optional, for highest throughput):
- Kernel bypass — zero syscalls per packet
- Hugepage memory — no TLB misses
- Poll-mode driver — no interrupt overhead
- `capsule-rs` or raw DPDK FFI bindings
- Enabled via `--features dpdk` cargo feature flag

**Expected throughput range** (with full ET Open ~30K rules):
- pcap backend (dev): 1-5 Gbps (kernel overhead)
- netmap backend (FreeBSD): 10-40 Gbps depending on core count
- DPDK backend (optional): 40-100+ Gbps on modern NICs

**Files**: `aifw-ids/src/lib.rs` (worker orchestration)

---

## Phase 12: API Integration

**Goal**: Add IDS management endpoints to the existing Axum API.

### 12.1 — New API Module (`aifw-api/src/ids.rs`)

**Configuration endpoints**:
- `GET /api/v1/ids/config` — get IDS configuration
- `PUT /api/v1/ids/config` — update configuration (mode, home_net, interfaces, etc.)
- `POST /api/v1/ids/reload` — trigger rule reload

**Alert endpoints**:
- `GET /api/v1/ids/alerts` — list alerts (paginated, filterable by severity, src_ip, sid, time range)
- `GET /api/v1/ids/alerts/:id` — get single alert
- `PUT /api/v1/ids/alerts/:id/acknowledge` — acknowledge alert
- `DELETE /api/v1/ids/alerts` — purge old alerts
- `GET /api/v1/ids/alerts/stream` — SSE stream of real-time alerts

**Ruleset endpoints**:
- `GET /api/v1/ids/rulesets` — list configured rulesets
- `POST /api/v1/ids/rulesets` — add a ruleset (URL + format)
- `PUT /api/v1/ids/rulesets/:id` — update ruleset config
- `DELETE /api/v1/ids/rulesets/:id` — remove ruleset
- `POST /api/v1/ids/rulesets/:id/update` — trigger manual update

**Rule endpoints**:
- `GET /api/v1/ids/rules` — list rules (paginated, filterable by ruleset, enabled, sid)
- `GET /api/v1/ids/rules/:id` — get single rule
- `PUT /api/v1/ids/rules/:id` — toggle enable/disable, override action
- `GET /api/v1/ids/rules/search?q=` — search rules by msg/sid

**Suppression endpoints**:
- `GET /api/v1/ids/suppressions` — list suppressions
- `POST /api/v1/ids/suppressions` — add suppression
- `DELETE /api/v1/ids/suppressions/:id` — remove suppression

**Stats endpoint**:
- `GET /api/v1/ids/stats` — packets inspected, alerts/sec, drops/sec, top signatures, top sources

### 12.2 — AppState Addition
Add to `aifw-api/src/main.rs`:
```rust
pub ids_engine: Arc<IdsEngine>,
```

### 12.3 — Plugin Hooks
Add new hook points to `aifw-plugins/src/hooks.rs`:
- `IdsAlert` — fires on every IDS alert (plugins can enrich, suppress, or trigger actions)
- `IdsDrop` — fires when IPS mode drops a packet

**Files**: `aifw-api/src/ids.rs` (new), `aifw-api/src/main.rs`, `aifw-plugins/src/hooks.rs`

---

## Phase 13: Web UI

**Goal**: Add IDS pages to the NextJS web interface.

### 13.1 — IDS Dashboard (`aifw-ui/src/app/ids/page.tsx`)
- Real-time alert feed (WebSocket)
- Alert severity breakdown (pie/bar chart)
- Top 10 alerting signatures
- Top 10 source IPs
- Packets/sec and alerts/sec gauges
- IDS mode toggle (IDS/IPS/Disabled)

### 13.2 — Alerts Page (`aifw-ui/src/app/ids/alerts/page.tsx`)
- Filterable data table: severity, source, destination, signature, time range
- Click to expand: full alert detail, payload hex dump, flow info
- Bulk acknowledge
- One-click: suppress rule, block source IP

### 13.3 — Rules Page (`aifw-ui/src/app/ids/rules/page.tsx`)
- Browse rules by ruleset/category
- Search by SID, message text
- Toggle enable/disable per rule
- Override action (alert → drop or vice versa)
- Rule hit count display

### 13.4 — Rulesets Page (`aifw-ui/src/app/ids/rulesets/page.tsx`)
- List configured rulesets (ET Open, Sigma, YARA, custom)
- Add/remove rulesets
- Enable/disable, configure auto-update interval
- Manual update trigger with progress

### 13.5 — Settings Page (`aifw-ui/src/app/ids/settings/page.tsx`)
- IDS mode (IDS/IPS/Disabled)
- Network variables ($HOME_NET, $EXTERNAL_NET, etc.)
- Monitored interfaces
- Alert retention
- EVE log toggle and path
- Syslog target configuration
- Performance tuning (worker count, flow table size, stream depth)

### 13.6 — Navigation
- Add "Intrusion Detection" section to sidebar in `AppShell` component
- Sub-items: Dashboard, Alerts, Rules, Rulesets, Settings

**Files**: `aifw-ui/src/app/ids/` (new directory tree), `aifw-ui/src/components/AppShell.tsx`

---

## Phase 14: Daemon Integration

**Goal**: Integrate IDS engine lifecycle into the existing `aifw-daemon`.

### 14.1 — Daemon Changes (`aifw-daemon/src/main.rs`)
- Initialize `IdsEngine` with config from database
- Start IDS worker threads
- Start rule auto-update background task
- Start alert retention cleanup task
- Graceful shutdown: stop workers, flush alerts, save state
- Health check: report IDS worker status

### 14.2 — Configuration Persistence
- IDS config stored in `ids_config` SQLite table
- On startup: load config → compile rules → start workers
- On config change via API: recompile if needed, restart affected components

**Files**: `aifw-daemon/src/main.rs`

---

## Phase 15: Testing

**Goal**: Comprehensive testing at every layer.

### 15.1 — Unit Tests
- Rule parser: test all Suricata keyword combinations with real ET Open rule samples
- Sigma parser: test with official Sigma rule examples
- YARA: test with sample YARA rules
- Protocol parsers: test with captured packet samples
- Flow tracking: test state transitions, timeout, reassembly
- Detection engine: test prefilter → full match pipeline
- Action engine: test verdict determination

### 15.2 — Integration Tests
- Full pipeline test: pcap file → capture → detect → alert output
- Use real ET Open rules against known-malicious pcap samples
- Verify EVE JSON output compatibility (validate against Suricata EVE schema)
- API integration tests following existing `axum_test::TestServer` pattern

### 15.3 — Performance Tests
- Benchmark: packets/sec per worker with ET Open ruleset
- Benchmark: Aho-Corasick build time for 30K+ content strings
- Benchmark: Hyperscan compile time for all pcre patterns
- Benchmark: flow table operations at scale (1M+ concurrent flows)
- Profile with `perf` / `flamegraph` to identify bottlenecks

### 15.4 — pcap Replay Testing
- Use `tcpreplay` against the capture interface
- Test with public malicious pcap datasets (malware-traffic-analysis.net)
- Verify detection matches expected Suricata alerts for same traffic

**Files**: Tests within each module + `aifw-ids/tests/` integration test directory

---

## Phase 16: Documentation & Polish

### 16.1 — README Updates
- Update main README with IDS feature description
- Add IDS configuration section
- Add rule management section

### 16.2 — CLAUDE.md Updates
- Add `aifw-ids` to crate dependency flow
- Document new API endpoints
- Add IDS-specific build/test commands

### 16.3 — Flow.md Updates
- Add IDS packet processing flow diagram
- Add IDS ↔ AI correlation flow diagram

---

## Implementation Order & Dependencies

```
Phase 1  (Foundation)        ← START HERE
   ↓
Phase 2  (Capture & Decode)  ← can develop independently
Phase 3  (Flow Tracking)     ← depends on Phase 2
   ↓
Phase 4  (Protocol Parsers)  ← depends on Phase 3
Phase 5  (Suricata Rules)    ← can develop in parallel with Phase 4
Phase 6  (Sigma & YARA)      ← depends on Phase 5 (shared interfaces)
   ↓
Phase 7  (Detection Engine)  ← depends on Phases 4, 5, 6
Phase 8  (Actions + pf)      ← depends on Phase 7
Phase 9  (Alert Outputs)     ← depends on Phase 8
   ↓
Phase 10 (Rule Management)   ← depends on Phase 5
Phase 11 (Multi-Core)        ← depends on Phase 7
   ↓
Phase 12 (API)               ← depends on Phases 8, 9, 10
Phase 13 (Web UI)            ← depends on Phase 12
Phase 14 (Daemon)            ← depends on Phase 12
   ↓
Phase 15 (Testing)           ← ongoing throughout, formal at end
Phase 16 (Documentation)     ← final phase
```

## Key Dependencies (Crates)

| Crate | Version | Purpose | License |
|-------|---------|---------|---------|
| `etherparse` | 0.16 | Zero-alloc packet parsing | MIT/Apache-2.0 |
| `pcap` | 2 | libpcap bindings (dev capture) | MIT/Apache-2.0 |
| `aho-corasick` | 1 | Multi-pattern string matching | MIT/Unlicense |
| `hyperscan` | 0.4 | Intel regex engine FFI | MIT |
| `regex` | 1 | Fallback regex (if no Hyperscan) | MIT/Apache-2.0 |
| `httparse` | 1 | Zero-alloc HTTP parsing | MIT/Apache-2.0 |
| `dns-parser` | 0.8 | DNS packet parsing | MIT/Apache-2.0 |
| `yara` | 0.28 | YARA rule bindings | MIT |
| `crossbeam` | 0.8 | Lock-free channels/queues | MIT/Apache-2.0 |
| `dashmap` | 6 | Concurrent hashmap | MIT |
| `bumpalo` | 3 | Arena allocator | MIT/Apache-2.0 |
| `syslog` | 7 | Syslog output | MIT |
| `core_affinity` | 0.8 | CPU pinning | MIT |
| `memchr` | 2 | SIMD byte scanning | MIT/Unlicense |
| `smallvec` | 1 | Stack-allocated small vectors | MIT/Apache-2.0 |

All free and open source — no paid crates.

## Files Modified in Existing Crates

| File | Change |
|------|--------|
| `Cargo.toml` | Add `aifw-ids` to workspace members |
| `aifw-common/src/lib.rs` | Add `pub mod ids;` and re-exports |
| `aifw-common/src/ids.rs` | New file — IDS shared types |
| `aifw-ai/src/types.rs` | Add `ThreatType::SignatureMatch` variant |
| `aifw-plugins/src/hooks.rs` | Add `IdsAlert`, `IdsDrop` hook points |
| `aifw-api/src/main.rs` | Add `ids_engine` to AppState, mount IDS routes |
| `aifw-api/src/ids.rs` | New file — IDS API endpoints |
| `aifw-daemon/src/main.rs` | Initialize and manage IDS engine lifecycle |
| `aifw-ui/src/components/AppShell.tsx` | Add IDS nav items |
| `aifw-ui/src/app/ids/` | New directory — all IDS UI pages |
| `README.md` | Document IDS features |
| `CLAUDE.md` | Document IDS crate, endpoints, commands |
| `Flow.md` | Add IDS architecture diagrams |
