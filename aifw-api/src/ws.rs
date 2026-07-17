use axum::{
    extract::{
        State, WebSocketUpgrade,
        ws::{Message, WebSocket},
    },
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use std::collections::VecDeque;
use std::time::Duration;

use crate::AppState;
use aifw_common::RuleStatus;

#[derive(Serialize)]
struct WsStatusUpdate {
    #[serde(rename = "type")]
    msg_type: &'static str,
    status: StatusPayload,
    system: SystemPayload,
    connections: Vec<ConnectionPayload>,
    interfaces: Vec<InterfacePayload>,
    blocked: Vec<BlockedPayload>,
    services: Vec<ServiceStatusPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    vpn: Option<Vec<VpnTunnelStatus>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ids: Option<IdsStatusPayload>,
}

#[derive(Serialize, Clone)]
struct VpnTunnelStatus {
    id: String,
    name: String,
    interface_name: String,
    running: bool,
    peers: Vec<VpnPeerStatus>,
}

#[derive(Serialize, Clone)]
struct VpnPeerStatus {
    public_key: String,
    endpoint: Option<String>,
    latest_handshake_secs_ago: i64,
    transfer_rx: u64,
    transfer_tx: u64,
}

#[derive(Serialize, Clone)]
struct IdsStatusPayload {
    running: bool,
    mode: String,
    loaded_rules: u32,
    alerts_total: u64,
    drops_total: u64,
    packets_inspected: u64,
    packets_per_sec: f64,
    bytes_per_sec: f64,
    active_flows: u64,
    recent_alerts: Vec<IdsAlertSummary>,
}

#[derive(Serialize, Clone)]
struct IdsAlertSummary {
    severity: u8,
    signature_msg: String,
    src_ip: String,
    dst_ip: String,
    protocol: String,
    timestamp: String,
}

#[derive(Serialize, Clone)]
struct ServiceStatusPayload {
    name: String,
    running: bool,
    enabled: bool,
}

#[derive(Serialize, Clone)]
struct BlockedPayload {
    timestamp: String,
    action: String,
    direction: String,
    interface: String,
    protocol: String,
    src_addr: String,
    src_port: u16,
    dst_addr: String,
    dst_port: u16,
}

#[derive(Serialize, Clone)]
struct SystemPayload {
    cpu_usage: f64,
    cpu_cores: u32,
    memory_total: u64,
    memory_used: u64,
    memory_pct: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    memory_breakdown: Option<MemoryBreakdown>,
    disks: Vec<DiskPayload>,
    disk_io: DiskIoPayload,
    uptime_secs: u64,
    hostname: String,
    os_version: String,
    dns_servers: Vec<String>,
    default_gateway: String,
    route_count: usize,
}

#[derive(Serialize, Clone)]
pub struct MemoryBreakdown {
    // OS-level memory categories (MB)
    pub active_mb: f64,
    pub inactive_mb: f64,
    pub wired_mb: f64,
    pub cached_mb: f64,
    pub free_mb: f64,
    // AiFw process memory
    pub api_rss_mb: f64,
    pub daemon_rss_mb: f64,
    // IDS alert buffer
    pub ids_buffer_mb: f64,
    pub ids_buffer_max_mb: f64,
    pub ids_buffer_count: usize,
    // Dashboard metrics history
    pub metrics_history_count: usize,
    pub metrics_history_mb: f64,
    // pf state table
    pub pf_states: u64,
    pub pf_states_max: u64,
    // Database
    pub db_size_mb: f64,
    // ZFS ARC cache
    pub arc_mb: f64,
}

#[derive(Serialize, Clone, Default)]
struct DiskIoPayload {
    reads_per_sec: f64,
    writes_per_sec: f64,
    read_kbps: f64,
    write_kbps: f64,
}

#[derive(Serialize, Clone)]
struct DiskPayload {
    mount: String,
    filesystem: String,
    total: u64,
    used: u64,
    pct: f64,
}

#[derive(Serialize, Clone)]
struct StatusPayload {
    pf_running: bool,
    pf_states: u64,
    pf_rules: u64,
    aifw_rules: usize,
    aifw_active_rules: usize,
    nat_rules: usize,
    packets_in: u64,
    packets_out: u64,
    bytes_in: u64,
    bytes_out: u64,
}

#[derive(Serialize)]
struct ConnectionPayload {
    protocol: String,
    src_addr: String,
    src_port: u16,
    dst_addr: String,
    dst_port: u16,
    state: String,
    bytes_in: u64,
    bytes_out: u64,
}

#[derive(Serialize, Clone)]
struct InterfacePayload {
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subnet: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    role: Option<String>,
    bytes_in: u64,
    bytes_out: u64,
    packets_in: u64,
    packets_out: u64,
}

/// Slim version stored in metrics_history — excludes blocked/connections to avoid
/// unbounded memory growth (10k blocked × 1800 history = multi-GB leak).
#[derive(Serialize)]
struct WsHistoryEntry {
    #[serde(rename = "type")]
    msg_type: &'static str,
    status: StatusPayload,
    system: SystemPayload,
    interfaces: Vec<InterfacePayload>,
    services: Vec<ServiceStatusPayload>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ids: Option<IdsHistoryPayload>,
}

/// Slim IDS counters for history (no alerts list).
#[derive(Serialize, Clone)]
struct IdsHistoryPayload {
    alerts_total: u64,
    drops_total: u64,
    packets_inspected: u64,
    packets_per_sec: f64,
    active_flows: u64,
    running: bool,
}

/// Deflate-compress one history JSON frame for the in-memory ring
/// (PERF-M5). The frames are highly repetitive JSON (~2-3 KB) and compress
/// 4-8x, cutting the 1800-entry ring from ~5 MB to ~1 MB of process heap.
pub fn compress_history_entry(json: &str) -> Vec<u8> {
    use std::io::Write;
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::fast());
    // Writing into a Vec is infallible; finish() only propagates write errors.
    match enc.write_all(json.as_bytes()).and_then(|_| enc.finish()) {
        Ok(buf) => buf,
        Err(e) => {
            tracing::warn!(error = %e, "failed to compress metrics history entry");
            Vec::new()
        }
    }
}

/// Inverse of `compress_history_entry`. Returns `None` (with a warning) on
/// corrupt data so one bad entry can't take down the history batch.
fn decompress_history_entry(data: &[u8]) -> Option<String> {
    use std::io::Read;
    let mut out = String::new();
    match flate2::read::DeflateDecoder::new(data).read_to_string(&mut out) {
        Ok(_) => Some(out),
        Err(e) => {
            tracing::warn!(error = %e, "failed to decompress metrics history entry");
            None
        }
    }
}

pub async fn ws_handler(State(state): State<AppState>, ws: WebSocketUpgrade) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();

    // Send a bounded slice of historical data so the frontend sets
    // historyLoaded=true. Cap at INITIAL_HISTORY_SAMPLES so a long
    // ring buffer (e.g. 24 h at 1 Hz) doesn't ship multi-MB JSON to
    // every reconnecting client.
    const INITIAL_HISTORY_SAMPLES: usize = 600; // ~10 minutes at 1 Hz
    {
        // Clone the (small) compressed entries under the read lock, then
        // decompress after releasing it so the producer's write never waits
        // behind the inflate work (PERF-M5).
        let compressed: Vec<Vec<u8>> = {
            let history = state.metrics_history.read().await;
            let skip = history.len().saturating_sub(INITIAL_HISTORY_SAMPLES);
            history.iter().skip(skip).cloned().collect()
        };
        let batch = if compressed.is_empty() {
            "{\"type\":\"history\",\"data\":[]}".to_string()
        } else {
            let mut out = String::with_capacity(compressed.len() * 2048 + 32);
            out.push_str("{\"type\":\"history\",\"data\":[");
            let mut first = true;
            for entry in &compressed {
                if let Some(json) = decompress_history_entry(entry) {
                    if !first {
                        out.push(',');
                    }
                    out.push_str(&json);
                    first = false;
                }
            }
            out.push_str("]}");
            out
        };
        let _ = sender.send(Message::Text(batch.into())).await;
    }

    // Subscribe to the global per-tick broadcast (#178). The dashboard
    // producer task builds `live_msg` once per tick and publishes it here;
    // we just forward. No more per-client `build_update` cloning the full
    // pf state table.
    let mut tick_rx = state.ws_tick.subscribe();
    let mut cluster_rx = state.cluster_events.subscribe();
    let mut push_task = tokio::spawn(async move {
        loop {
            tokio::select! {
                msg = tick_rx.recv() => {
                    match msg {
                        Ok(arc_msg) => {
                            if sender.send(Message::Text((*arc_msg).clone().into())).await.is_err() {
                                break;
                            }
                        }
                        // We dropped frames because we couldn't keep up.
                        // Don't disconnect — wait for the next tick.
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                ev = cluster_rx.recv() => {
                    match ev {
                        Ok(ev) => {
                            let frame = serde_json::json!({"channel": "cluster", "event": ev});
                            if sender.send(Message::Text(frame.to_string().into())).await.is_err() {
                                break;
                            }
                        }
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(_) => break,
                    }
                }
            }
        }
    });

    // Receive messages (handle client disconnect)
    let mut recv_task = tokio::spawn(async move {
        while let Some(Ok(msg)) = receiver.next().await {
            if let Message::Close(_) = msg {
                break;
            }
            // Client can send ping/pong, we just ignore other messages
        }
    });

    // Wait for either task to finish (client disconnect)
    tokio::select! {
        _ = &mut push_task => { recv_task.abort(); }
        _ = &mut recv_task => { push_task.abort(); }
    }
}

/// Single global producer for the per-tick dashboard payload (#178).
///
/// Pre-fix every connected WS client called `build_update` independently —
/// each one cloned the full `Vec<PfState>` and rebuilt identical JSON.
/// At 50k states × 10 clients that was 500k state clones / sec on the API
/// process. Now this task runs once per tick, builds the payload, writes
/// it to the metrics-history ring + Valkey *once*, and broadcasts the
/// `Arc<String>` to every subscriber.
///
/// Tick interval scales with state-table size: 1 Hz under 5k states (the
/// common case — snappy dashboard), 5 s above that (heavy load — protect
/// the box from busy-looping over a giant table).
pub async fn run_dashboard_producer(state: AppState) {
    use std::sync::Arc;
    use std::time::Instant;

    const HEAVY_STATE_THRESHOLD: u64 = 5_000;
    const FAST_INTERVAL: Duration = Duration::from_secs(1);
    const SLOW_INTERVAL: Duration = Duration::from_secs(5);

    let mut next_at = Instant::now() + FAST_INTERVAL;
    loop {
        tokio::time::sleep_until(tokio::time::Instant::from_std(next_at)).await;

        // Skip the heavy build when nobody's listening AND there's no
        // history to populate. metrics_history matters even with zero
        // current clients — reconnects need it — so we always tick when
        // there's a non-zero history retention. If the whole feature is
        // off (max == 0) and no clients, skip.
        let max = state
            .metrics_history_max
            .load(std::sync::atomic::Ordering::Relaxed);
        let have_subscribers = state.ws_tick.receiver_count() > 0;
        if !have_subscribers && max == 0 {
            next_at = Instant::now() + FAST_INTERVAL;
            continue;
        }

        let started = Instant::now();
        match build_update(&state).await {
            Ok((live_msg, history_msg)) => {
                // Slim history → Valkey (so the ring survives process
                // restart when configured) and the in-memory ring buffer
                // (so reconnects can backfill the dashboard).
                if let Some(ref redis) = state.redis {
                    let mut conn = redis.clone();
                    let _: Result<(), _> = redis::pipe()
                        .cmd("LPUSH")
                        .arg("aifw:metrics:history")
                        .arg(&history_msg)
                        .cmd("LTRIM")
                        .arg("aifw:metrics:history")
                        .arg(0i64)
                        .arg(max as i64 - 1)
                        .query_async(&mut conn)
                        .await;
                }
                // PERF-H10 (#354): the entry moves into the deque — the
                // write() critical section is only O(1) pop/push, so WS
                // connects reading the history don't stall behind a large
                // String clone (tokio's fair RwLock queues new readers
                // behind a waiting writer). Compression happens before the
                // lock is taken (PERF-M5).
                if max > 0 {
                    let compressed = compress_history_entry(&history_msg);
                    let mut buf = state.metrics_history.write().await;
                    while buf.len() >= max {
                        buf.pop_front();
                    }
                    buf.push_back(compressed);
                }
                // Live frame to dashboard clients. `send` errors only if
                // there are no subscribers, which is fine — we wanted to
                // populate history regardless.
                let _ = state.ws_tick.send(Arc::new(live_msg));
            }
            Err(e) => {
                tracing::debug!(error = %e, "ws producer build_update failed");
            }
        }

        // Throttle when we're sitting on a giant state table. Use the
        // value from the build we just did (cheap: cached on the tracker).
        let pf_states = state.conntrack.total_count().await as u64;
        let interval = if pf_states > HEAVY_STATE_THRESHOLD {
            SLOW_INTERVAL
        } else {
            FAST_INTERVAL
        };
        // Drift correction: schedule the next tick based on the start of
        // *this* one, not the end. Keeps the cadence stable when a build
        // takes longer than expected; falls back to "interval from now" if
        // the build blew past the budget.
        next_at = (started + interval).max(Instant::now());
    }
}

async fn build_update(state: &AppState) -> Result<(String, String), String> {
    let stats = state.pf.get_stats().await.map_err(|e| e.to_string())?;
    let rules = state
        .rule_engine
        .list_rules()
        .await
        .map_err(|e| e.to_string())?;
    let active = rules
        .iter()
        .filter(|r| r.status == RuleStatus::Active)
        .count();
    let nat_rules = state
        .nat_engine
        .list_rules()
        .await
        .map_err(|e| e.to_string())?;

    // conntrack snapshot — refreshed by the background polling task started
    // at boot, so this is an atomic ArcSwap load (no syscall, no clone).
    let conns = state.conntrack.snapshot();

    // Dispatch plugin hooks for new/closed connections. Skipped entirely when
    // no plugins are running — previously we paid for the HashSet diff
    // (50k connections × format!() × 2) every tick even with zero plugins.
    type ConnKey = (std::net::IpAddr, u16, std::net::IpAddr, u16);
    {
        use std::collections::HashSet;
        // PERF-H17 (#361): snapshot the running plugins under a short read
        // lock; all dispatching below happens without the manager lock.
        let plugins = state.plugin_manager.read().await.dispatch_set();
        if !plugins.is_empty() {
            static PREV_CONNS: std::sync::OnceLock<tokio::sync::RwLock<HashSet<ConnKey>>> =
                std::sync::OnceLock::new();
            let prev_lock = PREV_CONNS.get_or_init(|| tokio::sync::RwLock::new(HashSet::new()));

            let current_keys: HashSet<ConnKey> = conns
                .iter()
                .map(|c| (c.src_addr, c.src_port, c.dst_addr, c.dst_port))
                .collect();
            let prev_keys = prev_lock.read().await.clone();

            for c in conns.iter() {
                let key = (c.src_addr, c.src_port, c.dst_addr, c.dst_port);
                if !prev_keys.contains(&key) {
                    let event = aifw_plugins::HookEvent {
                        hook: aifw_plugins::HookPoint::ConnectionNew,
                        data: aifw_plugins::hooks::HookEventData::Connection {
                            src_ip: c.src_addr,
                            dst_ip: c.dst_addr,
                            src_port: c.src_port,
                            dst_port: c.dst_port,
                            protocol: c.protocol.clone(),
                            state: c.state.clone(),
                        },
                    };
                    let actions = plugins.dispatch(&event).await;
                    for action in actions {
                        if let aifw_plugins::HookAction::AddToTable { ref table, ip } = action {
                            let _ = state.pf.add_table_entry(table, ip).await;
                        }
                    }
                }
            }
            // Closed connections — tuple keys mean no string-parse fallback.
            for &(src_ip, src_port, dst_ip, dst_port) in &prev_keys {
                if !current_keys.contains(&(src_ip, src_port, dst_ip, dst_port)) {
                    let event = aifw_plugins::HookEvent {
                        hook: aifw_plugins::HookPoint::ConnectionClosed,
                        data: aifw_plugins::hooks::HookEventData::Connection {
                            src_ip,
                            dst_ip,
                            src_port,
                            dst_port,
                            protocol: String::new(),
                            state: "closed".to_string(),
                        },
                    };
                    let _ = plugins.dispatch(&event).await;
                }
            }
            *prev_lock.write().await = current_keys;
        }
    }

    let connections: Vec<ConnectionPayload> = conns
        .iter()
        .map(|c| ConnectionPayload {
            protocol: c.protocol.clone(),
            src_addr: c.src_addr.to_string(),
            src_port: c.src_port,
            dst_addr: c.dst_addr.to_string(),
            dst_port: c.dst_port,
            state: c.state.clone(),
            bytes_in: c.bytes_in,
            bytes_out: c.bytes_out,
        })
        .collect();

    // --- System metrics ---
    let mut system = collect_system_metrics().await;

    // Memory breakdown — refreshed every 10 ticks (~10s)
    static MEM_CACHE: tokio::sync::OnceCell<tokio::sync::RwLock<Option<MemoryBreakdown>>> =
        tokio::sync::OnceCell::const_new();
    let mem_cache = MEM_CACHE
        .get_or_init(|| async { tokio::sync::RwLock::new(None) })
        .await;
    static MEM_TICK: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    let mem_tick = MEM_TICK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if mem_tick.is_multiple_of(10) {
        let breakdown = collect_memory_breakdown(state).await;
        *mem_cache.write().await = Some(breakdown);
    }
    system.memory_breakdown = mem_cache.read().await.clone();

    // Get per-interface byte counters via netstat -I; addresses come from
    // native getifaddrs (single C-library walk instead of one ifconfig fork
    // per interface).
    let mut interfaces = Vec::new();
    let iface_infos = crate::native_metrics::iface_list();

    // Load interface roles (cached every 30 ticks)
    static IFACE_TICK: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    static ROLE_CACHE: tokio::sync::OnceCell<
        tokio::sync::RwLock<std::collections::HashMap<String, String>>,
    > = tokio::sync::OnceCell::const_new();
    let role_cache = ROLE_CACHE
        .get_or_init(|| async { tokio::sync::RwLock::new(std::collections::HashMap::new()) })
        .await;
    let iface_tick = IFACE_TICK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if iface_tick.is_multiple_of(30) {
        let roles: Vec<(String, String)> =
            sqlx::query_as("SELECT interface_name, role FROM interface_roles")
                .fetch_all(&state.pool)
                .await
                .unwrap_or_default();
        *role_cache.write().await = roles.into_iter().collect();
    }
    let roles = role_cache.read().await;

    for info in &iface_infos {
        let iface_name = info.name.as_str();
        if iface_name.starts_with("lo")
            || iface_name.starts_with("pflog")
            || iface_name.starts_with("enc")
            || iface_name.starts_with("pfsync")
        {
            continue;
        }

        let address = info.address.clone();
        let subnet = info.subnet.clone();
        let role = roles.get(iface_name).cloned();

        if let Ok(output) = tokio::process::Command::new("netstat")
            .args(["-I", iface_name, "-b", "-n"])
            .output()
            .await
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            // Format: Name Mtu Network Address Ipkts Ierrs Idrop Ibytes Opkts Oerrs Obytes Coll
            // Index:  0    1   2       3       4     5     6     7      8     9     10     11
            for line in stdout.lines().skip(1) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 11 && parts[0] == iface_name {
                    interfaces.push(InterfacePayload {
                        name: iface_name.to_string(),
                        address: address.clone(),
                        subnet: subnet.clone(),
                        role,
                        packets_in: parts[4].parse().unwrap_or(0),
                        bytes_in: parts[7].parse().unwrap_or(0),
                        packets_out: parts[8].parse().unwrap_or(0),
                        bytes_out: parts[10].parse().unwrap_or(0),
                    });
                    break;
                }
            }
        }
    }

    // Collect recent blocked traffic from pflog (last 50 entries, not all 10k)
    let blocked = collect_blocked_recent().await;

    // Collect service status (lightweight — just check PIDs)
    let services = collect_services(&state.pool).await;

    let status = StatusPayload {
        pf_running: stats.running,
        pf_states: stats.states_count,
        pf_rules: stats.rules_count,
        aifw_rules: rules.len(),
        aifw_active_rules: active,
        nat_rules: nat_rules.len(),
        packets_in: stats.packets_in,
        packets_out: stats.packets_out,
        bytes_in: stats.bytes_in,
        bytes_out: stats.bytes_out,
    };

    // VPN status — refresh every 10 ticks (~10s) to avoid running wg show every second
    static VPN_TICK: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    static VPN_CACHE: tokio::sync::OnceCell<tokio::sync::RwLock<Vec<VpnTunnelStatus>>> =
        tokio::sync::OnceCell::const_new();
    let vpn_cache = VPN_CACHE
        .get_or_init(|| async { tokio::sync::RwLock::new(Vec::new()) })
        .await;
    let tick = VPN_TICK.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let vpn = if tick.is_multiple_of(10) {
        let tunnels = state.vpn_engine.list_wg_tunnels().await.unwrap_or_default();
        let mut vpn_status = Vec::new();
        for t in &tunnels {
            if t.status == aifw_common::VpnStatus::Up {
                if let Ok(st) = state.vpn_engine.tunnel_status(t.id).await {
                    let peers: Vec<VpnPeerStatus> = st
                        .get("peers")
                        .and_then(|p| p.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|p| {
                                    Some(VpnPeerStatus {
                                        public_key: p.get("public_key")?.as_str()?.to_string(),
                                        endpoint: p
                                            .get("endpoint")
                                            .and_then(|v| v.as_str())
                                            .map(|s| s.to_string()),
                                        latest_handshake_secs_ago: p
                                            .get("latest_handshake_secs_ago")?
                                            .as_i64()?,
                                        transfer_rx: p.get("transfer_rx")?.as_u64()?,
                                        transfer_tx: p.get("transfer_tx")?.as_u64()?,
                                    })
                                })
                                .collect()
                        })
                        .unwrap_or_default();
                    vpn_status.push(VpnTunnelStatus {
                        id: t.id.to_string(),
                        name: t.name.clone(),
                        interface_name: t.interface.0.clone(),
                        running: true,
                        peers,
                    });
                }
            } else {
                vpn_status.push(VpnTunnelStatus {
                    id: t.id.to_string(),
                    name: t.name.clone(),
                    interface_name: t.interface.0.clone(),
                    running: false,
                    peers: vec![],
                });
            }
        }
        *vpn_cache.write().await = vpn_status.clone();
        Some(vpn_status)
    } else {
        let cached = vpn_cache.read().await;
        if cached.is_empty() {
            None
        } else {
            Some(cached.clone())
        }
    };

    // IDS status — refresh every 5 ticks (~5s) to avoid querying alerts every second
    static IDS_CACHE: tokio::sync::OnceCell<tokio::sync::RwLock<Option<IdsStatusPayload>>> =
        tokio::sync::OnceCell::const_new();
    let ids_cache = IDS_CACHE
        .get_or_init(|| async { tokio::sync::RwLock::new(None) })
        .await;
    let ids = if tick.is_multiple_of(5) {
        // All IDS state goes through the IPC client now. If aifw-ids is
        // offline, get_stats/tail_alerts return Unavailable and we surface
        // None — same as the legacy `ids_engine.is_none()` path used to do.
        let payload = match state.ids_client.get_stats().await {
            Ok(stats) => {
                let recent = state.ids_client.tail_alerts(5).await.unwrap_or_default();
                let recent_alerts: Vec<IdsAlertSummary> = recent
                    .into_iter()
                    .map(|a| IdsAlertSummary {
                        severity: a.severity,
                        signature_msg: a.msg.clone(),
                        src_ip: a.src_ip.clone(),
                        dst_ip: a.dst_ip.clone(),
                        protocol: a.protocol.clone(),
                        timestamp: a.timestamp.to_rfc3339(),
                    })
                    .collect();
                Some(IdsStatusPayload {
                    running: stats.running,
                    mode: stats.mode,
                    loaded_rules: stats.rules_loaded,
                    alerts_total: stats.alerts_total,
                    drops_total: stats.drops_total,
                    packets_inspected: stats.packets_inspected,
                    packets_per_sec: stats.packets_per_sec,
                    bytes_per_sec: stats.bytes_per_sec,
                    active_flows: stats.flow_count,
                    recent_alerts,
                })
            }
            Err(_) => None,
        };
        *ids_cache.write().await = payload.clone();
        payload
    } else {
        ids_cache.read().await.clone()
    };

    // Slim IDS counters for history
    let ids_history = ids.as_ref().map(|i| IdsHistoryPayload {
        alerts_total: i.alerts_total,
        drops_total: i.drops_total,
        packets_inspected: i.packets_inspected,
        packets_per_sec: i.packets_per_sec,
        active_flows: i.active_flows,
        running: i.running,
    });

    // Slim history entry (~2-3 KB) — excludes blocked/connections to prevent memory growth
    let history_entry = WsHistoryEntry {
        msg_type: "status_update",
        status: status.clone(),
        system: system.clone(),
        interfaces: interfaces.clone(),
        services: services.clone(),
        ids: ids_history,
    };
    let history_msg = serde_json::to_string(&history_entry).map_err(|e| e.to_string())?;

    // Full live update — includes recent blocked + connections for live clients
    let update = WsStatusUpdate {
        msg_type: "status_update",
        system,
        blocked,
        services,
        status,
        connections,
        interfaces,
        vpn,
        ids,
    };
    let live_msg = serde_json::to_string(&update).map_err(|e| e.to_string())?;

    Ok((live_msg, history_msg))
}

async fn collect_system_metrics() -> SystemPayload {
    use crate::native_metrics::sysctl;
    use tokio::process::Command;

    // CPU usage via kern.cp_time delta — native sysctlbyname; no fork.
    let cpu_usage = {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        // PERF-M19: lock-free. Only the single dashboard-producer task
        // calls this, so relaxed per-cell atomics are plenty — no Mutex,
        // no poisoning to `.expect()` around.
        static PREV_CP: [AtomicU64; 5] = [const { AtomicU64::new(0) }; 5];
        static PREV_INIT: AtomicBool = AtomicBool::new(false);

        let cur: Option<[u64; 5]> = sysctl::read_u64_array("kern.cp_time");
        if let Some(cur) = cur {
            let pct = if PREV_INIT.load(Ordering::Relaxed) {
                let d: Vec<u64> = (0..5)
                    .map(|i| cur[i].saturating_sub(PREV_CP[i].load(Ordering::Relaxed)))
                    .collect();
                let total: u64 = d.iter().sum();
                if total > 0 {
                    ((total - d[4]) as f64 / total as f64) * 100.0
                } else {
                    0.0
                }
            } else {
                0.0
            };
            for (cell, v) in PREV_CP.iter().zip(cur) {
                cell.store(v, Ordering::Relaxed);
            }
            PREV_INIT.store(true, Ordering::Relaxed);
            pct
        } else {
            0.0
        }
    };

    // Memory via native sysctlbyname — no fork.
    let (mem_total, mem_used, mem_pct) = {
        let total = sysctl::read_u64("hw.physmem").unwrap_or(0);
        let page_size = sysctl::read_u64("hw.pagesize").unwrap_or(4096);
        let free_pages = sysctl::read_u64("vm.stats.vm.v_free_count").unwrap_or(0);
        let inactive_pages = sysctl::read_u64("vm.stats.vm.v_inactive_count").unwrap_or(0);
        let cache_pages = sysctl::read_u64("vm.stats.vm.v_cache_count").unwrap_or(0);
        let available = (free_pages + inactive_pages + cache_pages) * page_size;
        let used = total.saturating_sub(available);
        let pct = if total > 0 {
            (used as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        (total, used, pct)
    };

    // Disk usage via statvfs (native; no `df` fork).
    let disks: Vec<DiskPayload> = crate::native_metrics::disk_usage()
        .into_iter()
        .map(|d| DiskPayload {
            filesystem: d.filesystem,
            mount: d.mount,
            total: d.total,
            used: d.used,
            pct: d.pct,
        })
        .collect();

    // Uptime via native kern.boottime sysctlbyname / /proc/uptime.
    let uptime_secs = crate::native_metrics::uptime_secs();

    // Hostname + OS version are cached once at startup (gethostname(3) +
    // kern.osrelease) — no per-tick subprocess.
    let hostname = crate::native_metrics::hostname();
    let os_version = crate::native_metrics::os_version();

    // DNS servers
    let dns_servers = tokio::fs::read_to_string("/etc/resolv.conf")
        .await
        .ok()
        .map(|c| {
            c.lines()
                .filter_map(|l| l.strip_prefix("nameserver").map(|s| s.trim().to_string()))
                .collect()
        })
        .unwrap_or_default();

    // Default gateway + route count
    let (default_gateway, route_count) = async {
        let out = Command::new("netstat")
            .args(["-rn", "-f", "inet"])
            .output()
            .await
            .ok()?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut gw = String::new();
        let mut count = 0;
        for line in stdout.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 3 {
                count += 1;
                if parts[0] == "default" {
                    gw = parts[1].to_string();
                }
            }
        }
        Some((gw, count))
    }
    .await
    .unwrap_or_default();

    // Disk I/O via gstat
    let disk_io = async {
        let out = Command::new("gstat")
            .args(["-b", "-p"])
            .output()
            .await
            .ok()?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut total = DiskIoPayload::default();
        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // gstat -bp: L(q) ops/s r/s kBps ms/r w/s kBps ms/w %busy Name
            if parts.len() >= 10 {
                let name = parts[9];
                // Only count whole disks, not partitions
                if name.contains('p') || name.starts_with("cd") {
                    continue;
                }
                total.reads_per_sec += parts[2].parse::<f64>().unwrap_or(0.0);
                total.read_kbps += parts[3].parse::<f64>().unwrap_or(0.0);
                total.writes_per_sec += parts[5].parse::<f64>().unwrap_or(0.0);
                total.write_kbps += parts[6].parse::<f64>().unwrap_or(0.0);
            }
        }
        Some(total)
    }
    .await
    .unwrap_or_default();

    let cpu_cores = std::thread::available_parallelism()
        .map(|n| n.get() as u32)
        .unwrap_or(1);

    SystemPayload {
        cpu_usage,
        cpu_cores,
        memory_total: mem_total,
        memory_used: mem_used,
        memory_pct: mem_pct,
        memory_breakdown: None,
        disks,
        disk_io,
        uptime_secs,
        hostname,
        os_version,
        dns_servers,
        default_gateway,
        route_count,
    }
}

/// Collect memory breakdown: OS categories, process RSS, IDS buffer, metrics, pf states, DB, ARC.
pub async fn collect_memory_breakdown(state: &AppState) -> MemoryBreakdown {
    use crate::native_metrics::sysctl;
    use tokio::process::Command;

    // OS-level memory categories via native sysctlbyname — no fork.
    let page_size = sysctl::read_u64("hw.pagesize").unwrap_or(4096);
    let pages_to_mb = |key: &str| -> f64 {
        let pages = sysctl::read_u64(key).unwrap_or(0);
        (pages * page_size) as f64 / (1024.0 * 1024.0)
    };
    let active_mb = pages_to_mb("vm.stats.vm.v_active_count");
    let inactive_mb = pages_to_mb("vm.stats.vm.v_inactive_count");
    let wired_mb = pages_to_mb("vm.stats.vm.v_wire_count");
    let cached_mb = pages_to_mb("vm.stats.vm.v_cache_count");
    let free_mb = pages_to_mb("vm.stats.vm.v_free_count");

    // Process RSS via a single O(1) syscall each — no `ps` fork (PERF-H12).
    // The API is the current process; the daemon's pid comes from its
    // rc.d pidfile. Missing/unreadable -> 0.0, same as the old ps miss.
    use crate::native_metrics::{process_rss_mb, read_pidfile};
    let api_rss_mb = process_rss_mb(std::process::id()).unwrap_or(0.0);
    let daemon_rss_mb = read_pidfile("/var/run/aifw_daemon.pid")
        .and_then(process_rss_mb)
        .unwrap_or(0.0);

    // IDS alert buffer — lives in aifw-ids; stats over IPC (best-effort).
    // alerts_total isn't the buffer size, but it's the closest metric we
    // expose. The buffer's MB/max-MB knobs are persisted in auth_config and
    // can be read there if needed; we keep returning 0 here to avoid lying.
    let (ids_buffer_mb, ids_buffer_max_mb, ids_buffer_count) = {
        match state.ids_client.get_stats().await {
            Ok(stats) => (0.0_f64, 0.0_f64, stats.alerts_total as usize),
            Err(_) => (0.0_f64, 0.0_f64, 0_usize),
        }
    };

    // Metrics history buffer
    let (metrics_history_count, metrics_history_mb) = {
        let buf = state.metrics_history.read().await;
        let count = buf.len();
        let bytes: usize = buf.iter().map(|s| s.len()).sum();
        (count, bytes as f64 / (1024.0 * 1024.0))
    };

    // pf state table
    let (pf_states, pf_states_max) = {
        let s = state.pf.get_stats().await.unwrap_or_default();
        let max = async {
            let out = Command::new("pfctl").args(["-sm"]).output().await.ok()?;
            let stdout = String::from_utf8_lossy(&out.stdout);
            for line in stdout.lines() {
                if line.starts_with("states") {
                    return line.split_whitespace().nth(3)?.parse::<u64>().ok();
                }
            }
            None
        }
        .await
        .unwrap_or(100_000);
        (s.states_count, max)
    };

    // DB file size
    let db_size_mb = tokio::fs::metadata("/var/db/aifw/aifw.db")
        .await
        .map(|m| m.len() as f64 / (1024.0 * 1024.0))
        .unwrap_or(0.0);

    // ZFS ARC via native sysctlbyname.
    let arc_mb = sysctl::read_u64("kstat.zfs.misc.arcstats.size")
        .map(|b| b as f64 / (1024.0 * 1024.0))
        .unwrap_or(0.0);

    MemoryBreakdown {
        active_mb,
        inactive_mb,
        wired_mb,
        cached_mb,
        free_mb,
        api_rss_mb,
        daemon_rss_mb,
        ids_buffer_mb,
        ids_buffer_max_mb,
        ids_buffer_count,
        metrics_history_count,
        metrics_history_mb,
        pf_states,
        pf_states_max,
        db_size_mb,
        arc_mb,
    }
}

/// Collect blocked traffic from pflog. Cached with tokio RwLock, refreshes every 5 seconds.
const PFLOG_MAX_ENTRIES: usize = 10_000;

/// Case-insensitive substring search without allocating a lowercased copy
/// of the haystack (PERF-M8 #376). `needle` must be ASCII.
fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    h.len() >= n.len() && h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

/// True if `word` appears in `line` (ASCII case-insensitive) bounded by
/// non-alphanumeric characters or the line edges. Catches every tcpdump
/// spelling ("UDP, length", "proto UDP (17)", "esp(spi=...)") — the old
/// `" udp "` match missed the common "UDP," form.
fn has_proto_word(line: &str, word: &str) -> bool {
    let h = line.as_bytes();
    let n = word.as_bytes();
    if h.len() < n.len() {
        return false;
    }
    for start in 0..=(h.len() - n.len()) {
        if !h[start..start + n.len()].eq_ignore_ascii_case(n) {
            continue;
        }
        let before_ok = start == 0 || !h[start - 1].is_ascii_alphanumeric();
        let after = start + n.len();
        let after_ok = after == h.len() || !h[after].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// Split a tcpdump host token ("203.0.113.5.443" or "203.0.113.5") into
/// address and port. Borrows from the token — no allocation. Returns
/// `(None, 0)` when the token doesn't look like an IPv4 address.
fn split_host_port(token: &str) -> (Option<&str>, u16) {
    let Some(dot_pos) = token.rfind('.') else {
        return (None, 0);
    };
    let maybe_ip = &token[..dot_pos];
    if let Ok(port) = token[dot_pos + 1..].parse::<u16>()
        && maybe_ip.bytes().filter(|b| *b == b'.').count() >= 3
    {
        return (Some(maybe_ip), port);
    }
    if token.bytes().filter(|b| *b == b'.').count() == 3 {
        (Some(token), 0)
    } else {
        (None, 0)
    }
}

/// Parse one `tcpdump -tttt` pflog line into a BlockedPayload. Hot path at
/// high block rates (PERF-M8 #376): all matching works on `&str` slices of
/// the input; the only allocations are the Strings moved into the returned
/// payload, and lines that don't parse allocate nothing.
fn parse_pflog_line(line: &str) -> Option<BlockedPayload> {
    let (action, marker_pos) = line
        .find(": block ")
        .map(|p| ("block", p))
        .or_else(|| line.find(": pass ").map(|p| ("pass", p)))?;

    // src/dst first — a line without a source address is discarded, so
    // nothing may be allocated before this check.
    let gt_pos = line.find(" > ")?;
    let src_token = line[..gt_pos].split_whitespace().next_back().unwrap_or("");
    let (src_addr, src_port) = split_host_port(src_token);
    let src_addr = src_addr?;
    let dst_token = line[gt_pos + 3..].split(':').next().unwrap_or("").trim();
    let (dst_addr, dst_port) = split_host_port(dst_token);

    // "... rule N/0(match): block in on igb0: ..." — words after the marker
    let mut words = line[marker_pos + 2..].split_whitespace();
    let direction = words.nth(1).unwrap_or("");
    let interface = words.nth(1).map(|s| s.trim_end_matches(':')).unwrap_or("");

    // -tttt format: "2026-04-01 13:09:28.475326 rule ..."
    let mut head = line.split_whitespace();
    let date_part = head.next().unwrap_or("");
    let time_part = head.next().unwrap_or("");

    let protocol = if line.contains("Flags [") || has_proto_word(line, "tcp") {
        "tcp"
    } else if has_proto_word(line, "udp") {
        "udp"
    } else if contains_ignore_ascii_case(line, "icmp") {
        "icmp"
    } else if has_proto_word(line, "esp") {
        "esp"
    } else if has_proto_word(line, "ah") {
        "ah"
    } else if has_proto_word(line, "gre") {
        "gre"
    } else if contains_ignore_ascii_case(line, "igmp") {
        "igmp"
    } else {
        ""
    };

    Some(BlockedPayload {
        timestamp: format!("{date_part}T{time_part}"),
        action: action.to_string(),
        direction: direction.to_string(),
        interface: interface.to_string(),
        protocol: protocol.to_string(),
        src_addr: src_addr.to_string(),
        src_port,
        dst_addr: dst_addr.map(str::to_string).unwrap_or_default(),
        dst_port,
    })
}

// VecDeque keeps push (push_back) and trim (pop_front) both O(1) even under
// high block rates (DDoS). Vec::drain(..N) on a 10k buffer was O(N) per
// insert → O(N²) under sustained traffic above the cap.
type BlockedBuffer = std::sync::Arc<tokio::sync::RwLock<VecDeque<BlockedPayload>>>;

fn blocked_buffer() -> &'static BlockedBuffer {
    static BUF: std::sync::OnceLock<BlockedBuffer> = std::sync::OnceLock::new();
    BUF.get_or_init(|| {
        std::sync::Arc::new(tokio::sync::RwLock::new(VecDeque::with_capacity(
            PFLOG_MAX_ENTRIES,
        )))
    })
}

/// Call once on API startup to bootstrap from pflog file and start live capture.
/// Both bootstrap and live capture run in a background task so the API starts immediately.
pub fn start_pflog_collector(
    plugin_mgr: std::sync::Arc<tokio::sync::RwLock<aifw_plugins::PluginManager>>,
) {
    let buf = blocked_buffer().clone();
    let buf2 = buf.clone();
    let pmgr = plugin_mgr.clone();
    tokio::spawn(async move {
        // Bootstrap: load historical entries from /var/log/pflog. Uses the
        // narrow aifw-sudo-tcpdump helper (SEC-C2) which rejects -z / -w / -G
        // / -W (the script-exec + arbitrary-write PE primitives).
        if let Ok(output) = aifw_core::sudo::tcpdump(&["-r", "/var/log/pflog"]).await
            && output.status.success()
        {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let entries_iter = stdout.lines().filter_map(parse_pflog_line);
            // Keep only the last PFLOG_MAX_ENTRIES; iterating and dropping the
            // front of a temporary Vec would be O(N²). Buffer the tail directly.
            let mut entries: VecDeque<BlockedPayload> = VecDeque::with_capacity(PFLOG_MAX_ENTRIES);
            for e in entries_iter {
                if entries.len() == PFLOG_MAX_ENTRIES {
                    entries.pop_front();
                }
                entries.push_back(e);
            }
            let count = entries.len();
            *buf.write().await = entries;
            tracing::info!(count, "pflog bootstrap complete");
        }

        // Live capture: persistent tcpdump on pflog0 interface, through the
        // narrow aifw-sudo-tcpdump helper (SEC-C2). The helper only allows
        // pflog0 as the live-capture iface and forbids -z/-w/-G/-W.
        use tokio::io::{AsyncBufReadExt, BufReader};
        loop {
            let child = tokio::process::Command::new("/usr/local/bin/sudo")
                .args(["/usr/local/libexec/aifw-sudo-tcpdump", "-i", "pflog0"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn();

            if let Ok(mut child) = child {
                if let Some(stdout) = child.stdout.take() {
                    let mut reader = BufReader::new(stdout).lines();
                    while let Ok(Some(line)) = reader.next_line().await {
                        if let Some(entry) = parse_pflog_line(&line) {
                            // Dispatch PostRule hook for blocked/passed traffic.
                            // PERF-H17 (#361): snapshot, then dispatch unlocked.
                            {
                                let plugins = pmgr.read().await.dispatch_set();
                                if !plugins.is_empty() {
                                    let event = aifw_plugins::HookEvent {
                                        hook: aifw_plugins::HookPoint::PostRule,
                                        data: aifw_plugins::hooks::HookEventData::Rule {
                                            src_ip: entry.src_addr.parse().ok(),
                                            dst_ip: entry.dst_addr.parse().ok(),
                                            src_port: if entry.src_port > 0 {
                                                Some(entry.src_port)
                                            } else {
                                                None
                                            },
                                            dst_port: if entry.dst_port > 0 {
                                                Some(entry.dst_port)
                                            } else {
                                                None
                                            },
                                            protocol: entry.protocol.clone(),
                                            action: entry.action.clone(),
                                            rule_id: None,
                                        },
                                    };
                                    let _ = plugins.dispatch(&event).await;
                                }
                            }
                            let mut buf = buf2.write().await;
                            if buf.len() == PFLOG_MAX_ENTRIES {
                                buf.pop_front();
                            }
                            buf.push_back(entry);
                        }
                    }
                }
                let _ = child.wait().await;
            }

            // If tcpdump exits, restart after a brief pause
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
}

/// Return only the most recent 50 blocked entries for WS updates.
/// The full 10k buffer remains available for the REST API.
const WS_BLOCKED_LIMIT: usize = 50;

async fn collect_blocked_recent() -> Vec<BlockedPayload> {
    let buf = blocked_buffer();
    let all = buf.read().await;
    let skip = all.len().saturating_sub(WS_BLOCKED_LIMIT);
    all.iter().skip(skip).cloned().collect()
}

async fn collect_services(pool: &sqlx::SqlitePool) -> Vec<ServiceStatusPayload> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::sync::RwLock;

    static TICK: AtomicU64 = AtomicU64::new(0);
    static CACHE: std::sync::OnceLock<RwLock<Vec<ServiceStatusPayload>>> =
        std::sync::OnceLock::new();

    let cache = CACHE.get_or_init(|| RwLock::new(Vec::new()));
    let tick = TICK.fetch_add(1, Ordering::Relaxed);

    // Refresh every 10 seconds
    if tick.is_multiple_of(10) {
        let mut svcs = Vec::new();
        for (name, svc_name) in [
            ("rDNS", "rdns"),
            ("rDHCP", "rdhcpd"),
            ("rTIME", "rtime"),
            ("TrafficCop", "trafficcop"),
        ] {
            let running = aifw_core::sudo::service(svc_name, "status")
                .await
                .map(|o| o.status.success())
                .unwrap_or(false);
            // For TrafficCop, the user-facing "enabled" state lives in the
            // reverse-proxy config DB (tc_config.enabled), not rc.conf. The
            // UI's Save writes the DB immediately, while Apply is what flushes
            // to sysrc — so the badge should follow the DB to match user intent.
            let enabled = if svc_name == "trafficcop" {
                sqlx::query_as::<_, (String,)>("SELECT value FROM tc_config WHERE key = 'enabled'")
                    .fetch_optional(pool)
                    .await
                    .ok()
                    .flatten()
                    .map(|(v,)| v == "true")
                    .unwrap_or(false)
            } else {
                // `sysrc -n` is a read; doesn't need root. Calling
                // `/usr/sbin/sysrc` directly avoids the helper allowlist
                // round-trip for what should be a status check.
                let enable_key = format!("{svc_name}_enable");
                tokio::process::Command::new("/usr/sbin/sysrc")
                    .args(["-n", &enable_key])
                    .output()
                    .await
                    .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "YES")
                    .unwrap_or(false)
            };
            svcs.push(ServiceStatusPayload {
                name: name.to_string(),
                running,
                enabled,
            });
        }
        *cache.write().await = svcs;
    }

    cache.read().await.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Guard for the PERF-M8 (#376) rewrite: parse results must match what the
    // allocating implementation produced for real `tcpdump -tttt` pflog lines.

    #[test]
    fn parses_tcp_block_line() {
        let line = "2026-04-01 13:09:28.475326 rule 5/0(match): block in on igb0: \
                    203.0.113.5.51234 > 10.0.0.2.443: Flags [S], seq 12345, win 65535, length 0";
        let e = parse_pflog_line(line).expect("line should parse");
        assert_eq!(e.timestamp, "2026-04-01T13:09:28.475326");
        assert_eq!(e.action, "block");
        assert_eq!(e.direction, "in");
        assert_eq!(e.interface, "igb0");
        assert_eq!(e.protocol, "tcp");
        assert_eq!(e.src_addr, "203.0.113.5");
        assert_eq!(e.src_port, 51234);
        assert_eq!(e.dst_addr, "10.0.0.2");
        assert_eq!(e.dst_port, 443);
    }

    #[test]
    fn parses_udp_pass_line() {
        let line = "2026-04-01 13:09:29.000001 rule 2/0(match): pass out on em1: \
                    198.51.100.9.5353 > 224.0.0.251.5353: UDP, length 45";
        let e = parse_pflog_line(line).expect("line should parse");
        assert_eq!(e.action, "pass");
        assert_eq!(e.direction, "out");
        assert_eq!(e.interface, "em1");
        assert_eq!(e.protocol, "udp");
        assert_eq!(e.src_addr, "198.51.100.9");
        assert_eq!(e.src_port, 5353);
        assert_eq!(e.dst_addr, "224.0.0.251");
        assert_eq!(e.dst_port, 5353);
    }

    #[test]
    fn parses_icmp_line_without_ports() {
        let line = "2026-04-01 13:09:30.123456 rule 7/0(match): block in on igb0: \
                    192.0.2.77 > 10.0.0.2: ICMP echo request, id 1, seq 1, length 64";
        let e = parse_pflog_line(line).expect("line should parse");
        assert_eq!(e.protocol, "icmp");
        assert_eq!(e.src_addr, "192.0.2.77");
        assert_eq!(e.src_port, 0);
        assert_eq!(e.dst_addr, "10.0.0.2");
        assert_eq!(e.dst_port, 0);
    }

    #[test]
    fn rejects_non_block_pass_lines() {
        assert!(
            parse_pflog_line("2026-04-01 13:09:31.0 rule 1/0(match): nat out on igb0: x").is_none()
        );
        assert!(parse_pflog_line("garbage line with no markers").is_none());
        assert!(parse_pflog_line("").is_none());
    }

    #[test]
    fn rejects_lines_without_source_address() {
        // marker present but no " > " host pair
        assert!(
            parse_pflog_line("2026-04-01 13:09:32.0 rule 3/0(match): block in on igb0:").is_none()
        );
    }

    #[test]
    fn split_host_port_variants() {
        assert_eq!(split_host_port("10.0.0.2.443"), (Some("10.0.0.2"), 443));
        assert_eq!(split_host_port("10.0.0.2"), (Some("10.0.0.2"), 0));
        assert_eq!(split_host_port("hostname"), (None, 0));
        assert_eq!(split_host_port(""), (None, 0));
        // port out of u16 range and too many dots for a bare IPv4 → rejected
        assert_eq!(split_host_port("10.0.0.2.99999"), (None, 0));
    }

    #[test]
    fn case_insensitive_contains_without_alloc() {
        assert!(contains_ignore_ascii_case("A B TCP C", " tcp "));
        assert!(contains_ignore_ascii_case("x Icmp y", "icmp"));
        assert!(!contains_ignore_ascii_case("short", " longer needle "));
        assert!(!contains_ignore_ascii_case("abc", "xyz"));
    }

    #[test]
    fn proto_word_matching() {
        // the "UDP," form the old " udp " match missed
        assert!(has_proto_word(
            "1.2.3.4.53 > 5.6.7.8.53: UDP, length 45",
            "udp"
        ));
        assert!(has_proto_word("proto UDP (17)", "udp"));
        assert!(has_proto_word("esp(spi=0x1234)", "esp"));
        // word boundaries: no match inside larger words
        assert!(!has_proto_word("resp(code=1)", "esp"));
        assert!(!has_proto_word("blah(x)", "ah"));
        assert!(!has_proto_word("update stream", "udp"));
    }
}
