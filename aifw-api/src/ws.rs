use axum::{
    extract::{State, WebSocketUpgrade, ws::{Message, WebSocket}},
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use std::time::Duration;
use tokio::time::interval;

use crate::{AppState, METRICS_HISTORY_SIZE};
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

#[derive(Serialize)]
struct SystemPayload {
    cpu_usage: f64,
    cpu_cores: u32,
    memory_total: u64,
    memory_used: u64,
    memory_pct: f64,
    disks: Vec<DiskPayload>,
    disk_io: DiskIoPayload,
    uptime_secs: u64,
    hostname: String,
    os_version: String,
    dns_servers: Vec<String>,
    default_gateway: String,
    route_count: usize,
}

#[derive(Serialize, Default)]
struct DiskIoPayload {
    reads_per_sec: f64,
    writes_per_sec: f64,
    read_kbps: f64,
    write_kbps: f64,
}

#[derive(Serialize)]
struct DiskPayload {
    mount: String,
    filesystem: String,
    total: u64,
    used: u64,
    pct: f64,
}

#[derive(Serialize)]
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

#[derive(Serialize)]
struct InterfacePayload {
    name: String,
    bytes_in: u64,
    bytes_out: u64,
    packets_in: u64,
    packets_out: u64,
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
) -> Response {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

async fn handle_socket(socket: WebSocket, state: AppState) {
    let (mut sender, mut receiver) = socket.split();

    // Send historical data first
    {
        let history = state.metrics_history.read().await;
        if !history.is_empty() {
            // Send a batch history message
            let batch = format!(
                "{{\"type\":\"history\",\"data\":[{}]}}",
                history.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(",")
            );
            let _ = sender.send(Message::Text(batch.into())).await;
        }
    }

    // Spawn a task to push updates every second
    let push_state = state.clone();
    let mut push_task = tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            match build_update(&push_state).await {
                Ok(msg) => {
                    // Store in server-side ring buffer
                    {
                        let mut buf = push_state.metrics_history.write().await;
                        if buf.len() >= METRICS_HISTORY_SIZE {
                            buf.pop_front();
                        }
                        buf.push_back(msg.clone());
                    }

                    // Persist to Valkey if available
                    if let Some(ref redis) = push_state.redis {
                        let mut conn = redis.clone();
                        let _: Result<(), _> = redis::pipe()
                            .cmd("LPUSH").arg("aifw:metrics:history").arg(&msg)
                            .cmd("LTRIM").arg("aifw:metrics:history").arg(0i64).arg(METRICS_HISTORY_SIZE as i64 - 1)
                            .query_async(&mut conn)
                            .await;
                    }

                    if sender.send(Message::Text(msg.into())).await.is_err() {
                        break;
                    }
                }
                Err(_) => {}
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

async fn build_update(state: &AppState) -> Result<String, String> {
    let stats = state.pf.get_stats().await.map_err(|e| e.to_string())?;
    let rules = state.rule_engine.list_rules().await.map_err(|e| e.to_string())?;
    let active = rules.iter().filter(|r| r.status == RuleStatus::Active).count();
    let nat_rules = state.nat_engine.list_rules().await.map_err(|e| e.to_string())?;

    state.conntrack.refresh().await.map_err(|e| e.to_string())?;
    let conns = state.conntrack.get_connections().await;

    // Dispatch plugin hooks for new/closed connections
    {
        use std::collections::HashSet;
        static PREV_CONNS: std::sync::OnceLock<tokio::sync::RwLock<HashSet<String>>> = std::sync::OnceLock::new();
        let prev_lock = PREV_CONNS.get_or_init(|| tokio::sync::RwLock::new(HashSet::new()));

        let current_keys: HashSet<String> = conns.iter().map(|c| format!("{}:{}:{}:{}", c.src_addr, c.src_port, c.dst_addr, c.dst_port)).collect();
        let prev_keys = prev_lock.read().await.clone();

        // New connections
        let mgr = state.plugin_manager.read().await;
        if mgr.running_count() > 0 {
            for c in &conns {
                let key = format!("{}:{}:{}:{}", c.src_addr, c.src_port, c.dst_addr, c.dst_port);
                if !prev_keys.contains(&key) {
                    let event = aifw_plugins::HookEvent {
                        hook: aifw_plugins::HookPoint::ConnectionNew,
                        data: aifw_plugins::hooks::HookEventData::Connection {
                            src_ip: c.src_addr, dst_ip: c.dst_addr,
                            src_port: c.src_port, dst_port: c.dst_port,
                            protocol: c.protocol.clone(), state: c.state.clone(),
                        },
                    };
                    let actions = mgr.dispatch(&event).await;
                    for action in actions {
                        if let aifw_plugins::HookAction::AddToTable { ref table, ip } = action {
                            let _ = state.pf.add_table_entry(table, ip).await;
                        }
                    }
                }
            }
            // Closed connections
            for key in &prev_keys {
                if !current_keys.contains(key) {
                    let parts: Vec<&str> = key.split(':').collect();
                    if parts.len() >= 4 {
                        let event = aifw_plugins::HookEvent {
                            hook: aifw_plugins::HookPoint::ConnectionClosed,
                            data: aifw_plugins::hooks::HookEventData::Connection {
                                src_ip: parts[0].parse().unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                                dst_ip: parts[2].parse().unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
                                src_port: parts[1].parse().unwrap_or(0),
                                dst_port: parts[3].parse().unwrap_or(0),
                                protocol: String::new(), state: "closed".to_string(),
                            },
                        };
                        let _ = mgr.dispatch(&event).await;
                    }
                }
            }
        }
        *prev_lock.write().await = current_keys;
    }

    let connections: Vec<ConnectionPayload> = conns.iter().map(|c| ConnectionPayload {
        protocol: c.protocol.clone(),
        src_addr: c.src_addr.to_string(),
        src_port: c.src_port,
        dst_addr: c.dst_addr.to_string(),
        dst_port: c.dst_port,
        state: c.state.clone(),
        bytes_in: c.bytes_in,
        bytes_out: c.bytes_out,
    }).collect();

    // --- System metrics ---
    let system = collect_system_metrics().await;

    // Get per-interface byte counters via netstat -I
    let mut interfaces = Vec::new();
    let ifconfig_out = tokio::process::Command::new("ifconfig")
        .arg("-l")
        .output()
        .await
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    for iface_name in ifconfig_out.split_whitespace() {
        if iface_name.starts_with("lo") || iface_name.starts_with("pflog") || iface_name.starts_with("enc") || iface_name.starts_with("pfsync") {
            continue;
        }
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

    // Collect blocked traffic from pflog (cached, refreshed every 5 ticks)
    let blocked = collect_blocked().await;

    // Collect service status (lightweight — just check PIDs)
    let services = collect_services().await;

    let update = WsStatusUpdate {
        msg_type: "status_update",
        system,
        blocked,
        services,
        status: StatusPayload {
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
        },
        connections,
        interfaces,
    };

    serde_json::to_string(&update).map_err(|e| e.to_string())
}

async fn collect_system_metrics() -> SystemPayload {
    use tokio::process::Command;

    // CPU usage via kern.cp_time delta
    let cpu_usage = {
        use std::sync::Mutex;
        static PREV_CP: Mutex<Option<[u64; 5]>> = Mutex::new(None);

        let out = Command::new("sysctl").args(["-n", "kern.cp_time"]).output().await.ok();
        let cur: Option<[u64; 5]> = out.and_then(|o| {
            let s = String::from_utf8_lossy(&o.stdout);
            let v: Vec<u64> = s.split_whitespace().filter_map(|x| x.parse().ok()).collect();
            if v.len() >= 5 { Some([v[0], v[1], v[2], v[3], v[4]]) } else { None }
        });

        let usage = if let Some(cur) = cur {
            let mut prev_lock = PREV_CP.lock().unwrap();
            let pct = if let Some(prev) = *prev_lock {
                let d: Vec<u64> = (0..5).map(|i| cur[i].saturating_sub(prev[i])).collect();
                let total: u64 = d.iter().sum();
                if total > 0 { ((total - d[4]) as f64 / total as f64) * 100.0 } else { 0.0 }
            } else {
                0.0
            };
            *prev_lock = Some(cur);
            pct
        } else {
            0.0
        };
        usage
    };

    // Memory via sysctl
    let (mem_total, mem_used, mem_pct) = async {
        let total_out = Command::new("sysctl").args(["-n", "hw.physmem"]).output().await.ok()?;
        let total: u64 = String::from_utf8_lossy(&total_out.stdout).trim().parse().ok()?;

        let page_size_out = Command::new("sysctl").args(["-n", "hw.pagesize"]).output().await.ok()?;
        let page_size: u64 = String::from_utf8_lossy(&page_size_out.stdout).trim().parse().ok()?;

        let free_out = Command::new("sysctl").args(["-n", "vm.stats.vm.v_free_count"]).output().await.ok()?;
        let free_pages: u64 = String::from_utf8_lossy(&free_out.stdout).trim().parse().ok()?;

        let inactive_out = Command::new("sysctl").args(["-n", "vm.stats.vm.v_inactive_count"]).output().await.ok()?;
        let inactive_pages: u64 = String::from_utf8_lossy(&inactive_out.stdout).trim().parse().ok()?;

        let cache_out = Command::new("sysctl").args(["-n", "vm.stats.vm.v_cache_count"]).output().await.ok().and_then(|o| {
            String::from_utf8_lossy(&o.stdout).trim().parse::<u64>().ok()
        }).unwrap_or(0);

        let available = (free_pages + inactive_pages + cache_out) * page_size;
        let used = if total > available { total - available } else { 0 };
        let pct = if total > 0 { (used as f64 / total as f64) * 100.0 } else { 0.0 };
        Some((total, used, pct))
    }.await.unwrap_or((0, 0, 0.0));

    // Disk usage via df
    let disks = async {
        let out = Command::new("df").args(["-k", "-t", "ufs,zfs"]).output().await.ok()?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut disks = Vec::new();
        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 6 {
                let total: u64 = parts[1].parse().unwrap_or(0) * 1024; // KB to bytes
                let used: u64 = parts[2].parse().unwrap_or(0) * 1024;
                let pct_str = parts[4].trim_end_matches('%');
                let pct: f64 = pct_str.parse().unwrap_or(0.0);
                disks.push(DiskPayload {
                    filesystem: parts[0].to_string(),
                    mount: parts[5].to_string(),
                    total, used, pct,
                });
            }
        }
        Some(disks)
    }.await.unwrap_or_default();

    // Uptime
    let uptime_secs = async {
        let out = Command::new("sysctl").args(["-n", "kern.boottime"]).output().await.ok()?;
        let s = String::from_utf8_lossy(&out.stdout);
        // Format: "{ sec = 1711561045, usec = 123456 } Thu Mar 27..."
        let sec_str = s.split("sec = ").nth(1)?.split(',').next()?;
        let boot: u64 = sec_str.trim().parse().ok()?;
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).ok()?.as_secs();
        Some(now.saturating_sub(boot))
    }.await.unwrap_or(0);

    // Hostname
    let hostname = async {
        let out = Command::new("hostname").output().await.ok()?;
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }.await.unwrap_or_else(|| "aifw".to_string());

    // OS version
    let os_version = async {
        let out = Command::new("freebsd-version").output().await.ok()?;
        Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }.await.unwrap_or_else(|| "FreeBSD".to_string());

    // DNS servers
    let dns_servers = tokio::fs::read_to_string("/etc/resolv.conf").await.ok()
        .map(|c| c.lines().filter_map(|l| l.strip_prefix("nameserver").map(|s| s.trim().to_string())).collect())
        .unwrap_or_default();

    // Default gateway + route count
    let (default_gateway, route_count) = async {
        let out = Command::new("netstat").args(["-rn", "-f", "inet"]).output().await.ok()?;
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
    }.await.unwrap_or_default();

    // Disk I/O via gstat
    let disk_io = async {
        let out = Command::new("gstat").args(["-b", "-p"]).output().await.ok()?;
        let stdout = String::from_utf8_lossy(&out.stdout);
        let mut total = DiskIoPayload::default();
        for line in stdout.lines().skip(1) {
            let parts: Vec<&str> = line.split_whitespace().collect();
            // gstat -bp: L(q) ops/s r/s kBps ms/r w/s kBps ms/w %busy Name
            if parts.len() >= 10 {
                let name = parts[9];
                // Only count whole disks, not partitions
                if name.contains('p') || name.starts_with("cd") { continue; }
                total.reads_per_sec += parts[2].parse::<f64>().unwrap_or(0.0);
                total.read_kbps += parts[3].parse::<f64>().unwrap_or(0.0);
                total.writes_per_sec += parts[5].parse::<f64>().unwrap_or(0.0);
                total.write_kbps += parts[6].parse::<f64>().unwrap_or(0.0);
            }
        }
        Some(total)
    }.await.unwrap_or_default();

    let cpu_cores = std::thread::available_parallelism().map(|n| n.get() as u32).unwrap_or(1);

    SystemPayload {
        cpu_usage, cpu_cores, memory_total: mem_total, memory_used: mem_used, memory_pct: mem_pct,
        disks, disk_io, uptime_secs, hostname, os_version, dns_servers, default_gateway, route_count,
    }
}

/// Collect blocked traffic from pflog. Cached with tokio RwLock, refreshes every 5 seconds.
const PFLOG_MAX_ENTRIES: usize = 10_000;

fn parse_pflog_line(line: &str) -> Option<BlockedPayload> {
    let action = if line.contains(": block ") { "block" }
        else if line.contains(": pass ") { "pass" }
        else { return None };

    // -tttt format: "2026-04-01 13:09:28.475326 rule ..."
    let mut words = line.split_whitespace();
    let date_part = words.next().unwrap_or("");
    let time_part = words.next().unwrap_or("");
    let timestamp = format!("{date_part}T{time_part}");

    let mut entry = BlockedPayload {
        timestamp,
        action: action.to_string(),
        direction: String::new(), interface: String::new(),
        protocol: String::new(),
        src_addr: String::new(), src_port: 0,
        dst_addr: String::new(), dst_port: 0,
    };

    let marker = if action == "block" { ": block " } else { ": pass " };
    if let Some(pos) = line.find(marker) {
        let rest = &line[pos + 2..];
        let parts: Vec<&str> = rest.split_whitespace().collect();
        entry.direction = parts.get(1).unwrap_or(&"").to_string();
        entry.interface = parts.get(3).map(|s| s.trim_end_matches(':')).unwrap_or("").to_string();
    }

    if let Some(gt_pos) = line.find(" > ") {
        let before = &line[..gt_pos];
        let src_token = before.split_whitespace().next_back().unwrap_or("");
        if let Some(dot_pos) = src_token.rfind('.') {
            let maybe_port = &src_token[dot_pos + 1..];
            let maybe_ip = &src_token[..dot_pos];
            if let Ok(port) = maybe_port.parse::<u16>() {
                if maybe_ip.chars().filter(|c| *c == '.').count() >= 3 {
                    entry.src_addr = maybe_ip.to_string();
                    entry.src_port = port;
                } else if src_token.chars().filter(|c| *c == '.').count() == 3 {
                    entry.src_addr = src_token.to_string();
                }
            } else if src_token.chars().filter(|c| *c == '.').count() == 3 {
                entry.src_addr = src_token.to_string();
            }
        }
        let after = &line[gt_pos + 3..];
        let dst_token = after.split(':').next().unwrap_or("").trim();
        if let Some(dot_pos) = dst_token.rfind('.') {
            let maybe_port = &dst_token[dot_pos + 1..];
            let maybe_ip = &dst_token[..dot_pos];
            if let Ok(port) = maybe_port.parse::<u16>() {
                if maybe_ip.chars().filter(|c| *c == '.').count() >= 3 {
                    entry.dst_addr = maybe_ip.to_string();
                    entry.dst_port = port;
                } else if dst_token.chars().filter(|c| *c == '.').count() == 3 {
                    entry.dst_addr = dst_token.to_string();
                }
            } else if dst_token.chars().filter(|c| *c == '.').count() == 3 {
                entry.dst_addr = dst_token.to_string();
            }
        }
    }

    let lower = line.to_lowercase();
    if line.contains("Flags [") || lower.contains(" tcp ") { entry.protocol = "tcp".to_string(); }
    else if lower.contains(" udp ") { entry.protocol = "udp".to_string(); }
    else if lower.contains("icmp") { entry.protocol = "icmp".to_string(); }
    else if lower.contains(" esp ") || lower.contains("esp(") { entry.protocol = "esp".to_string(); }
    else if lower.contains(" ah ") || lower.contains("ah(") { entry.protocol = "ah".to_string(); }
    else if lower.contains(" gre ") || lower.contains("gre(") { entry.protocol = "gre".to_string(); }
    else if lower.contains("igmp") { entry.protocol = "igmp".to_string(); }

    if entry.src_addr.is_empty() { return None; }
    Some(entry)
}

type BlockedBuffer = std::sync::Arc<tokio::sync::RwLock<Vec<BlockedPayload>>>;

fn blocked_buffer() -> &'static BlockedBuffer {
    static BUF: std::sync::OnceLock<BlockedBuffer> = std::sync::OnceLock::new();
    BUF.get_or_init(|| std::sync::Arc::new(tokio::sync::RwLock::new(Vec::new())))
}

/// Call once on API startup to bootstrap from pflog file and start live capture.
pub async fn start_pflog_collector(plugin_mgr: std::sync::Arc<tokio::sync::RwLock<aifw_plugins::PluginManager>>) {
    let buf = blocked_buffer().clone();

    // Bootstrap: load historical entries from /var/log/pflog
    if let Ok(output) = tokio::process::Command::new("/usr/local/bin/sudo")
        .args(["/usr/sbin/tcpdump", "-tttt", "-n", "-e", "-r", "/var/log/pflog"])
        .output().await
    {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let mut entries: Vec<BlockedPayload> = stdout.lines()
                .filter_map(|line| parse_pflog_line(line))
                .collect();
            // Keep only the most recent entries
            if entries.len() > PFLOG_MAX_ENTRIES {
                entries.drain(..entries.len() - PFLOG_MAX_ENTRIES);
            }
            *buf.write().await = entries;
        }
    }

    // Live capture: persistent tcpdump on pflog0 interface
    let buf2 = buf.clone();
    let pmgr = plugin_mgr.clone();
    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, BufReader};
        loop {
            let child = tokio::process::Command::new("/usr/local/bin/sudo")
                .args(["/usr/sbin/tcpdump", "-tttt", "-n", "-e", "-l", "-i", "pflog0"])
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null())
                .spawn();

            if let Ok(mut child) = child {
                if let Some(stdout) = child.stdout.take() {
                    let mut reader = BufReader::new(stdout).lines();
                    while let Ok(Some(line)) = reader.next_line().await {
                        if let Some(entry) = parse_pflog_line(&line) {
                            // Dispatch PostRule hook for blocked/passed traffic
                            {
                                let mgr = pmgr.read().await;
                                if mgr.running_count() > 0 {
                                    let event = aifw_plugins::HookEvent {
                                        hook: aifw_plugins::HookPoint::PostRule,
                                        data: aifw_plugins::hooks::HookEventData::Rule {
                                            src_ip: entry.src_addr.parse().ok(),
                                            dst_ip: entry.dst_addr.parse().ok(),
                                            src_port: if entry.src_port > 0 { Some(entry.src_port) } else { None },
                                            dst_port: if entry.dst_port > 0 { Some(entry.dst_port) } else { None },
                                            protocol: entry.protocol.clone(),
                                            action: entry.action.clone(),
                                            rule_id: None,
                                        },
                                    };
                                    let _ = mgr.dispatch(&event).await;
                                }
                            }
                            let mut buf = buf2.write().await;
                            buf.push(entry);
                            let excess = buf.len().saturating_sub(PFLOG_MAX_ENTRIES);
                            if excess > 0 {
                                buf.drain(..excess);
                            }
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

async fn collect_blocked() -> Vec<BlockedPayload> {
    let buf = blocked_buffer();
    buf.read().await.clone()
}

async fn collect_services() -> Vec<ServiceStatusPayload> {
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::sync::RwLock;

    static TICK: AtomicU64 = AtomicU64::new(0);
    static CACHE: std::sync::OnceLock<RwLock<Vec<ServiceStatusPayload>>> = std::sync::OnceLock::new();

    let cache = CACHE.get_or_init(|| RwLock::new(Vec::new()));
    let tick = TICK.fetch_add(1, Ordering::Relaxed);

    // Refresh every 10 seconds
    if tick % 10 == 0 {
        let mut svcs = Vec::new();
        for (name, svc_name) in [("rDNS", "rdns"), ("rDHCP", "rdhcpd"), ("rTIME", "rtime"), ("TrafficCop", "trafficcop")] {
            let running = tokio::process::Command::new("/usr/local/bin/sudo")
                .args(["/usr/sbin/service", svc_name, "status"])
                .output().await
                .map(|o| o.status.success()).unwrap_or(false);
            let enabled = tokio::process::Command::new("/usr/local/bin/sudo")
                .args(["/usr/sbin/sysrc", "-n", &format!("{svc_name}_enable")])
                .output().await
                .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "YES").unwrap_or(false);
            svcs.push(ServiceStatusPayload { name: name.to_string(), running, enabled });
        }
        *cache.write().await = svcs;
    }

    cache.read().await.clone()
}
