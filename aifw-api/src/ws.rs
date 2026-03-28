use axum::{
    extract::{State, WebSocketUpgrade, ws::{Message, WebSocket}},
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use serde::Serialize;
use std::time::Duration;
use tokio::time::interval;

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
}

#[derive(Serialize)]
struct SystemPayload {
    cpu_usage: f64,
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

    // Spawn a task to push updates every 2 seconds
    let push_state = state.clone();
    let mut push_task = tokio::spawn(async move {
        let mut tick = interval(Duration::from_secs(1));
        loop {
            tick.tick().await;
            match build_update(&push_state).await {
                Ok(msg) => {
                    if sender.send(Message::Text(msg.into())).await.is_err() {
                        break; // client disconnected
                    }
                }
                Err(_) => {
                    // Skip this tick on error
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

async fn build_update(state: &AppState) -> Result<String, String> {
    let stats = state.pf.get_stats().await.map_err(|e| e.to_string())?;
    let rules = state.rule_engine.list_rules().await.map_err(|e| e.to_string())?;
    let active = rules.iter().filter(|r| r.status == RuleStatus::Active).count();
    let nat_rules = state.nat_engine.list_rules().await.map_err(|e| e.to_string())?;

    state.conntrack.refresh().await.map_err(|e| e.to_string())?;
    let conns = state.conntrack.get_connections().await;

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

    let update = WsStatusUpdate {
        msg_type: "status_update",
        system,
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

    // CPU usage via sysctl kern.cp_time
    let cpu_usage = async {
        let out = Command::new("sysctl").args(["-n", "kern.cp_time"]).output().await.ok()?;
        let s = String::from_utf8_lossy(&out.stdout);
        let vals: Vec<u64> = s.split_whitespace().filter_map(|v| v.parse().ok()).collect();
        // vals: user, nice, system, interrupt, idle
        if vals.len() >= 5 {
            let total: u64 = vals.iter().sum();
            let idle = vals[4];
            if total > 0 { Some(((total - idle) as f64 / total as f64) * 100.0) } else { Some(0.0) }
        } else { None }
    }.await.unwrap_or(0.0);

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

    SystemPayload {
        cpu_usage, memory_total: mem_total, memory_used: mem_used, memory_pct: mem_pct,
        disks, disk_io, uptime_secs, hostname, os_version, dns_servers, default_gateway, route_count,
    }
}
