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
    connections: Vec<ConnectionPayload>,
    interfaces: Vec<InterfacePayload>,
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
