//! HTTP / WebSocket bindings for the DNS blocklist engine.
//!
//! All schema, downloading, parsing, and the cron scheduler live in
//! `aifw_core::dns_blocklists`. The scheduler is owned by `aifw-daemon`,
//! not this process — these handlers only do CRUD and on-demand refresh.

use crate::AppState;
use aifw_core::dns_blocklists as bl;
use axum::{
    Json,
    extract::{Path, Query, State, WebSocketUpgrade,
        ws::{Message as WsMessage, WebSocket}},
    http::StatusCode,
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

pub use aifw_core::dns_blocklists::migrate;

const CONTROL_SOCKET: &str = bl::CONTROL_SOCKET;

// ---- list / CRUD ----

#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub category: Option<String>,
    pub enabled: Option<bool>,
}

pub async fn list_sources(
    State(state): State<AppState>,
    Query(q): Query<ListQuery>,
) -> Json<Vec<bl::BlocklistSource>> {
    let mut all = bl::load_all_sources(&state.pool).await;
    if let Some(cat) = q.category {
        all.retain(|s| s.category == cat);
    }
    if let Some(en) = q.enabled {
        all.retain(|s| s.enabled == en);
    }
    Json(all)
}

pub async fn get_source(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<Json<bl::BlocklistSource>, StatusCode> {
    bl::load_source(&state.pool, id).await
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

pub async fn create_source(
    State(state): State<AppState>,
    Json(req): Json<bl::NewBlocklistSource>,
) -> Result<Json<bl::BlocklistSource>, (StatusCode, String)> {
    bl::create_source(&state.pool, req).await
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))
}

pub async fn update_source(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(req): Json<bl::UpdateBlocklistSource>,
) -> Result<Json<bl::BlocklistSource>, (StatusCode, String)> {
    bl::update_source(&state.pool, id, req).await
        .map(Json)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))
}

pub async fn delete_source(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
    bl::delete_source(&state.pool, id).await
        .map(|_| StatusCode::NO_CONTENT)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))
}

pub async fn refresh_one(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Json<bl::RefreshOutcome> {
    let outcome = bl::refresh_source(&state.pool, id).await;
    if outcome.ok {
        let _ = bl::trigger_rdns_reload().await;
    }
    Json(outcome)
}

pub async fn refresh_everything(State(state): State<AppState>) -> Json<Vec<bl::RefreshOutcome>> {
    Json(bl::refresh_all(&state.pool).await)
}

pub async fn get_schedule(State(state): State<AppState>) -> Json<bl::BlocklistSchedule> {
    Json(bl::load_schedule(&state.pool).await)
}

pub async fn put_schedule(
    State(state): State<AppState>,
    Json(req): Json<bl::BlocklistSchedule>,
) -> Result<Json<bl::BlocklistSchedule>, (StatusCode, String)> {
    bl::put_schedule(&state.pool, &req).await
        .map(|_| Json(req))
        .map_err(|e| (StatusCode::BAD_REQUEST, e))
}

#[derive(serde::Deserialize)]
pub struct EnabledReq {
    pub enabled: bool,
}

pub async fn set_enabled(
    State(state): State<AppState>,
    Json(req): Json<EnabledReq>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    bl::set_enabled(&state.pool, req.enabled).await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    Ok(Json(serde_json::json!({ "enabled": req.enabled })))
}

// ---- whitelist / custom blocks ----

pub async fn list_whitelist(State(state): State<AppState>) -> Json<Vec<bl::PatternEntry>> {
    Json(bl::list_patterns(&state.pool, "dns_whitelist").await)
}

pub async fn create_whitelist(
    State(state): State<AppState>,
    Json(req): Json<bl::NewPatternEntry>,
) -> Result<Json<bl::PatternEntry>, (StatusCode, String)> {
    let entry = bl::insert_pattern(&state.pool, "dns_whitelist", req).await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let _ = bl::rebuild_custom_rpz(&state.pool).await;
    let _ = bl::trigger_rdns_reload().await;
    Ok(Json(entry))
}

pub async fn delete_whitelist(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
    bl::delete_pattern(&state.pool, "dns_whitelist", id).await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let _ = bl::rebuild_custom_rpz(&state.pool).await;
    let _ = bl::trigger_rdns_reload().await;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_customblocks(State(state): State<AppState>) -> Json<Vec<bl::PatternEntry>> {
    Json(bl::list_patterns(&state.pool, "dns_blocklist_custom").await)
}

pub async fn create_customblock(
    State(state): State<AppState>,
    Json(req): Json<bl::NewPatternEntry>,
) -> Result<Json<bl::PatternEntry>, (StatusCode, String)> {
    let entry = bl::insert_pattern(&state.pool, "dns_blocklist_custom", req).await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let _ = bl::rebuild_custom_rpz(&state.pool).await;
    let _ = bl::trigger_rdns_reload().await;
    Ok(Json(entry))
}

pub async fn delete_customblock(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> Result<StatusCode, (StatusCode, String)> {
    bl::delete_pattern(&state.pool, "dns_blocklist_custom", id).await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    let _ = bl::rebuild_custom_rpz(&state.pool).await;
    let _ = bl::trigger_rdns_reload().await;
    Ok(StatusCode::NO_CONTENT)
}

// ---- stats / live stream ----

pub async fn get_stats_snapshot(_state: State<AppState>)
    -> Result<Json<serde_json::Value>, (StatusCode, String)>
{
    let line = control_request("stats-json").await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("rdns control: {e}")))?;
    let v: serde_json::Value = serde_json::from_str(&line)
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("invalid json from rdns: {e}")))?;
    Ok(Json(v))
}

async fn control_request(cmd: &str) -> std::io::Result<String> {
    let stream = tokio::net::UnixStream::connect(CONTROL_SOCKET).await?;
    let (reader, mut writer) = stream.into_split();
    writer.write_all(cmd.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    writer.flush().await?;
    let mut br = BufReader::new(reader);
    let mut line = String::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), br.read_line(&mut line)).await;
    Ok(line.trim().to_string())
}

/// WebSocket — multiplexes rDNS `watch 1` (stats) and `tail-blocks 50`
/// (block events) onto a single connection. Frames are tagged
/// `{ "type": "stats" | "block" | "error", "data": ... }`.
///
/// Auth is enforced by the route-layer middleware (dns:read).
pub async fn stream_metrics(
    State(_state): State<AppState>,
    ws: WebSocketUpgrade,
) -> Response {
    ws.on_upgrade(handle_stream_socket)
}

async fn handle_stream_socket(socket: WebSocket) {
    let (mut tx, mut rx) = socket.split();

    let stats_stream = match tokio::net::UnixStream::connect(CONTROL_SOCKET).await {
        Ok(s) => s,
        Err(e) => {
            let _ = tx.send(WsMessage::Text(
                format!("{{\"type\":\"error\",\"error\":\"rdns control unreachable: {e}\"}}").into()
            )).await;
            return;
        }
    };
    let blocks_stream = match tokio::net::UnixStream::connect(CONTROL_SOCKET).await {
        Ok(s) => s,
        Err(e) => {
            let _ = tx.send(WsMessage::Text(
                format!("{{\"type\":\"error\",\"error\":\"rdns control unreachable: {e}\"}}").into()
            )).await;
            return;
        }
    };

    let (stats_r, mut stats_w) = stats_stream.into_split();
    let (blocks_r, mut blocks_w) = blocks_stream.into_split();

    if stats_w.write_all(b"watch 1\n").await.is_err() { return; }
    if blocks_w.write_all(b"tail-blocks 50\n").await.is_err() { return; }

    let (frame_tx, mut frame_rx) = tokio::sync::mpsc::channel::<String>(256);

    let stats_task = {
        let frame_tx = frame_tx.clone();
        tokio::spawn(async move {
            let mut br = BufReader::new(stats_r);
            let mut line = String::new();
            loop {
                line.clear();
                match br.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let body = line.trim();
                        if body.is_empty() { continue; }
                        let framed = format!("{{\"type\":\"stats\",\"data\":{body}}}");
                        if frame_tx.send(framed).await.is_err() { break; }
                    }
                }
            }
        })
    };

    let blocks_task = {
        let frame_tx = frame_tx.clone();
        tokio::spawn(async move {
            let mut br = BufReader::new(blocks_r);
            let mut line = String::new();
            loop {
                line.clear();
                match br.read_line(&mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let body = line.trim();
                        if body.is_empty() { continue; }
                        let framed = format!("{{\"type\":\"block\",\"data\":{body}}}");
                        if frame_tx.send(framed).await.is_err() { break; }
                    }
                }
            }
        })
    };

    drop(frame_tx);

    loop {
        tokio::select! {
            maybe_msg = rx.next() => match maybe_msg {
                Some(Ok(WsMessage::Close(_))) | None => break,
                Some(Err(_)) => break,
                _ => {}
            },
            maybe_frame = frame_rx.recv() => match maybe_frame {
                Some(s) => {
                    if tx.send(WsMessage::Text(s.into())).await.is_err() { break; }
                }
                None => break,
            }
        }
    }

    stats_task.abort();
    blocks_task.abort();
}
