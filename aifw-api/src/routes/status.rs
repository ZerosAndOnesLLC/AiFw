//! Status, metrics, live connections, pending-change stream, reload, the
//! pf state-table tuning knobs, the About payload, the pflog-derived
//! blocked-traffic feed, and the audit log listing.

use super::*;

#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub pf_running: bool,
    pub pf_states: u64,
    pub pf_rules: u64,
    pub aifw_rules: usize,
    pub aifw_active_rules: usize,
    pub nat_rules: usize,
    pub packets_in: u64,
    pub packets_out: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

#[derive(Debug, Serialize)]
pub struct MetricsResponse {
    pub pf_running: bool,
    pub pf_states_count: u64,
    pub pf_rules_count: u64,
    pub pf_packets_in: u64,
    pub pf_packets_out: u64,
    pub pf_bytes_in: u64,
    pub pf_bytes_out: u64,
    pub aifw_rules_total: usize,
    pub aifw_rules_active: usize,
    pub aifw_nat_rules_total: usize,
}

pub async fn status(State(state): State<AppState>) -> Result<Json<StatusResponse>, StatusCode> {
    let stats = state.pf.get_stats().await.map_err(|_| internal())?;
    let rules = state.rule_engine.list().await.map_err(|_| internal())?;
    let active = rules
        .iter()
        .filter(|r| r.status == RuleStatus::Active)
        .count();
    let nat_rules = state.nat_engine.list().await.map_err(|_| internal())?;

    Ok(Json(StatusResponse {
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
    }))
}

// --- pf state-table tuning (Settings → System → max states) ---

#[derive(serde::Serialize)]
pub struct PfTuningResponse {
    pub configured_max_states: u64,
    /// What pf is actually using right now. Drifts from `configured` if the
    /// last apply failed (e.g. pf wasn't running). UI uses both.
    pub live_max_states: Option<u64>,
    pub current_states: u64,
    pub min_states: u64,
    pub max_states: u64,
}

pub async fn get_pf_tuning(State(state): State<AppState>) -> Json<PfTuningResponse> {
    let stats = state.pf.get_stats().await.unwrap_or_default();
    Json(PfTuningResponse {
        configured_max_states: aifw_core::pf_tuning::configured_max_states(&state.pool).await,
        live_max_states: aifw_core::pf_tuning::live_max_states().await,
        current_states: stats.states_count,
        min_states: aifw_core::pf_tuning::MIN_STATES,
        max_states: aifw_core::pf_tuning::MAX_STATES,
    })
}

#[derive(serde::Deserialize)]
pub struct PutPfTuningRequest {
    pub max_states: u64,
}

pub async fn put_pf_tuning(
    State(state): State<AppState>,
    Json(req): Json<PutPfTuningRequest>,
) -> Result<Json<PfTuningResponse>, (StatusCode, String)> {
    aifw_core::pf_tuning::set_max_states(&state.pool, req.max_states)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    Ok(get_pf_tuning(State(state)).await)
}

/// `/api/v1/about` — surfaces version + memory breakdown for the About
/// page so it doesn't need to subscribe to the dashboard WebSocket just
/// to show a memory readout.
#[derive(serde::Serialize)]
pub struct AboutResponse {
    pub version: String,
    pub git_commit: Option<String>,
    pub built_at: Option<String>,
    pub memory: crate::ws::MemoryBreakdown,
}

pub async fn about_info(State(state): State<AppState>) -> Json<AboutResponse> {
    Json(AboutResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        // Optional build-time stamps. Both injected via env if set; otherwise
        // None — the About page treats them as best-effort.
        git_commit: option_env!("AIFW_GIT_COMMIT").map(|s| s.to_string()),
        built_at: option_env!("AIFW_BUILT_AT").map(|s| s.to_string()),
        memory: crate::ws::collect_memory_breakdown(&state).await,
    })
}

// --- Connections ---

#[derive(Debug, Deserialize, Default)]
pub struct ConnectionsQuery {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

pub async fn list_connections(
    State(state): State<AppState>,
    axum::extract::Query(q): axum::extract::Query<ConnectionsQuery>,
) -> Result<Json<ApiResponse<Vec<aifw_pf::PfState>>>, StatusCode> {
    // No per-request refresh — the background poller (start_polling) keeps
    // the snapshot fresh on a fixed cadence so /connections is an O(1) load.
    let connections = state.conntrack.snapshot();
    // Pagination (#178): a 50k-state appliance returning the full table on
    // every poll is multi-MB JSON per request. Cap unpaginated callers at
    // a sane default; honor explicit `limit`/`offset` when supplied.
    const DEFAULT_LIMIT: usize = 1_000;
    const MAX_LIMIT: usize = 10_000;
    let offset = q.offset.unwrap_or(0).min(connections.len());
    let limit = q.limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    let end = offset.saturating_add(limit).min(connections.len());
    let page = connections[offset..end].to_vec();
    Ok(Json(ApiResponse { data: page }))
}

// --- Pending / Reload ---

pub async fn get_pending(
    State(state): State<AppState>,
) -> Result<Json<crate::PendingChanges>, StatusCode> {
    let pending = state.pending.read().await.clone();
    Ok(Json(pending))
}

/// Issue a short-lived, single-use ticket for the WebSocket / SSE handshake.
/// The caller authenticates via the normal bearer header; the returned
/// ticket is then appended as `?ticket=<id>` to the stream URL. Browsers
/// can't set Authorization on WebSocket or EventSource, so the ticket is
/// the canonical way to prove identity on those endpoints.
pub async fn issue_ws_ticket(
    State(state): State<AppState>,
    auth_user: axum::Extension<crate::auth::AuthUser>,
) -> Json<serde_json::Value> {
    let ticket = state.ws_tickets.issue(&auth_user.user_id).await;
    Json(serde_json::json!({ "ticket": ticket, "expires_in_seconds": 30 }))
}

/// SSE stream that pushes PendingChanges whenever they mutate.
/// Auth handled by auth_middleware — for browsers use `?ticket=<id>`.
pub async fn pending_stream(
    State(state): State<AppState>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let mut rx = state.pending_tx.subscribe();

    let stream = async_stream::stream! {
        // Send current state immediately on connect.
        let current = state.pending.read().await.clone();
        if let Ok(json) = serde_json::to_string(&current) {
            yield Ok(Event::default().data(json));
        }

        // Then push on every change.
        while rx.changed().await.is_ok() {
            let val = rx.borrow_and_update().clone();
            if let Ok(json) = serde_json::to_string(&val) {
                yield Ok(Event::default().data(json));
            }
        }
    };

    Sse::new(stream).keep_alive(KeepAlive::default())
}

pub async fn reload(State(state): State<AppState>) -> Result<Json<MessageResponse>, StatusCode> {
    let mut errors = Vec::new();

    // Apply VLANs from DB to OS
    if let Err(e) = crate::iface::apply_vlans(&state.pool).await {
        tracing::error!("Failed to apply VLANs: {e}");
        errors.push(format!("vlans: {e}"));
    }

    // Sync alias pf tables before loading rules that reference them
    if let Err(e) = state.alias_engine.sync_all().await {
        tracing::error!("Failed to sync aliases: {e}");
        errors.push(format!("aliases: {e}"));
    }
    // Re-inject VPN rules before applying filter rules
    if let Ok(vpn_rules) = state.vpn_engine.collect_vpn_rules().await {
        state.rule_engine.set_extra_rules(vpn_rules).await;
    }
    if let Err(e) = state.rule_engine.apply_rules().await {
        tracing::error!("Failed to apply filter rules: {e}");
        errors.push(format!("filter: {e}"));
    }
    if let Err(e) = state.nat_engine.apply_rules().await {
        tracing::error!("Failed to apply NAT rules: {e}");
        errors.push(format!("nat: {e}"));
    }
    // Clear pending flags for firewall and NAT
    state
        .set_pending(|p| {
            p.firewall = false;
            p.nat = false;
        })
        .await;
    if errors.is_empty() {
        Ok(Json(MessageResponse {
            message: "Changes applied successfully".to_string(),
        }))
    } else {
        Ok(Json(MessageResponse {
            message: format!("Partial reload: {}", errors.join("; ")),
        }))
    }
}

// --- Blocked Traffic (pflog) ---

#[derive(Debug, Serialize)]
pub struct BlockedEntry {
    pub timestamp: String,
    pub action: String,
    pub direction: String,
    pub interface: String,
    pub protocol: String,
    pub src_addr: String,
    pub src_port: u16,
    pub dst_addr: String,
    pub dst_port: u16,
    pub reason: String,
}

pub async fn list_blocked_traffic() -> Result<Json<ApiResponse<Vec<BlockedEntry>>>, StatusCode> {
    let mut entries = Vec::new();

    // Read from /var/log/pflog binary — this is where pf logs all block/pass with log flag
    // tcpdump -n -e -r /var/log/pflog shows: "rule X(match): block/pass in/out on iface: src > dst"
    if let Ok(output) = tokio::process::Command::new("/usr/local/bin/sudo")
        .args([
            "/usr/sbin/tcpdump",
            "-tttt",
            "-n",
            "-e",
            "-r",
            "/var/log/pflog",
        ])
        .output()
        .await
        && output.status.success()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().rev() {
            let action = if line.contains(": block ") {
                "block"
            } else if line.contains(": pass ") {
                "pass"
            } else {
                continue;
            };

            // -tttt format: "2026-04-01 13:09:28.475326 rule ..."
            let mut words = line.split_whitespace();
            let date_part = words.next().unwrap_or("");
            let time_part = words.next().unwrap_or("");
            let timestamp = format!("{date_part}T{time_part}");

            let mut entry = BlockedEntry {
                timestamp,
                action: action.to_string(),
                direction: String::new(),
                interface: String::new(),
                protocol: String::new(),
                src_addr: String::new(),
                src_port: 0,
                dst_addr: String::new(),
                dst_port: 0,
                reason: "policy".to_string(),
            };

            let action_pos = if action == "block" {
                line.find(": block ")
            } else {
                line.find(": pass ")
            };
            if let Some(pos) = action_pos {
                let rest = &line[pos + 2..];
                let parts: Vec<&str> = rest.split_whitespace().collect();
                entry.direction = parts.get(1).unwrap_or(&"").to_string();
                entry.interface = parts
                    .get(3)
                    .map(|s| s.trim_end_matches(':'))
                    .unwrap_or("")
                    .to_string();
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
            if line.contains("Flags [") || lower.contains(" tcp ") {
                entry.protocol = "tcp".to_string();
            } else if lower.contains(" udp ") {
                entry.protocol = "udp".to_string();
            } else if lower.contains("icmp") {
                entry.protocol = "icmp".to_string();
            } else if lower.contains(" esp ") || lower.contains("esp(") {
                entry.protocol = "esp".to_string();
            } else if lower.contains(" ah ") || lower.contains("ah(") {
                entry.protocol = "ah".to_string();
            } else if lower.contains(" gre ") || lower.contains("gre(") {
                entry.protocol = "gre".to_string();
            } else if lower.contains("igmp") {
                entry.protocol = "igmp".to_string();
            }

            if !entry.src_addr.is_empty() {
                entries.push(entry);
            }
        }
    }

    Ok(Json(ApiResponse { data: entries }))
}

// --- Metrics ---

pub async fn metrics(State(state): State<AppState>) -> Result<Json<MetricsResponse>, StatusCode> {
    let stats = state.pf.get_stats().await.map_err(|_| internal())?;
    let rules = state.rule_engine.list().await.map_err(|_| internal())?;
    let active = rules
        .iter()
        .filter(|r| r.status == RuleStatus::Active)
        .count();
    let nat_rules = state.nat_engine.list().await.map_err(|_| internal())?;

    Ok(Json(MetricsResponse {
        pf_running: stats.running,
        pf_states_count: stats.states_count,
        pf_rules_count: stats.rules_count,
        pf_packets_in: stats.packets_in,
        pf_packets_out: stats.packets_out,
        pf_bytes_in: stats.bytes_in,
        pf_bytes_out: stats.bytes_out,
        aifw_rules_total: rules.len(),
        aifw_rules_active: active,
        aifw_nat_rules_total: nat_rules.len(),
    }))
}

// --- Logs ---

pub async fn list_logs(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<Vec<aifw_core::audit::AuditEntry>>>, StatusCode> {
    let entries = state
        .rule_engine
        .audit()
        .list(100)
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: entries }))
}
