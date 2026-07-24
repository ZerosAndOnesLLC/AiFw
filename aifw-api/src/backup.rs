use aifw_core::config::FirewallConfig;
use aifw_core::config_manager::{ConfigDiff, ConfigManager, ConfigVersion};
use axum::{
    Json,
    extract::{Query, Request, State},
    http::{Method, StatusCode},
    middleware::Next,
    response::Response,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::AppState;

fn internal() -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}

// ============================================================
// Commit Confirm — Juniper-style timed rollback
// ============================================================

#[derive(Clone, Serialize)]
pub struct CommitConfirmState {
    pub active: bool,
    pub expires_at: String,
    pub seconds_remaining: u64,
    pub description: String,
}

type CommitConfirmStore = Arc<RwLock<Option<CommitConfirmInner>>>;

struct CommitConfirmInner {
    rollback_config: String, // JSON snapshot of pre-change config
    expires_at: chrono::DateTime<chrono::Utc>,
    description: String,
    cancel_tx: tokio::sync::oneshot::Sender<()>,
}

fn commit_store() -> &'static CommitConfirmStore {
    static STORE: std::sync::OnceLock<CommitConfirmStore> = std::sync::OnceLock::new();
    STORE.get_or_init(|| Arc::new(RwLock::new(None)))
}

#[derive(Serialize)]
pub struct ApiResponse<T: Serialize> {
    pub data: T,
}

#[derive(Serialize)]
pub struct MessageResponse {
    pub message: String,
}

// ============================================================
// History
// ============================================================

#[derive(Deserialize)]
pub struct HistoryParams {
    pub limit: Option<i64>,
}

pub async fn config_history(
    State(state): State<AppState>,
    Query(params): Query<HistoryParams>,
) -> Result<Json<ApiResponse<Vec<ConfigVersion>>>, StatusCode> {
    let mgr = ConfigManager::new(state.pool.clone());
    let history = mgr
        .history(params.limit.unwrap_or(50))
        .await
        .map_err(|_| internal())?;
    Ok(Json(ApiResponse { data: history }))
}

// ============================================================
// Get version JSON
// ============================================================

#[derive(Deserialize)]
pub struct VersionParams {
    pub version: i64,
}

pub async fn get_version(
    State(state): State<AppState>,
    Query(params): Query<VersionParams>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    let mgr = ConfigManager::new(state.pool.clone());
    let config = mgr
        .get_version(params.version)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let json: serde_json::Value = serde_json::to_value(&config).map_err(|_| internal())?;
    Ok(Json(json))
}

// ============================================================
// Diff two versions
// ============================================================

#[derive(Deserialize)]
pub struct DiffParams {
    pub v1: i64,
    pub v2: i64,
}

#[derive(Serialize)]
pub struct DetailedDiff {
    #[serde(flatten)]
    pub summary: ConfigDiff,
    pub v1_json: serde_json::Value,
    pub v2_json: serde_json::Value,
}

pub async fn diff_versions(
    State(state): State<AppState>,
    Query(params): Query<DiffParams>,
) -> Result<Json<ApiResponse<DetailedDiff>>, StatusCode> {
    let mgr = ConfigManager::new(state.pool.clone());
    let summary = mgr
        .diff(params.v1, params.v2)
        .await
        .map_err(|_| internal())?;
    let c1 = mgr.get_version(params.v1).await.map_err(|_| internal())?;
    let c2 = mgr.get_version(params.v2).await.map_err(|_| internal())?;
    let v1_json = serde_json::to_value(&c1).map_err(|_| internal())?;
    let v2_json = serde_json::to_value(&c2).map_err(|_| internal())?;

    Ok(Json(ApiResponse {
        data: DetailedDiff {
            summary,
            v1_json,
            v2_json,
        },
    }))
}

// ============================================================
// Save current state as a version
// ============================================================

#[derive(Deserialize)]
pub struct SaveVersionRequest {
    pub comment: Option<String>,
}

pub async fn save_version(
    State(state): State<AppState>,
    Json(req): Json<SaveVersionRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let config = build_current_config(&state).await?;
    let mgr = ConfigManager::new(state.pool.clone());
    mgr.migrate().await.map_err(|_| internal())?;
    let version = mgr
        .save_version(&config, "admin", req.comment.as_deref())
        .await
        .map_err(|_| internal())?;
    mgr.mark_applied(version).await.map_err(|_| internal())?;
    Ok(Json(MessageResponse {
        message: format!("Config saved as version {version}"),
    }))
}

// ============================================================
// Restore to a previous version
// ============================================================

#[derive(Deserialize)]
pub struct RestoreRequest {
    pub version: i64,
    #[serde(default)]
    pub interface_map: InterfaceMap,
}

pub async fn restore_version(
    State(state): State<AppState>,
    Json(req): Json<RestoreRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let mgr = ConfigManager::new(state.pool.clone());
    let config = mgr
        .get_version(req.version)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;

    apply_firewall_config_or_rollback(&state, &config, &req.interface_map).await?;

    mgr.mark_applied(req.version)
        .await
        .map_err(|_| internal())?;

    Ok(Json(MessageResponse {
        message: format!("Restored to version {}", req.version),
    }))
}

// ============================================================
// Config checker — validate current config
// ============================================================

#[derive(Serialize)]
pub struct ConfigCheck {
    pub valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub info: Vec<String>,
}

pub async fn check_config(
    State(state): State<AppState>,
) -> Result<Json<ApiResponse<ConfigCheck>>, StatusCode> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    let mut info = Vec::new();

    // Check rules
    let rules = state
        .rule_engine
        .list_rules()
        .await
        .map_err(|_| internal())?;
    info.push(format!("{} firewall rules configured", rules.len()));

    // Check for rules with Any/Any (too permissive)
    for rule in &rules {
        if rule.action == aifw_common::Action::Pass
            && rule.rule_match.src_addr == aifw_common::Address::Any
            && rule.rule_match.dst_addr == aifw_common::Address::Any
            && rule.rule_match.dst_port.is_none()
        {
            warnings.push(format!(
                "Rule '{}' passes all traffic (any -> any, no port restriction)",
                rule.label.as_deref().unwrap_or(&rule.id.to_string()[..8])
            ));
        }
    }

    // Check NAT
    let nat_rules = state
        .nat_engine
        .list_rules()
        .await
        .map_err(|_| internal())?;
    info.push(format!("{} NAT rules configured", nat_rules.len()));

    // Check for duplicate NAT port forwards
    let mut seen_ports: std::collections::HashSet<String> = std::collections::HashSet::new();
    for nat in &nat_rules {
        {
            let key = format!("{}:{:?}:{}", nat.interface, nat.protocol, nat.redirect);
            if !seen_ports.insert(key.clone()) {
                warnings.push(format!(
                    "Possible duplicate NAT forward on {}",
                    nat.interface
                ));
            }
        }
    }

    // Check GeoIP
    let geoip_rules = state
        .geoip_engine
        .list_rules()
        .await
        .map_err(|_| internal())?;
    if !geoip_rules.is_empty() {
        info.push(format!("{} Geo-IP rules configured", geoip_rules.len()));
    }

    // Check VPN
    let wg = state
        .vpn_engine
        .list_wg_tunnels()
        .await
        .map_err(|_| internal())?;
    let ipsec = state
        .vpn_engine
        .list_ipsec_sas()
        .await
        .map_err(|_| internal())?;
    if !wg.is_empty() {
        info.push(format!("{} WireGuard tunnel(s)", wg.len()));
    }
    if !ipsec.is_empty() {
        info.push(format!("{} legacy IPsec SA record(s)", ipsec.len()));
    }
    let ipsec_tunnels = state
        .ipsec_engine
        .list_tunnels()
        .await
        .map_err(|_| internal())?;
    if !ipsec_tunnels.is_empty() {
        info.push(format!("{} IPsec tunnel(s)", ipsec_tunnels.len()));
    }

    // Check DNS
    let dns = tokio::fs::read_to_string("/etc/resolv.conf")
        .await
        .unwrap_or_default();
    let dns_count = dns.lines().filter(|l| l.starts_with("nameserver")).count();
    if dns_count == 0 {
        errors.push("No DNS nameservers configured in /etc/resolv.conf".to_string());
    } else {
        info.push(format!("{} DNS nameserver(s) configured", dns_count));
    }

    // Check static routes
    let routes =
        sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM static_routes WHERE enabled = 1")
            .fetch_one(&state.pool)
            .await
            .map(|r| r.0)
            .unwrap_or(0);
    if routes > 0 {
        info.push(format!("{} static route(s)", routes));
    }

    // Check pf status
    let pf_ok = state.pf.get_stats().await.is_ok();
    if pf_ok {
        info.push("pf firewall is responding".to_string());
    } else {
        warnings.push("pf firewall is not responding — rules may not be loaded".to_string());
    }

    // Check for empty ruleset
    if rules.is_empty() {
        warnings.push(
            "No firewall rules configured — all traffic may be blocked or allowed by default"
                .to_string(),
        );
    }

    // DHCP validation
    validate_dhcp(&state.pool, &mut errors, &mut warnings, &mut info).await;

    let valid = errors.is_empty();

    Ok(Json(ApiResponse {
        data: ConfigCheck {
            valid,
            errors,
            warnings,
            info,
        },
    }))
}

// ============================================================
// Commit Confirm endpoints
// ============================================================

pub async fn commit_confirm_start(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let timeout_secs = payload
        .get("timeout_secs")
        .and_then(|v| v.as_u64())
        .unwrap_or(300);
    let description = payload
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("Config change")
        .to_string();

    // Capture current state as the rollback snapshot. Callers that need to
    // capture state *before* their own changes (e.g. the OPNsense importer)
    // should use `commit_confirm_arm_with_snapshot` instead.
    let snapshot_json = capture_runtime_snapshot(&state).await?;
    commit_confirm_arm_with_snapshot(state.clone(), snapshot_json, description, timeout_secs)
        .await
        .map(|msg| Json(MessageResponse { message: msg }))
}

/// Build a JSON snapshot of the live rules + NAT + aliases + routes for use
/// as a commit-confirm rollback target. The snapshot is a `FirewallConfig`
/// with only the sections `apply_firewall_config` knows how to delete +
/// restore — VPN, geo-IP, and other engine state stays untouched on revert.
pub(crate) async fn capture_runtime_snapshot(state: &AppState) -> Result<String, StatusCode> {
    use aifw_core::config::*;

    let rules = state
        .rule_engine
        .list_rules()
        .await
        .map_err(|_| internal())?;
    let nat_rules = state
        .nat_engine
        .list_rules()
        .await
        .map_err(|_| internal())?;
    let aliases = build_aliases_section(state).await;
    let static_routes = build_static_routes_section(&state.pool).await;

    let snapshot = FirewallConfig {
        rules: rules
            .iter()
            .map(|r| RuleConfig {
                id: r.id.to_string(),
                priority: r.priority,
                action: r.action,
                direction: r.direction,
                protocol: r.protocol,
                interface: r.interface.as_ref().map(|i| i.0.clone()),
                src_addr: Some(r.rule_match.src_addr.to_string()),
                src_port_start: r.rule_match.src_port.as_ref().map(|p| p.start),
                src_port_end: r.rule_match.src_port.as_ref().map(|p| p.end),
                dst_addr: Some(r.rule_match.dst_addr.to_string()),
                dst_port_start: r.rule_match.dst_port.as_ref().map(|p| p.start),
                dst_port_end: r.rule_match.dst_port.as_ref().map(|p| p.end),
                log: r.log,
                quick: r.quick,
                label: r.label.clone(),
                state_tracking: r.state_options.tracking,
                status: r.status,
                ip_version: r.ip_version,
                src_invert: r.src_invert,
                dst_invert: r.dst_invert,
                schedule_id: r.schedule_id.clone(),
                gateway: r.gateway.clone(),
            })
            .collect(),
        nat: nat_rules
            .iter()
            .map(|n| NatRuleConfig {
                id: n.id.to_string(),
                nat_type: n.nat_type,
                interface: n.interface.0.clone(),
                protocol: n.protocol,
                src_addr: Some(n.src_addr.to_string()),
                src_port_start: n.src_port.as_ref().map(|p| p.start),
                src_port_end: n.src_port.as_ref().map(|p| p.end),
                dst_addr: Some(n.dst_addr.to_string()),
                dst_port_start: n.dst_port.as_ref().map(|p| p.start),
                dst_port_end: n.dst_port.as_ref().map(|p| p.end),
                redirect_addr: n.redirect.address.to_string(),
                redirect_port_start: n.redirect.port.as_ref().map(|p| p.start),
                redirect_port_end: n.redirect.port.as_ref().map(|p| p.end),
                label: n.label.clone(),
                status: n.status,
            })
            .collect(),
        aliases,
        static_routes,
        ..Default::default()
    };
    serde_json::to_string(&snapshot).map_err(|_| internal())
}

/// Arm commit-confirm with a caller-supplied snapshot. Returns `409 Conflict`
/// if a confirm window is already active — concurrent imports / config
/// changes cannot stack their rollback timers on top of each other (the
/// previous global-store overwrite would silently drop the older timer).
pub(crate) async fn commit_confirm_arm_with_snapshot(
    state: AppState,
    snapshot_json: String,
    description: String,
    timeout_secs: u64,
) -> Result<String, StatusCode> {
    // Never arm with a rollback target that can't actually roll back
    // (#535): the timer would fire, fail to parse or apply the snapshot,
    // and leave the operator believing a revert happened. Parse and
    // validate it with the same checks the apply path uses.
    match serde_json::from_str::<FirewallConfig>(&snapshot_json) {
        Ok(snapshot) => {
            if let Err(e) = prevalidate_config(&snapshot, &InterfaceMap::new()) {
                tracing::error!(error = %e, "refusing to arm commit-confirm: snapshot fails validation");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }
        Err(e) => {
            tracing::error!(error = %e, "refusing to arm commit-confirm: snapshot is not a valid FirewallConfig");
            return Err(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
    {
        let store_read = commit_store().read().await;
        if store_read.is_some() {
            return Err(StatusCode::CONFLICT);
        }
    }

    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(timeout_secs as i64);
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();

    {
        let mut store = commit_store().write().await;
        if store.is_some() {
            // Lost a race with another armer between the read above and this
            // write — refuse rather than overwrite.
            return Err(StatusCode::CONFLICT);
        }
        *store = Some(CommitConfirmInner {
            rollback_config: snapshot_json.clone(),
            expires_at,
            description: description.clone(),
            cancel_tx,
        });
    }

    // Spawn timer that auto-rollbacks if not confirmed
    let rollback_state = state.clone();
    let store = commit_store().clone();

    tokio::spawn(async move {
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(timeout_secs)) => {
                // Timer expired — rollback!
                tracing::warn!("Commit confirm expired after {timeout_secs}s — rolling back");
                if let Some(inner) = store.write().await.take() {
                    // Parse validated at arm time; a failure here means the
                    // stored snapshot was corrupted in memory — log loudly,
                    // never silently skip the rollback (#535).
                    match serde_json::from_str::<FirewallConfig>(&inner.rollback_config) {
                        Ok(config) => {
                            if let Err(e) = apply_firewall_config(&rollback_state, &config, &InterfaceMap::new()).await {
                                tracing::error!(error = ?e, "commit confirm ROLLBACK FAILED — system may be partially configured");
                            } else {
                                tracing::info!("Config rolled back successfully");
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "commit confirm ROLLBACK FAILED — stored snapshot unparseable; system keeps the unconfirmed config");
                        }
                    }
                }
            }
            _ = cancel_rx => {
                // Confirmed — do nothing, config stays
                tracing::info!("Commit confirmed — config accepted");
            }
        }
    });

    Ok(format!(
        "Commit confirm started. You have {timeout_secs} seconds to confirm. If you do not log in and confirm, the configuration will automatically revert."
    ))
}

pub async fn commit_confirm_accept() -> Result<Json<MessageResponse>, StatusCode> {
    let mut store = commit_store().write().await;
    if let Some(inner) = store.take() {
        // Safely ignorable: oneshot send only fails if the rollback timer task
        // already exited (timer fired or task dropped) — nothing left to cancel.
        let _ = inner.cancel_tx.send(()); // Cancel the rollback timer
        Ok(Json(MessageResponse {
            message: "Configuration confirmed and accepted permanently.".to_string(),
        }))
    } else {
        Ok(Json(MessageResponse {
            message: "No pending commit confirm to accept.".to_string(),
        }))
    }
}

pub async fn commit_confirm_status() -> Result<Json<CommitConfirmState>, StatusCode> {
    let store = commit_store().read().await;
    if let Some(inner) = store.as_ref() {
        let remaining = (inner.expires_at - chrono::Utc::now()).num_seconds().max(0) as u64;
        Ok(Json(CommitConfirmState {
            active: true,
            expires_at: inner.expires_at.to_rfc3339(),
            seconds_remaining: remaining,
            description: inner.description.clone(),
        }))
    } else {
        Ok(Json(CommitConfirmState {
            active: false,
            expires_at: String::new(),
            seconds_remaining: 0,
            description: String::new(),
        }))
    }
}

// ============================================================
// Helpers
// ============================================================

/// Build a FirewallConfig from current live state
pub(crate) async fn build_current_config(state: &AppState) -> Result<FirewallConfig, StatusCode> {
    use aifw_core::config::*;

    let rules = state
        .rule_engine
        .list_rules()
        .await
        .map_err(|_| internal())?;
    let nat_rules = state
        .nat_engine
        .list_rules()
        .await
        .map_err(|_| internal())?;
    let geoip_rules = state
        .geoip_engine
        .list_rules()
        .await
        .map_err(|_| internal())?;
    let wg_tunnels = state
        .vpn_engine
        .list_wg_tunnels()
        .await
        .map_err(|_| internal())?;
    let ipsec_sas = state
        .vpn_engine
        .list_ipsec_sas()
        .await
        .map_err(|_| internal())?;
    let ipsec_tunnels = state
        .ipsec_engine
        .list_tunnels()
        .await
        .map_err(|_| internal())?;

    let queues = state.shaping_engine.list_queues().await.unwrap_or_default();
    let rate_limits = state
        .shaping_engine
        .list_rate_limits()
        .await
        .unwrap_or_default();

    let sni_rules = state.tls_engine.list_sni_rules().await.unwrap_or_default();
    let ja3 = state.tls_engine.list_ja3_blocks().await.unwrap_or_default();

    let carp_vips = state
        .cluster_engine
        .list_carp_vips()
        .await
        .unwrap_or_default();
    let cluster_nodes = state.cluster_engine.list_nodes().await.unwrap_or_default();
    let pfsync = state.cluster_engine.get_pfsync().await.ok().flatten();

    let max_states = aifw_core::pf_tuning::configured_max_states(&state.pool).await;

    let dns = tokio::fs::read_to_string("/etc/resolv.conf")
        .await
        .unwrap_or_default();
    let dns_servers: Vec<String> = dns
        .lines()
        .filter_map(|l| l.strip_prefix("nameserver").map(|s| s.trim().to_string()))
        .collect();

    let auth = &state.auth_settings;

    // PERF-H7: one query for all peers, grouped by tunnel, instead of N+1.
    let mut peers_by_tunnel = state
        .vpn_engine
        .list_all_wg_peers_grouped()
        .await
        .unwrap_or_default();
    let mut wireguard: Vec<WireguardTunnelConfig> = Vec::with_capacity(wg_tunnels.len());
    for t in &wg_tunnels {
        let peers = peers_by_tunnel.remove(&t.id).unwrap_or_default();
        wireguard.push(WireguardTunnelConfig {
            id: t.id.to_string(),
            name: t.name.clone(),
            interface: t.interface.0.clone(),
            listen_port: t.listen_port,
            private_key: t.private_key.clone(),
            public_key: t.public_key.clone(),
            address: t.address.to_string(),
            address6: t.address6.as_ref().map(|a| a.to_string()),
            dns: t.dns.clone(),
            mtu: t.mtu,
            peers: peers
                .iter()
                .map(|p| WireguardPeerConfig {
                    id: p.id.to_string(),
                    name: p.name.clone(),
                    public_key: p.public_key.clone(),
                    preshared_key: p.preshared_key.clone(),
                    endpoint: p.endpoint.clone(),
                    allowed_ips: p.allowed_ips.iter().map(|a| a.to_string()).collect(),
                    persistent_keepalive: p.persistent_keepalive,
                })
                .collect(),
        });
    }

    let config = FirewallConfig {
        schema_version: 1,
        system: SystemConfig {
            hostname: gethostname().unwrap_or_else(|| "aifw".to_string()),
            dns_servers,
            wan_interface: String::new(),
            lan_interface: None,
            lan_ip: None,
            api_listen: "0.0.0.0".to_string(),
            api_port: 8080,
            ui_enabled: true,
            ..SystemConfig::default()
        },
        auth: AuthConfig {
            access_token_expiry_mins: auth.access_token_expiry_mins,
            refresh_token_expiry_days: auth.refresh_token_expiry_days,
            require_totp: auth.require_totp,
            require_totp_for_oauth: false,
            auto_create_oauth_users: true,
        },
        rules: rules
            .iter()
            .map(|r| RuleConfig {
                id: r.id.to_string(),
                priority: r.priority,
                action: r.action,
                direction: r.direction,
                protocol: r.protocol,
                interface: r.interface.as_ref().map(|i| i.0.clone()),
                src_addr: Some(r.rule_match.src_addr.to_string()),
                src_port_start: r.rule_match.src_port.as_ref().map(|p| p.start),
                src_port_end: r.rule_match.src_port.as_ref().map(|p| p.end),
                dst_addr: Some(r.rule_match.dst_addr.to_string()),
                dst_port_start: r.rule_match.dst_port.as_ref().map(|p| p.start),
                dst_port_end: r.rule_match.dst_port.as_ref().map(|p| p.end),
                log: r.log,
                quick: r.quick,
                label: r.label.clone(),
                state_tracking: r.state_options.tracking,
                status: r.status,
                ip_version: r.ip_version,
                src_invert: r.src_invert,
                dst_invert: r.dst_invert,
                schedule_id: r.schedule_id.clone(),
                gateway: r.gateway.clone(),
            })
            .collect(),
        nat: nat_rules
            .iter()
            .map(|n| NatRuleConfig {
                id: n.id.to_string(),
                nat_type: n.nat_type,
                interface: n.interface.0.clone(),
                protocol: n.protocol,
                src_addr: Some(n.src_addr.to_string()),
                src_port_start: n.src_port.as_ref().map(|p| p.start),
                src_port_end: n.src_port.as_ref().map(|p| p.end),
                dst_addr: Some(n.dst_addr.to_string()),
                dst_port_start: n.dst_port.as_ref().map(|p| p.start),
                dst_port_end: n.dst_port.as_ref().map(|p| p.end),
                redirect_addr: n.redirect.address.to_string(),
                redirect_port_start: n.redirect.port.as_ref().map(|p| p.start),
                redirect_port_end: n.redirect.port.as_ref().map(|p| p.end),
                label: n.label.clone(),
                status: n.status,
            })
            .collect(),
        queues: queues
            .iter()
            .map(|q| QueueConfigEntry {
                id: q.id.to_string(),
                name: q.name.clone(),
                interface: q.interface.0.clone(),
                queue_type: q.queue_type,
                bandwidth_value: q.bandwidth.value,
                bandwidth_unit: q.bandwidth.unit,
                traffic_class: q.traffic_class,
                bandwidth_pct: q.bandwidth_pct,
                default: q.default,
                status: q.status,
                fq_codel: q.fq_codel,
            })
            .collect(),
        rate_limits: rate_limits
            .iter()
            .map(|r| RateLimitEntry {
                id: r.id.to_string(),
                name: r.name.clone(),
                interface: r.interface.as_ref().map(|i| i.0.clone()),
                protocol: r.protocol,
                dst_port_start: r.dst_port.as_ref().map(|p| p.start),
                dst_port_end: r.dst_port.as_ref().map(|p| p.end),
                max_connections: r.max_connections,
                window_secs: r.window_secs,
                overload_table: r.overload_table.clone(),
                flush_states: r.flush_states,
                status: r.status,
            })
            .collect(),
        vpn: VpnConfig {
            wireguard,
            ipsec: ipsec_sas
                .iter()
                .map(|s| IpsecSaConfig {
                    id: s.id.to_string(),
                    name: s.name.clone(),
                    src_addr: s.src_addr.to_string(),
                    dst_addr: s.dst_addr.to_string(),
                    protocol: s.protocol,
                    mode: s.mode,
                    enc_algo: s.enc_algo.clone(),
                    auth_algo: s.auth_algo.clone(),
                })
                .collect(),
            ipsec_tunnels,
        },
        geoip: geoip_rules
            .iter()
            .map(|g| GeoIpEntry {
                id: g.id.to_string(),
                country: g.country.0.clone(),
                action: g.action,
                label: g.label.clone(),
                status: g.status,
            })
            .collect(),
        tls: TlsConfig {
            min_version: "tls12".to_string(),
            block_self_signed: false,
            block_expired: true,
            block_weak_keys: true,
            blocked_ja3: ja3.into_iter().map(|(hash, _, _)| hash).collect(),
            sni_rules: sni_rules
                .iter()
                .map(|r| SniRuleConfig {
                    id: r.id.to_string(),
                    pattern: r.pattern.clone(),
                    action: r.action,
                    label: r.label.clone(),
                })
                .collect(),
        },
        ha: HaConfig {
            carp_vips: carp_vips
                .iter()
                .map(|v| CarpVipConfig {
                    id: v.id.to_string(),
                    vhid: v.vhid,
                    virtual_ip: v.virtual_ip.to_string(),
                    prefix: v.prefix,
                    interface: v.interface.0.clone(),
                    password: v.password.clone(),
                })
                .collect(),
            pfsync: pfsync.as_ref().map(|p| PfsyncEntry {
                sync_interface: p.sync_interface.0.clone(),
                sync_peer: p.sync_peer.as_ref().map(|a| a.to_string()),
                defer: p.defer,
            }),
            nodes: cluster_nodes
                .iter()
                .map(|n| ClusterNodeConfig {
                    id: n.id.to_string(),
                    name: n.name.clone(),
                    address: n.address.to_string(),
                    role: enum_as_string(&n.role),
                })
                .collect(),
        },
        tuning: vec![TuningEntry {
            key: "pf.max_states".to_string(),
            value: max_states.to_string(),
            target: "sysctl".to_string(),
            reason: "pf state table size".to_string(),
            enabled: true,
        }],
        dhcp: build_dhcp_section(&state.pool).await,
        aliases: build_aliases_section(state).await,
        static_routes: build_static_routes_section(&state.pool).await,
        dns_resolver: Some(crate::dns_resolver::load_config(&state.pool).await),
    };

    Ok(config)
}

async fn build_aliases_section(state: &AppState) -> Vec<aifw_core::config::AliasConfig> {
    use aifw_core::config::AliasConfig;
    state
        .alias_engine
        .list()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|a| AliasConfig {
            id: a.id.to_string(),
            name: a.name,
            alias_type: a.alias_type.as_str().to_string(),
            entries: a.entries,
            description: a.description,
            enabled: a.enabled,
        })
        .collect()
}

async fn build_static_routes_section(
    pool: &sqlx::SqlitePool,
) -> Vec<aifw_core::config::StaticRouteConfig> {
    use aifw_core::config::StaticRouteConfig;
    sqlx::query_as::<
        _,
        (String, String, String, Option<String>, i64, bool, Option<String>, i64),
    >(
        "SELECT id, destination, gateway, interface, COALESCE(metric,0), enabled, description, COALESCE(fib,0) FROM static_routes ORDER BY metric ASC",
    )
    .fetch_all(pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(id, destination, gateway, interface, metric, enabled, description, fib)| StaticRouteConfig {
        id,
        destination,
        gateway,
        interface,
        metric: metric as i32,
        enabled,
        description,
        fib: fib as u32,
    })
    .collect()
}

async fn build_dhcp_section(pool: &sqlx::SqlitePool) -> aifw_core::config::DhcpSection {
    use aifw_core::config::*;
    use sqlx::Row;

    // --- global key/value config -----------------------------
    let mut global = DhcpGlobalSection::default();
    let rows = sqlx::query_as::<_, (String, String)>("SELECT key, value FROM dhcp_config")
        .fetch_all(pool)
        .await
        .unwrap_or_default();
    for (key, value) in rows {
        match key.as_str() {
            "enabled" => global.enabled = value == "true",
            "interfaces" => global.interfaces = split_csv(&value),
            "authoritative" => global.authoritative = value == "true",
            "default_lease_time" => global.default_lease_time = value.parse().unwrap_or(3600),
            "max_lease_time" => global.max_lease_time = value.parse().unwrap_or(86400),
            "dns_servers" => global.dns_servers = split_csv(&value),
            "domain_name" => global.domain_name = value,
            "domain_search" => global.domain_search = split_csv(&value),
            "ntp_servers" => global.ntp_servers = split_csv(&value),
            "wins_servers" => global.wins_servers = split_csv(&value),
            "next_server" => global.next_server = if value.is_empty() { None } else { Some(value) },
            "boot_filename" => {
                global.boot_filename = if value.is_empty() { None } else { Some(value) }
            }
            "log_level" => global.log_level = value,
            "log_format" => global.log_format = value,
            "api_port" => global.api_port = value.parse().unwrap_or(9967),
            "workers" => global.workers = value.parse().unwrap_or(1),
            "accept_relayed" => global.accept_relayed = value == "true",
            "relay_rate_limit_burst" => {
                global.relay_rate_limit_burst = value.parse().unwrap_or(200)
            }
            "relay_rate_limit_pps" => global.relay_rate_limit_pps = value.parse().unwrap_or(100.0),
            _ => {}
        }
    }

    // --- subnets ---------------------------------------------
    let subnet_rows = sqlx::query(
        "SELECT id, network, pool_start, pool_end, gateway, dns_servers, domain_name, \
         lease_time, max_lease_time, renewal_time, rebinding_time, preferred_time, \
         subnet_type, delegated_length, enabled, description, \
         trusted_relays, ntp_servers, options, created_at FROM dhcp_subnets ORDER BY created_at ASC"
    ).fetch_all(pool).await.unwrap_or_default();

    let subnets: Vec<DhcpSubnetConfig> = subnet_rows
        .into_iter()
        .map(|r| {
            let trusted_relays = r
                .try_get::<String, _>("trusted_relays")
                .ok()
                .and_then(|s| serde_json::from_str::<Vec<String>>(&s).ok())
                .unwrap_or_default();
            let options = r
                .try_get::<String, _>("options")
                .ok()
                .and_then(|s| serde_json::from_str::<Vec<DhcpOptionOverrideConfig>>(&s).ok())
                .unwrap_or_default();
            DhcpSubnetConfig {
                id: r.get("id"),
                network: r.get("network"),
                pool_start: r.get("pool_start"),
                pool_end: r.get("pool_end"),
                gateway: r.get("gateway"),
                dns_servers: r.get("dns_servers"),
                domain_name: r.get("domain_name"),
                lease_time: r.get::<Option<i64>, _>("lease_time").map(|v| v as u32),
                max_lease_time: r.get::<Option<i64>, _>("max_lease_time").map(|v| v as u32),
                renewal_time: r.get::<Option<i64>, _>("renewal_time").map(|v| v as u32),
                rebinding_time: r.get::<Option<i64>, _>("rebinding_time").map(|v| v as u32),
                preferred_time: r.get::<Option<i64>, _>("preferred_time").map(|v| v as u32),
                subnet_type: r
                    .get::<Option<String>, _>("subnet_type")
                    .unwrap_or_else(|| "address".to_string()),
                delegated_length: r.get::<Option<i64>, _>("delegated_length").map(|v| v as u8),
                enabled: r.get("enabled"),
                description: r.get("description"),
                trusted_relays,
                ntp_servers: r.try_get::<Option<String>, _>("ntp_servers").ok().flatten(),
                options,
                created_at: r.get("created_at"),
            }
        })
        .collect();

    // --- reservations ----------------------------------------
    let reservations: Vec<DhcpReservationConfig> = sqlx::query_as::<_,
        (String, Option<String>, String, String, Option<String>, Option<String>, Option<String>, String)>(
        "SELECT id, subnet_id, mac_address, ip_address, hostname, client_id, description, created_at \
         FROM dhcp_reservations ORDER BY ip_address ASC"
    ).fetch_all(pool).await.unwrap_or_default()
    .into_iter().map(|(id, subnet_id, mac, ip, hostname, client_id, description, created_at)| {
        DhcpReservationConfig { id, subnet_id, mac_address: mac, ip_address: ip, hostname, client_id, description, created_at }
    }).collect();

    // --- DDNS ------------------------------------------------
    let mut ddns = DhcpDdnsSection::default();
    let rows = sqlx::query_as::<_, (String, String)>("SELECT key, value FROM dhcp_ddns_config")
        .fetch_all(pool)
        .await
        .unwrap_or_default();
    for (key, value) in rows {
        match key.as_str() {
            "enabled" => ddns.enabled = value == "true",
            "forward_zone" => ddns.forward_zone = value,
            "reverse_zone_v4" => ddns.reverse_zone_v4 = value,
            "reverse_zone_v6" => ddns.reverse_zone_v6 = value,
            "dns_server" => ddns.dns_server = value,
            "tsig_key" => ddns.tsig_key = value,
            "tsig_algorithm" => ddns.tsig_algorithm = value,
            "tsig_secret" => ddns.tsig_secret = value,
            "ttl" => ddns.ttl = value.parse().unwrap_or(300),
            _ => {}
        }
    }

    // --- DHCP HA ---------------------------------------------
    let mut ha = DhcpHaSection::default();
    let rows = sqlx::query_as::<_, (String, String)>("SELECT key, value FROM dhcp_ha_config")
        .fetch_all(pool)
        .await
        .unwrap_or_default();
    for (key, value) in rows {
        match key.as_str() {
            "mode" => ha.mode = value,
            "peer" => ha.peer = nonempty(value),
            "listen" => ha.listen = nonempty(value),
            "scope_split" => ha.scope_split = value.parse().ok(),
            "mclt" => ha.mclt = value.parse().ok(),
            "partner_down_delay" => ha.partner_down_delay = value.parse().ok(),
            "node_id" => ha.node_id = value.parse().ok(),
            "peers" => ha.peers = nonempty(value.clone()).map(|_| split_csv(&value)),
            "tls_cert" => ha.tls_cert = nonempty(value),
            "tls_key" => ha.tls_key = nonempty(value),
            "tls_ca" => ha.tls_ca = nonempty(value),
            _ => {}
        }
    }

    DhcpSection {
        global,
        subnets,
        reservations,
        ddns,
        dhcp_ha: ha,
    }
}

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect()
}

fn nonempty(s: String) -> Option<String> {
    if s.is_empty() { None } else { Some(s) }
}

async fn validate_dhcp(
    pool: &sqlx::SqlitePool,
    errors: &mut Vec<String>,
    warnings: &mut Vec<String>,
    info: &mut Vec<String>,
) {
    let dhcp = build_dhcp_section(pool).await;

    if !dhcp.global.enabled && dhcp.subnets.is_empty() {
        return; // no DHCP configured, nothing to check
    }
    info.push(format!("{} DHCP subnet(s) configured", dhcp.subnets.len()));
    if !dhcp.reservations.is_empty() {
        info.push(format!(
            "{} DHCP reservation(s) configured",
            dhcp.reservations.len()
        ));
    }

    use std::net::Ipv4Addr;

    // Per-subnet checks: gateway + pool inside CIDR, pool_start ≤ pool_end, relay IPs sane.
    for s in &dhcp.subnets {
        if !s.enabled {
            continue;
        }
        let Some((net_ip, prefix)) = parse_v4_cidr(&s.network) else {
            warnings.push(format!("DHCP subnet {}: invalid CIDR", s.network));
            continue;
        };

        // Skip IPv6 / prefix-delegation — only validate address-family IPv4 scopes.
        if s.subnet_type == "prefix-delegation" {
            continue;
        }

        if let Ok(gw) = s.gateway.parse::<Ipv4Addr>() {
            if !ipv4_in_subnet(gw, net_ip, prefix) {
                errors.push(format!(
                    "DHCP subnet {}: gateway {} is outside the subnet",
                    s.network, s.gateway
                ));
            }
        } else if !s.gateway.is_empty() {
            errors.push(format!(
                "DHCP subnet {}: gateway '{}' is not a valid IPv4 address",
                s.network, s.gateway
            ));
        }

        match (
            s.pool_start.parse::<Ipv4Addr>(),
            s.pool_end.parse::<Ipv4Addr>(),
        ) {
            (Ok(start), Ok(end)) => {
                if u32::from(start) > u32::from(end) {
                    errors.push(format!(
                        "DHCP subnet {}: pool_start {} > pool_end {}",
                        s.network, s.pool_start, s.pool_end
                    ));
                }
                if !ipv4_in_subnet(start, net_ip, prefix) {
                    errors.push(format!(
                        "DHCP subnet {}: pool_start {} outside subnet",
                        s.network, s.pool_start
                    ));
                }
                if !ipv4_in_subnet(end, net_ip, prefix) {
                    errors.push(format!(
                        "DHCP subnet {}: pool_end {} outside subnet",
                        s.network, s.pool_end
                    ));
                }
            }
            _ => errors.push(format!("DHCP subnet {}: invalid pool range", s.network)),
        }

        for relay in &s.trusted_relays {
            match relay.parse::<Ipv4Addr>() {
                Ok(ip) if ip.is_loopback() => errors.push(format!(
                    "DHCP subnet {}: trusted relay {} is a loopback address",
                    s.network, relay
                )),
                Err(_) => errors.push(format!(
                    "DHCP subnet {}: trusted relay '{}' is not a valid IPv4 address",
                    s.network, relay
                )),
                Ok(_) => {}
            }
        }

        // Global accept_relayed off + per-subnet trusted_relays set is user intent
        // mismatch — warn so the operator knows the whitelist won't be consulted.
        if !dhcp.global.accept_relayed && !s.trusted_relays.is_empty() {
            warnings.push(format!(
                "DHCP subnet {}: trusted_relays set but global accept_relayed is off — list will be ignored",
                s.network
            ));
        }

        // Generic option overrides — rDHCP refuses to start on bad entries, so
        // surface them as errors here before the operator saves/applies.
        let mut seen_codes: std::collections::HashSet<u8> = std::collections::HashSet::new();
        for opt in &s.options {
            if !seen_codes.insert(opt.code) {
                errors.push(format!(
                    "DHCP subnet {}: option {} is duplicated",
                    s.network, opt.code
                ));
            }
            if RESERVED_OPTION_CODES.contains(&opt.code) {
                errors.push(format!(
                    "DHCP subnet {}: option code {} is reserved",
                    s.network, opt.code
                ));
            } else if COLLISION_OPTION_CODES.contains(&opt.code) {
                errors.push(format!(
                    "DHCP subnet {}: option code {} conflicts with a typed field (router/dns/domain/ntp)",
                    s.network, opt.code
                ));
            } else if !is_option_override_safe(opt) {
                errors.push(format!(
                    "DHCP subnet {}: option {} has an invalid value for type '{}'",
                    s.network, opt.code, opt.value_type
                ));
            }
        }
    }

    // Overlapping pools across enabled v4 subnets (same network collision).
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for s in dhcp
        .subnets
        .iter()
        .filter(|s| s.enabled && s.subnet_type != "prefix-delegation")
    {
        if !seen.insert(s.network.clone()) {
            warnings.push(format!("DHCP: duplicate subnet {}", s.network));
        }
    }

    // Reservation checks: IP should be in its linked subnet, and unique.
    let mut reserved_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
    for r in &dhcp.reservations {
        if !reserved_ips.insert(r.ip_address.clone()) {
            errors.push(format!(
                "DHCP reservation IP {} is duplicated",
                r.ip_address
            ));
        }
        if let Some(sid) = &r.subnet_id {
            if let Some(subnet) = dhcp.subnets.iter().find(|s| &s.id == sid) {
                if let (Some((net_ip, prefix)), Ok(ip)) = (
                    parse_v4_cidr(&subnet.network),
                    r.ip_address.parse::<Ipv4Addr>(),
                ) && !ipv4_in_subnet(ip, net_ip, prefix)
                {
                    errors.push(format!(
                        "DHCP reservation {} (MAC {}) is outside subnet {}",
                        r.ip_address, r.mac_address, subnet.network
                    ));
                }
            } else {
                warnings.push(format!(
                    "DHCP reservation {} references missing subnet {}",
                    r.ip_address, sid
                ));
            }
        }
    }
}

/// Must mirror `aifw-api/src/dhcp.rs::validate_option_overrides` — kept in
/// sync with rDHCP src/config/validation.rs RESERVED_CODES.
const RESERVED_OPTION_CODES: &[u8] = &[0, 1, 28, 50, 51, 53, 54, 55, 57, 58, 59, 82, 255];
const COLLISION_OPTION_CODES: &[u8] = &[3, 6, 15, 42];

fn is_option_override_safe(o: &aifw_core::config::DhcpOptionOverrideConfig) -> bool {
    if RESERVED_OPTION_CODES.contains(&o.code) {
        return false;
    }
    if COLLISION_OPTION_CODES.contains(&o.code) {
        return false;
    }
    let v = o.value.trim();
    if v.is_empty() {
        return false;
    }
    match o.value_type.as_str() {
        "ip" => v.parse::<std::net::Ipv4Addr>().is_ok(),
        "ips" => {
            let parts: Vec<&str> = v
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .collect();
            !parts.is_empty()
                && parts
                    .iter()
                    .all(|p| p.parse::<std::net::Ipv4Addr>().is_ok())
        }
        "string" => v.len() <= 255 && v.bytes().all(|b| b.is_ascii_graphic() || b == b' '),
        "u8" => v.parse::<u8>().is_ok(),
        "u16" => v.parse::<u16>().is_ok(),
        "u32" => v.parse::<u32>().is_ok(),
        "hex" => {
            v.len() <= 510 && v.len().is_multiple_of(2) && v.chars().all(|c| c.is_ascii_hexdigit())
        }
        _ => false,
    }
}

fn parse_v4_cidr(cidr: &str) -> Option<(std::net::Ipv4Addr, u8)> {
    let (ip_str, prefix_str) = cidr.split_once('/')?;
    let ip: std::net::Ipv4Addr = ip_str.parse().ok()?;
    let prefix: u8 = prefix_str.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    Some((ip, prefix))
}

fn ipv4_in_subnet(ip: std::net::Ipv4Addr, net: std::net::Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask: u32 = u32::MAX.checked_shl(32 - prefix as u32).unwrap_or(0);
    (u32::from(ip) & mask) == (u32::from(net) & mask)
}

fn enum_as_string<T: serde::Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|val| val.as_str().map(String::from))
        .unwrap_or_default()
}

pub(crate) type InterfaceMap = std::collections::HashMap<String, Option<String>>;

// ============================================================
// Import/Restore preview — NIC name mismatch detection
// ============================================================

#[derive(Serialize)]
pub struct InterfaceInfo {
    pub name: String,
    pub mac: Option<String>,
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub ipv4_mode: Option<String>, // "dhcp" | "static" | "none"
    pub status: String,            // "up" | "down"
}

#[derive(Serialize, Default)]
pub struct DropSummary {
    pub rules: u32,
    pub nat: u32,
    pub wireguard: u32,
    pub carp: u32,
    pub queues: u32,
    pub rate_limits: u32,
    pub pfsync: bool,
}

#[derive(Serialize)]
pub struct ImportPreview {
    pub interfaces_found: Vec<String>,
    pub interfaces_missing: Vec<String>,
    pub interfaces_present: Vec<InterfaceInfo>,
    pub suggestions: std::collections::HashMap<String, String>,
    /// How many entries WILL BE DROPPED per section if every currently-missing
    /// interface is left unmapped. Updated client-side as user picks mappings.
    pub drop_summary_if_unmapped: DropSummary,
}

/// Walk a FirewallConfig and collect every interface-name reference.
fn collect_interface_refs(cfg: &FirewallConfig) -> std::collections::BTreeSet<String> {
    let mut set = std::collections::BTreeSet::new();
    for r in &cfg.rules {
        if let Some(i) = r.interface.as_deref() {
            set.insert(i.to_string());
        }
    }
    for n in &cfg.nat {
        set.insert(n.interface.clone());
    }
    for w in &cfg.vpn.wireguard {
        set.insert(w.interface.clone());
    }
    for v in &cfg.ha.carp_vips {
        set.insert(v.interface.clone());
    }
    if let Some(p) = &cfg.ha.pfsync {
        set.insert(p.sync_interface.clone());
    }
    for q in &cfg.queues {
        set.insert(q.interface.clone());
    }
    for rl in &cfg.rate_limits {
        if let Some(i) = rl.interface.as_deref() {
            set.insert(i.to_string());
        }
    }
    set
}

/// Count per-section entries that would be dropped if `missing` are unmapped.
fn compute_drop_summary(
    cfg: &FirewallConfig,
    missing: &std::collections::BTreeSet<String>,
) -> DropSummary {
    let mut s = DropSummary::default();
    for r in &cfg.rules {
        if r.interface.as_deref().is_some_and(|i| missing.contains(i)) {
            s.rules += 1;
        }
    }
    for n in &cfg.nat {
        if missing.contains(&n.interface) {
            s.nat += 1;
        }
    }
    for w in &cfg.vpn.wireguard {
        if missing.contains(&w.interface) {
            s.wireguard += 1;
        }
    }
    for v in &cfg.ha.carp_vips {
        if missing.contains(&v.interface) {
            s.carp += 1;
        }
    }
    for q in &cfg.queues {
        if missing.contains(&q.interface) {
            s.queues += 1;
        }
    }
    for rl in &cfg.rate_limits {
        if rl.interface.as_deref().is_some_and(|i| missing.contains(i)) {
            s.rate_limits += 1;
        }
    }
    if let Some(p) = &cfg.ha.pfsync
        && missing.contains(&p.sync_interface)
    {
        s.pfsync = true;
    }
    s
}

/// Heuristic: prefer an interface that shares the same non-digit base name.
/// Falls back to the first physical interface if no base match is available.
fn suggest_interface(missing: &str, present: &[InterfaceInfo]) -> Option<String> {
    let base = missing.trim_end_matches(|c: char| c.is_ascii_digit());
    let physical: Vec<&InterfaceInfo> = present
        .iter()
        .filter(|i| {
            !i.name.starts_with("lo")
                && !i.name.starts_with("pflog")
                && !i.name.starts_with("pfsync")
                && !i.name.starts_with("enc")
        })
        .collect();
    if !base.is_empty()
        && let Some(m) = physical.iter().find(|i| i.name.starts_with(base))
    {
        return Some(m.name.clone());
    }
    physical.first().map(|i| i.name.clone())
}

async fn collect_system_interfaces() -> Vec<InterfaceInfo> {
    let details = crate::iface::parse_ifconfig().await;
    let mut out = Vec::with_capacity(details.len());
    for d in details {
        let mode = crate::iface::get_rc_ipv4_mode(&d.name).await;
        out.push(InterfaceInfo {
            ipv4_mode: mode,
            name: d.name,
            mac: d.mac,
            ipv4: d.ipv4,
            ipv6: d.ipv6,
            status: d.status,
        });
    }
    out
}

/// Build the preview for a given FirewallConfig.
pub(crate) async fn build_import_preview(cfg: &FirewallConfig) -> ImportPreview {
    let refs = collect_interface_refs(cfg);
    let present = collect_system_interfaces().await;
    let present_names: std::collections::HashSet<String> =
        present.iter().map(|i| i.name.clone()).collect();

    let missing: std::collections::BTreeSet<String> = refs
        .iter()
        .filter(|i| !present_names.contains(*i))
        .cloned()
        .collect();

    let suggestions: std::collections::HashMap<String, String> = missing
        .iter()
        .filter_map(|m| suggest_interface(m, &present).map(|s| (m.clone(), s)))
        .collect();

    let drop = compute_drop_summary(cfg, &missing);

    ImportPreview {
        interfaces_found: refs.into_iter().collect(),
        interfaces_missing: missing.into_iter().collect(),
        interfaces_present: present,
        suggestions,
        drop_summary_if_unmapped: drop,
    }
}

#[derive(Deserialize)]
pub struct RestorePreviewQuery {
    pub version: i64,
}

pub async fn preview_import(
    State(_state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<ImportPreview>, StatusCode> {
    let config_val = payload.get("config").ok_or(StatusCode::BAD_REQUEST)?;
    let config: FirewallConfig =
        serde_json::from_value(config_val.clone()).map_err(|_| StatusCode::BAD_REQUEST)?;
    Ok(Json(build_import_preview(&config).await))
}

pub async fn preview_restore(
    State(state): State<AppState>,
    Query(q): Query<RestorePreviewQuery>,
) -> Result<Json<ImportPreview>, StatusCode> {
    let mgr = ConfigManager::new(state.pool.clone());
    let config = mgr
        .get_version(q.version)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    Ok(Json(build_import_preview(&config).await))
}

/// Resolve the target interface name via the provided map.
/// Returns `None` iff the entry should be dropped (explicit skip).
fn map_iface(name: &str, map: &InterfaceMap) -> Option<String> {
    match map.get(name) {
        Some(Some(new)) => Some(new.clone()),
        Some(None) => None,
        None => Some(name.to_string()),
    }
}

/// Apply a FirewallConfig to live state: wipe all tracked tables, re-insert
/// from the config, then reload pf anchors. Used by both version-history
/// restore and by the raw Export/Import endpoint.
///
/// `iface_map` lets the caller rename interfaces (backup-name → target-name)
/// or skip entries whose interface has no mapping on the target (value = None).
/// Pass an empty map for literal restore (version history on the same box).
/// Map a failed required restore step to the 500 the handlers return,
/// logging the step so the operator can see exactly what aborted (#535).
fn apply_fail(step: &str, e: impl std::fmt::Display) -> StatusCode {
    tracing::error!(error = %e, "config apply: {step} failed — aborting restore");
    StatusCode::INTERNAL_SERVER_ERROR
}

/// Pre-apply validation (#535): run the target config through the same
/// converters and validators the apply path uses, *before* the first
/// destructive DELETE. Entries the apply loop would silently skip
/// (unparseable rows, interfaces the user chose to drop) are skipped here
/// too — this only rejects configs that would abort mid-apply.
pub(crate) fn prevalidate_config(
    config: &FirewallConfig,
    iface_map: &InterfaceMap,
) -> Result<(), String> {
    config.validate()?;

    for rc in &config.rules {
        let iface_after = match rc.interface.as_deref() {
            Some(name) => match map_iface(name, iface_map) {
                Some(mapped) => Some(mapped),
                None => continue,
            },
            None => None,
        };
        let mut rc = rc.clone();
        rc.interface = iface_after;
        if let Some(rule) = rule_from_config(&rc) {
            aifw_core::validation::validate_rule(&rule)
                .map_err(|e| format!("rule {}: {e}", rc.id))?;
        }
    }

    for nc in &config.nat {
        let Some(mapped) = map_iface(&nc.interface, iface_map) else {
            continue;
        };
        let mut nc = nc.clone();
        nc.interface = mapped;
        if let Some(nat) = nat_from_config(&nc) {
            aifw_core::nat::validate_nat_rule(&nat)
                .map_err(|e| format!("nat rule {}: {e}", nc.id))?;
        }
    }

    for ac in &config.aliases {
        if aifw_common::AliasType::parse(&ac.alias_type).is_none() {
            continue;
        }
        aifw_core::AliasEngine::validate_name(&ac.name)
            .map_err(|e| format!("alias {}: {e}", ac.name))?;
    }

    // WireGuard: mirror the engine's add-time checks, plus duplicate listen
    // ports *within* the config (the tables are wiped before re-insert, so
    // only intra-config duplicates can collide).
    let mut wg_ports = std::collections::HashSet::new();
    for wg in &config.vpn.wireguard {
        if aifw_common::Address::parse(&wg.address).is_err()
            || map_iface(&wg.interface, iface_map).is_none()
        {
            continue;
        }
        if wg.name.is_empty() {
            return Err(format!("wg tunnel {}: tunnel name required", wg.id));
        }
        if wg.listen_port == 0 {
            return Err(format!("wg tunnel {}: listen port required", wg.name));
        }
        if !wg_ports.insert(wg.listen_port) {
            return Err(format!(
                "wg tunnel {}: listen port {} used by another tunnel in this config",
                wg.name, wg.listen_port
            ));
        }
        for p in &wg.peers {
            if p.public_key.is_empty() {
                return Err(format!(
                    "wg peer {} on {}: public key required",
                    p.id, wg.name
                ));
            }
        }
    }

    for sac in &config.vpn.ipsec {
        if aifw_common::Address::parse(&sac.src_addr).is_err()
            || aifw_common::Address::parse(&sac.dst_addr).is_err()
        {
            continue;
        }
        if sac.name.is_empty() {
            return Err(format!("ipsec SA {}: name required", sac.id));
        }
    }

    for tunnel in &config.vpn.ipsec_tunnels {
        tunnel
            .validate()
            .map_err(|e| format!("ipsec tunnel {}: {e}", tunnel.name))?;
    }

    for rc in &config.rate_limits {
        if rate_limit_from_config(rc).is_some() {
            if rc.max_connections == 0 {
                return Err(format!(
                    "rate limit {}: max_connections must be > 0",
                    rc.name
                ));
            }
            if rc.window_secs == 0 {
                return Err(format!("rate limit {}: window_secs must be > 0", rc.name));
            }
        }
    }

    for sc in &config.tls.sni_rules {
        if sc.pattern.is_empty() {
            return Err(format!("sni rule {}: pattern required", sc.id));
        }
    }

    for vc in &config.ha.carp_vips {
        if map_iface(&vc.interface, iface_map).is_none() || carp_vip_from_config(vc).is_none() {
            continue;
        }
        if vc.vhid == 0 {
            return Err(format!("carp vip {}: VHID must be > 0", vc.virtual_ip));
        }
        if vc.password.is_empty() {
            return Err(format!(
                "carp vip {}: CARP password required",
                vc.virtual_ip
            ));
        }
    }

    for nc in &config.ha.nodes {
        if cluster_node_from_config(nc).is_some() && nc.name.is_empty() {
            return Err(format!("cluster node {}: name required", nc.id));
        }
    }

    Ok(())
}

/// Restore-with-rollback wrapper around [`apply_firewall_config`] (#535).
///
/// Captures the current running config first, applies the target strictly,
/// and on any required-step failure re-applies the snapshot so the system
/// never stays half-restored. Three outcomes, never silent partial success:
/// 1. target applied — `Ok`;
/// 2. apply failed, prior state restored — `Err(500)`, audited;
/// 3. apply failed AND rollback failed — `Err(500)`, audited + logged as
///    high severity so the operator knows the system needs attention.
///
/// SQL transactions alone can't provide this contract because engine applies
/// mutate pf/kernel state sqlx can't rewind (see #158 for the DB-side
/// transaction work); snapshot/reapply is the rollback mechanism.
pub(crate) async fn apply_firewall_config_or_rollback(
    state: &AppState,
    config: &FirewallConfig,
    iface_map: &InterfaceMap,
) -> Result<(), StatusCode> {
    // Validate before snapshotting: a config that can't apply must be
    // rejected with nothing mutated, not "applied" and rolled back.
    prevalidate_config(config, iface_map).map_err(|e| {
        tracing::warn!(error = %e, "config apply: pre-validation rejected target config");
        StatusCode::BAD_REQUEST
    })?;
    let snapshot = build_current_config(state).await?;
    let Err(apply_err) = apply_firewall_config(state, config, iface_map).await else {
        return Ok(());
    };
    tracing::error!("config apply failed; rolling back to pre-apply snapshot");
    let audit = state.rule_engine.audit();
    match apply_firewall_config(state, &snapshot, &InterfaceMap::new()).await {
        Ok(()) => {
            if let Err(e) = audit
                .log(
                    aifw_core::AuditAction::ConfigChanged,
                    None,
                    "config restore failed; rolled back to pre-restore state",
                    "restore",
                )
                .await
            {
                tracing::warn!(error = %e, "config apply: rollback audit write failed");
            }
        }
        Err(rollback_err) => {
            tracing::error!(
                ?rollback_err,
                "config apply ROLLBACK FAILED — system may be partially configured; \
                 restore from a known-good backup"
            );
            if let Err(e) = audit
                .log(
                    aifw_core::AuditAction::ConfigChanged,
                    None,
                    "config restore failed AND rollback failed — system may be partially configured",
                    "restore",
                )
                .await
            {
                tracing::warn!(error = %e, "config apply: rollback audit write failed");
            }
        }
    }
    Err(apply_err)
}

pub(crate) async fn apply_firewall_config(
    state: &AppState,
    config: &FirewallConfig,
    iface_map: &InterfaceMap,
) -> Result<(), StatusCode> {
    use aifw_common::{
        Address, CountryCode, GeoIpRule, Interface, IpsecSa, VpnStatus, WgPeer, WgTunnel,
    };

    // Direct callers (commit-confirm rollback timer, cluster snapshot sync)
    // don't go through the wrapper — validate here too before any DELETE.
    prevalidate_config(config, iface_map).map_err(|e| {
        tracing::error!(error = %e, "config apply: pre-validation failed — nothing changed");
        StatusCode::BAD_REQUEST
    })?;

    // Engines whose tables may not exist yet. Their migrates are idempotent
    // DDL — run them before the transaction so the write transaction below
    // holds only data statements.
    let shaping = aifw_core::shaping::ShapingEngine::new(state.pool.clone(), state.pf.clone());
    shaping
        .migrate()
        .await
        .map_err(|e| apply_fail("shaping migrate", e))?;
    let tls_engine = aifw_core::tls::TlsEngine::new(state.pool.clone(), state.pf.clone());
    tls_engine
        .migrate()
        .await
        .map_err(|e| apply_fail("tls migrate", e))?;
    let ha_engine = aifw_core::ha::ClusterEngine::new(state.pool.clone(), state.pf.clone());
    ha_engine
        .migrate()
        .await
        .map_err(|e| apply_fail("ha migrate", e))?;

    // Single transaction for ALL database mutations (#158/#535): the
    // DELETE-then-reinsert of every section below either commits wholesale
    // or rolls back automatically on the first error, so the DB can never
    // end up half-restored. pf/kernel/service state can't ride in a SQL
    // transaction — those applies run after commit, with the snapshot
    // wrapper (`apply_firewall_config_or_rollback`) as their recovery path.
    // Parse/mapping skips (`continue`) below are intentional drops the
    // import preview already surfaced; operational failures are errors.
    // Rows actually inserted per table, checked against committed counts
    // after the transaction lands (#535 post-apply verification).
    let mut inserted = std::collections::BTreeMap::<&str, i64>::new();

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| apply_fail("begin restore transaction", e))?;

    // NB: "queue_configs"/"rate_limit_rules" are the real shaping table
    // names — the pre-#535 code deleted from "queues"/"rate_limits" (which
    // don't exist) and swallowed the error, so shaping rows were never
    // actually cleared before re-insert.
    for table in [
        "wg_peers",
        "wg_tunnels",
        "ipsec_sas",
        "ipsec_tunnels",
        "geoip_rules",
        "rules",
        "nat_rules",
        "aliases",
        "static_routes",
        "queue_configs",
        "rate_limit_rules",
        "sni_rules",
        "ja3_blocklist",
        "carp_vips",
        "pfsync_config",
        "cluster_nodes",
    ] {
        sqlx::query(sqlx::AssertSqlSafe(format!("DELETE FROM {table}")))
            .execute(&mut *tx)
            .await
            .map_err(|e| apply_fail(&format!("clearing {table}"), e))?;
    }

    for rc in &config.rules {
        let iface_after = match rc.interface.as_deref() {
            Some(name) => match map_iface(name, iface_map) {
                Some(mapped) => Some(mapped),
                None => continue, // user chose to drop entries on this interface
            },
            None => None,
        };
        let mut rc = rc.clone();
        rc.interface = iface_after;
        if let Some(rule) = rule_from_config(&rc) {
            let rule_id = rule.id;
            aifw_core::Database::insert_rule_on(&mut *tx, &rule)
                .await
                .map_err(|e| apply_fail(&format!("rule {rule_id} restore"), e))?;
            *inserted.entry("rules").or_default() += 1;
        } else {
            tracing::warn!(rule_id = %rc.id, "import: skipping unparseable rule entry");
        }
    }

    for nc in &config.nat {
        let Some(mapped_iface) = map_iface(&nc.interface, iface_map) else {
            continue;
        };
        let mut nc = nc.clone();
        nc.interface = mapped_iface;
        if let Some(nat) = nat_from_config(&nc) {
            let nat_id = nat.id;
            aifw_core::nat::NatEngine::insert_rule_on(&mut *tx, &nat)
                .await
                .map_err(|e| apply_fail(&format!("nat rule {nat_id} restore"), e))?;
            *inserted.entry("nat_rules").or_default() += 1;
        } else {
            tracing::warn!(nat_id = %nc.id, "import: skipping unparseable nat entry");
        }
    }

    // Aliases — rows insert in the transaction; pf tables re-sync after
    // commit (sync_all_strict below).
    for ac in &config.aliases {
        use aifw_common::{Alias, AliasType};
        let Some(alias_type) = AliasType::parse(&ac.alias_type) else {
            continue;
        };
        let id = uuid::Uuid::parse_str(&ac.id).unwrap_or_else(|_| uuid::Uuid::new_v4());
        let alias = Alias {
            id,
            name: ac.name.clone(),
            alias_type,
            entries: ac.entries.clone(),
            description: ac.description.clone(),
            enabled: ac.enabled,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        aifw_core::AliasEngine::insert_on(&mut *tx, &alias)
            .await
            .map_err(|e| apply_fail(&format!("alias {} restore", alias.name), e))?;
        *inserted.entry("aliases").or_default() += 1;
    }

    // Static routes — restored via direct INSERT, matching what
    // /api/v1/routes does for manual creates. Interface map applies if the
    // snapshot pinned a specific iface. Kernel route application is deferred
    // to after commit (collected here).
    let mut kernel_routes: Vec<(aifw_core::config::StaticRouteConfig, Option<String>)> = Vec::new();
    for rc in &config.static_routes {
        let iface_after = match rc.interface.as_deref() {
            Some(name) => match map_iface(name, iface_map) {
                Some(m) => Some(m),
                None => continue,
            },
            None => None,
        };
        sqlx::query(
            "INSERT INTO static_routes (id, destination, gateway, interface, metric, enabled, description, created_at, fib) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(&rc.id)
        .bind(&rc.destination)
        .bind(&rc.gateway)
        .bind(iface_after.as_deref())
        .bind(rc.metric as i64)
        .bind(rc.enabled)
        .bind(rc.description.as_deref())
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(rc.fib as i64)
        .execute(&mut *tx)
        .await
        .map_err(|e| apply_fail(&format!("static route {} restore", rc.destination), e))?;
        *inserted.entry("static_routes").or_default() += 1;
        if rc.enabled {
            kernel_routes.push((rc.clone(), iface_after));
        }
    }

    for gc in &config.geoip {
        let Ok(country) = CountryCode::new(&gc.country) else {
            continue;
        };
        let id = uuid::Uuid::parse_str(&gc.id).unwrap_or_else(|_| uuid::Uuid::new_v4());
        let mut rule = GeoIpRule::new(country, gc.action);
        rule.id = id;
        rule.label = gc.label.clone();
        rule.status = gc.status;
        let country = rule.country.0.clone();
        aifw_core::geoip::GeoIpEngine::insert_rule_on(&mut *tx, &rule)
            .await
            .map_err(|e| apply_fail(&format!("geo-ip rule {country} restore"), e))?;
        *inserted.entry("geoip_rules").or_default() += 1;
    }

    for wg in &config.vpn.wireguard {
        let Ok(address) = Address::parse(&wg.address) else {
            continue;
        };
        let Some(iface_name) = map_iface(&wg.interface, iface_map) else {
            continue;
        };
        let id = uuid::Uuid::parse_str(&wg.id).unwrap_or_else(|_| uuid::Uuid::new_v4());
        let now = chrono::Utc::now();
        let tunnel = WgTunnel {
            id,
            name: wg.name.clone(),
            interface: Interface(iface_name),
            private_key: wg.private_key.clone(),
            public_key: wg.public_key.clone(),
            listen_port: wg.listen_port,
            address,
            address6: wg.address6.as_deref().and_then(|s| Address::parse(s).ok()),
            dns: wg.dns.clone(),
            mtu: wg.mtu,
            listen_interface: None,
            split_routes: None,
            status: VpnStatus::Down,
            created_at: now,
            updated_at: now,
        };
        aifw_core::vpn::VpnEngine::insert_wg_tunnel_on(&mut *tx, &tunnel)
            .await
            .map_err(|e| apply_fail(&format!("wg tunnel {} restore", tunnel.name), e))?;
        *inserted.entry("wg_tunnels").or_default() += 1;
        for p in &wg.peers {
            let peer_id = uuid::Uuid::parse_str(&p.id).unwrap_or_else(|_| uuid::Uuid::new_v4());
            let allowed_ips: Vec<Address> = p
                .allowed_ips
                .iter()
                .filter_map(|s| Address::parse(s).ok())
                .collect();
            let peer = WgPeer {
                id: peer_id,
                tunnel_id: id,
                name: p.name.clone(),
                public_key: p.public_key.clone(),
                preshared_key: p.preshared_key.clone(),
                client_private_key: None,
                endpoint: p.endpoint.clone(),
                allowed_ips,
                persistent_keepalive: p.persistent_keepalive,
                created_at: now,
                updated_at: now,
            };
            aifw_core::vpn::VpnEngine::insert_wg_peer_on(&mut *tx, &peer)
                .await
                .map_err(|e| apply_fail(&format!("wg peer {} restore", peer.name), e))?;
            *inserted.entry("wg_peers").or_default() += 1;
        }
    }

    for sac in &config.vpn.ipsec {
        let Ok(src_addr) = Address::parse(&sac.src_addr) else {
            continue;
        };
        let Ok(dst_addr) = Address::parse(&sac.dst_addr) else {
            continue;
        };
        let id = uuid::Uuid::parse_str(&sac.id).unwrap_or_else(|_| uuid::Uuid::new_v4());
        let mut sa = IpsecSa::new(sac.name.clone(), src_addr, dst_addr, sac.protocol, sac.mode);
        sa.id = id;
        sa.enc_algo = sac.enc_algo.clone();
        sa.auth_algo = sac.auth_algo.clone();
        aifw_core::vpn::VpnEngine::insert_ipsec_sa_on(&mut *tx, &sa)
            .await
            .map_err(|e| apply_fail(&format!("ipsec SA {} restore", sa.name), e))?;
        *inserted.entry("ipsec_sas").or_default() += 1;
    }

    // Real IPsec tunnels (#530): restore records in the transaction; the
    // swanctl re-render + charon reload runs after commit.
    for tunnel in &config.vpn.ipsec_tunnels {
        aifw_core::ipsec::IpsecEngine::insert_tunnel_on(&mut *tx, tunnel)
            .await
            .map_err(|e| apply_fail(&format!("ipsec tunnel {} restore", tunnel.name), e))?;
        *inserted.entry("ipsec_tunnels").or_default() += 1;
    }

    let auth = &config.auth;
    for (key, value) in [
        (
            "access_token_expiry_mins",
            auth.access_token_expiry_mins.to_string(),
        ),
        (
            "refresh_token_expiry_days",
            auth.refresh_token_expiry_days.to_string(),
        ),
        (
            "require_totp",
            if auth.require_totp { "true" } else { "false" }.to_string(),
        ),
    ] {
        sqlx::query("INSERT OR REPLACE INTO auth_config (key, value) VALUES (?1, ?2)")
            .bind(key)
            .bind(value)
            .execute(&mut *tx)
            .await
            .map_err(|e| apply_fail(&format!("auth config {key} restore"), e))?;
    }

    // Traffic shaping: queues + per-IP rate limits (tables cleared above)
    for qc in &config.queues {
        let Some(mapped) = map_iface(&qc.interface, iface_map) else {
            continue;
        };
        let mut qc = qc.clone();
        qc.interface = mapped;
        if let Some(q) = queue_from_config(&qc) {
            aifw_core::shaping::ShapingEngine::insert_queue_on(&mut *tx, &q)
                .await
                .map_err(|e| apply_fail(&format!("shaping queue {} restore", qc.name), e))?;
            *inserted.entry("queue_configs").or_default() += 1;
        }
    }
    for rc in &config.rate_limits {
        let iface_after = match rc.interface.as_deref() {
            Some(name) => match map_iface(name, iface_map) {
                Some(m) => Some(m),
                None => continue,
            },
            None => None,
        };
        let mut rc = rc.clone();
        rc.interface = iface_after;
        if let Some(r) = rate_limit_from_config(&rc) {
            aifw_core::shaping::ShapingEngine::insert_rate_limit_on(&mut *tx, &r)
                .await
                .map_err(|e| apply_fail("rate limit restore", e))?;
            *inserted.entry("rate_limit_rules").or_default() += 1;
        }
    }

    // TLS: SNI rules + JA3 blocklist (tables cleared above)
    for sc in &config.tls.sni_rules {
        if let Some(sni) = sni_rule_from_config(sc) {
            aifw_core::tls::TlsEngine::insert_sni_rule_on(&mut *tx, &sni)
                .await
                .map_err(|e| apply_fail(&format!("sni rule {} restore", sc.pattern), e))?;
            *inserted.entry("sni_rules").or_default() += 1;
        }
    }
    for hash in &config.tls.blocked_ja3 {
        aifw_core::tls::TlsEngine::insert_ja3_block_on(&mut *tx, hash, "restored from backup")
            .await
            .map_err(|e| apply_fail(&format!("ja3 block {hash} restore"), e))?;
    }

    // HA: CARP VIPs + pfsync + cluster nodes (tables cleared above)
    for vc in &config.ha.carp_vips {
        let Some(mapped) = map_iface(&vc.interface, iface_map) else {
            continue;
        };
        let mut vc = vc.clone();
        vc.interface = mapped;
        if let Some(vip) = carp_vip_from_config(&vc) {
            aifw_core::ha::ClusterEngine::insert_carp_vip_on(&mut *tx, &vip)
                .await
                .map_err(|e| apply_fail(&format!("carp vip {} restore", vc.virtual_ip), e))?;
            *inserted.entry("carp_vips").or_default() += 1;
        }
    }
    if let Some(pc) = &config.ha.pfsync
        && let Some(mapped_sync) = map_iface(&pc.sync_interface, iface_map)
    {
        let mut pc = pc.clone();
        pc.sync_interface = mapped_sync;
        if let Some(pfsync) = pfsync_from_config(&pc) {
            aifw_core::ha::ClusterEngine::set_pfsync_on(&mut tx, &pfsync)
                .await
                .map_err(|e| apply_fail("pfsync restore", e))?;
        }
    }
    for nc in &config.ha.nodes {
        if let Some(node) = cluster_node_from_config(nc) {
            aifw_core::ha::ClusterEngine::insert_node_on(&mut *tx, &node)
                .await
                .map_err(|e| apply_fail("cluster node restore", e))?;
            *inserted.entry("cluster_nodes").or_default() += 1;
        }
    }

    // DHCP: subnets, reservations, global/DDNS/HA config (DB rows only; the
    // rDHCP service regen runs after commit)
    apply_dhcp_section_db(&mut tx, &config.dhcp).await?;

    // DNS resolver settings (#589). `None` = backup predates the section;
    // leave the box's resolver config untouched instead of resetting it to
    // defaults. Service regen runs after commit.
    if let Some(resolver) = &config.dns_resolver {
        crate::dns_resolver::save_config_on(&mut tx, resolver)
            .await
            .map_err(|e| apply_fail("dns resolver config restore", e))?;
    }

    // One audit row for the whole restore, committed atomically with it.
    // (Pre-#158 each engine `add` wrote a per-row audit entry; a restore is
    // one operator action, not N rule additions.)
    aifw_core::AuditLog::log_on(
        &mut *tx,
        aifw_core::AuditAction::ConfigChanged,
        None,
        &format!(
            "config restore applied: {} rules, {} nat, {} aliases, {} geoip, {} wg, {} ipsec tunnels",
            config.rules.len(),
            config.nat.len(),
            config.aliases.len(),
            config.geoip.len(),
            config.vpn.wireguard.len(),
            config.vpn.ipsec_tunnels.len(),
        ),
        "restore",
    )
    .await
    .map_err(|e| apply_fail("restore audit entry", e))?;

    tx.commit()
        .await
        .map_err(|e| apply_fail("commit restore transaction", e))?;

    // Post-commit DB verification (#535): the transaction guarantees
    // atomicity, but confirm the committed row counts match what the
    // restore inserted before touching the data plane. (Key/value config
    // tables and INSERT OR REPLACE targets are excluded — duplicates
    // legitimately collapse there.)
    for table in [
        "rules",
        "nat_rules",
        "aliases",
        "static_routes",
        "geoip_rules",
        "wg_tunnels",
        "wg_peers",
        "ipsec_sas",
        "ipsec_tunnels",
        "queue_configs",
        "rate_limit_rules",
        "sni_rules",
        "carp_vips",
        "cluster_nodes",
    ] {
        let expected = inserted.get(table).copied().unwrap_or(0);
        let (count,): (i64,) =
            sqlx::query_as(sqlx::AssertSqlSafe(format!("SELECT COUNT(*) FROM {table}")))
                .fetch_one(&state.pool)
                .await
                .map_err(|e| apply_fail(&format!("verifying {table}"), e))?;
        if count != expected {
            return Err(apply_fail(
                &format!("verifying {table}"),
                format!("{count} rows committed but {expected} were inserted"),
            ));
        }
    }

    // ============================================================
    // Post-commit: pf / kernel / service applies. The DB is now fully
    // consistent; a failure below is a data-plane mismatch that must
    // surface as an error (#535) — the snapshot wrapper re-applies the
    // prior config to recover. Steps marked best-effort are reapplied at
    // boot and degrade capacity, not policy.
    // ============================================================

    // Kernel route application. Best-effort: it shells out to `route`,
    // which is absent/unprivileged on dev hosts; rows are reapplied at boot.
    for (rc, iface_after) in &kernel_routes {
        crate::routes::apply_route_to_system(
            &rc.destination,
            &rc.gateway,
            iface_after.as_deref(),
            rc.fib,
        )
        .await;
    }

    // Alias pf tables — required; a stale table means rules referencing the
    // alias match the wrong addresses.
    state
        .alias_engine
        .sync_all_strict()
        .await
        .map_err(|e| apply_fail("alias pf table sync", e))?;

    // swanctl re-render + charon reload. Warn-only: strongSwan is a
    // FreeBSD-side companion service absent on dev hosts; tunnels stay down
    // until re-applied.
    if !config.vpn.ipsec_tunnels.is_empty()
        && let Err(e) = state.ipsec_engine.apply_all().await
    {
        tracing::warn!(error = %e, "restored IPsec tunnels but swanctl apply failed — tunnels stay down until re-applied");
    }

    if !config.system.dns_servers.is_empty() {
        let content: String = config
            .system
            .dns_servers
            .iter()
            .map(|s| format!("nameserver {s}\n"))
            .collect();
        // /etc/resolv.conf is root-owned, so a direct write as the aifw user
        // fails on FreeBSD (#307); stage in /tmp and go through the
        // `aifw-sudo-install` allowlist instead. Warn-only like the other
        // post-commit system applies: the helper is absent on dev hosts.
        if let Err(e) = install_resolv_conf(&content).await {
            tracing::warn!(error = %e, "import: /etc/resolv.conf install failed — restored DNS servers not applied to the system resolver");
        }
    }

    // pf state-table tuning. Best-effort: this shells out to system tooling
    // absent on dev hosts, the same setting is reapplied at every boot
    // (`pf_tuning::apply_on_boot`, also warn-only), and a missed tuning value
    // degrades capacity rather than firewall policy.
    for t in &config.tuning {
        if t.enabled
            && t.key == "pf.max_states"
            && let Ok(val) = t.value.parse::<u64>()
            && let Err(e) = aifw_core::pf_tuning::set_max_states(&state.pool, val).await
        {
            tracing::warn!(value = val, error = %e, "import: pf.max_states restore failed");
        }
    }

    // Regenerate rDHCP TOML + restart service so the restored config takes
    // effect. Best-effort: the companion service may be absent (dev hosts);
    // the DB rows are authoritative and reapplied at boot.
    crate::dhcp::auto_apply(state).await;

    // Regenerate resolver config + restart the DNS backend so the restored
    // settings take effect (#589). Best-effort like rDHCP above: the backend
    // service may be absent (dev hosts); the DB rows are authoritative and
    // switch_backend probes + auto-rolls-back on a failed start.
    if let Some(resolver) = &config.dns_resolver {
        let report = crate::dns_resolver::switch_backend(state, &resolver.backend, resolver).await;
        if report.rolled_back || (resolver.enabled && !report.probe_udp) {
            tracing::warn!(
                backend = %resolver.backend,
                rolled_back = report.rolled_back,
                message = %report.message,
                "import: DNS resolver apply did not come up healthy — settings are restored in the DB, re-apply via /dns/resolver/apply"
            );
        }
    }

    // Final data-plane applies — a failure here means the kernel does NOT
    // match the restored DB, so it must not report success (#535).
    shaping
        .apply_queues()
        .await
        .map_err(|e| apply_fail("shaping queues apply", e))?;
    shaping
        .apply_rate_limits()
        .await
        .map_err(|e| apply_fail("rate limits apply", e))?;
    let vpn_rules = state
        .vpn_engine
        .collect_vpn_rules()
        .await
        .map_err(|e| apply_fail("collecting vpn rules", e))?;
    state.rule_engine.set_extra_rules(vpn_rules).await;
    state
        .rule_engine
        .apply_rules()
        .await
        .map_err(|e| apply_fail("firewall rules apply", e))?;
    state
        .nat_engine
        .apply_rules()
        .await
        .map_err(|e| apply_fail("nat rules apply", e))?;
    state
        .geoip_engine
        .apply_rules()
        .await
        .map_err(|e| apply_fail("geoip rules apply", e))?;

    // Post-apply data-plane verification (#535): pf must hold exactly the
    // rulesets the engines just rendered. Catches a backend that reported
    // success but didn't take the rules.
    state
        .rule_engine
        .verify_applied()
        .await
        .map_err(|e| apply_fail("firewall rules verification", e))?;
    state
        .nat_engine
        .verify_applied()
        .await
        .map_err(|e| apply_fail("nat rules verification", e))?;
    state
        .geoip_engine
        .verify_applied()
        .await
        .map_err(|e| apply_fail("geoip rules verification", e))?;

    Ok(())
}

/// Stage `content` in /tmp and atomically install it as `/etc/resolv.conf`
/// via `aifw_core::sudo::install`. The destination is on the
/// `aifw-sudo-install` allowlist; a direct `tokio::fs::write` silently
/// fails as the unprivileged aifw user on FreeBSD (#307).
async fn install_resolv_conf(content: &str) -> Result<(), String> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp = format!("/tmp/aifw.resolv.conf.{nanos}.tmp");
    tokio::fs::write(&tmp, content)
        .await
        .map_err(|e| format!("stage tmp: {e}"))?;
    let result = aifw_core::sudo::install(Some("0644"), None, None, &tmp, "/etc/resolv.conf")
        .await
        .map_err(|e| format!("spawn sudo install: {e}"));
    // Best-effort tmp cleanup; the install result below is what matters.
    let _ = tokio::fs::remove_file(&tmp).await;
    let out = result?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_string());
    }
    Ok(())
}

/// DHCP section of a restore — DB rows only, on the caller's transaction
/// connection (#158/#535). The rDHCP service regen (`dhcp::auto_apply`)
/// runs post-commit in `apply_firewall_config`.
async fn apply_dhcp_section_db(
    conn: &mut sqlx::SqliteConnection,
    dhcp: &aifw_core::config::DhcpSection,
) -> Result<(), StatusCode> {
    // Wipe + re-insert for a clean restore. DB mutations are required
    // steps (#535).
    for table in [
        "dhcp_subnets",
        "dhcp_reservations",
        "dhcp_config",
        "dhcp_ddns_config",
        "dhcp_ha_config",
    ] {
        sqlx::query(sqlx::AssertSqlSafe(format!("DELETE FROM {table}")))
            .execute(&mut *conn)
            .await
            .map_err(|e| apply_fail(&format!("clearing {table}"), e))?;
    }

    // --- global ----------------------------------------------
    let g = &dhcp.global;
    for (k, v) in [
        (
            "enabled",
            if g.enabled {
                "true".to_string()
            } else {
                "false".to_string()
            },
        ),
        ("interfaces", g.interfaces.join(",")),
        (
            "authoritative",
            if g.authoritative {
                "true".to_string()
            } else {
                "false".to_string()
            },
        ),
        ("default_lease_time", g.default_lease_time.to_string()),
        ("max_lease_time", g.max_lease_time.to_string()),
        ("dns_servers", g.dns_servers.join(",")),
        ("domain_name", g.domain_name.clone()),
        ("domain_search", g.domain_search.join(",")),
        ("ntp_servers", g.ntp_servers.join(",")),
        ("wins_servers", g.wins_servers.join(",")),
        ("next_server", g.next_server.clone().unwrap_or_default()),
        ("boot_filename", g.boot_filename.clone().unwrap_or_default()),
        ("log_level", g.log_level.clone()),
        ("log_format", g.log_format.clone()),
        ("api_port", g.api_port.to_string()),
        ("workers", g.workers.to_string()),
        (
            "accept_relayed",
            if g.accept_relayed {
                "true".to_string()
            } else {
                "false".to_string()
            },
        ),
        (
            "relay_rate_limit_burst",
            g.relay_rate_limit_burst.to_string(),
        ),
        ("relay_rate_limit_pps", g.relay_rate_limit_pps.to_string()),
    ] {
        sqlx::query("INSERT OR REPLACE INTO dhcp_config (key, value) VALUES (?1, ?2)")
            .bind(k)
            .bind(v)
            .execute(&mut *conn)
            .await
            .map_err(|e| apply_fail(&format!("dhcp config {k} restore"), e))?;
    }

    // --- subnets ---------------------------------------------
    for s in &dhcp.subnets {
        // Revalidate trusted_relays on restore: older backups or hand-edited JSON
        // could contain bad entries. Skip invalid ones rather than abort the
        // whole restore.
        let relays: Vec<String> = s
            .trusted_relays
            .iter()
            .filter(|r| {
                let t = r.trim();
                !t.is_empty()
                    && t.parse::<std::net::Ipv4Addr>()
                        .map(|ip| !ip.is_loopback())
                        .unwrap_or(false)
            })
            .cloned()
            .collect();
        if relays.len() != s.trusted_relays.len() {
            tracing::warn!(
                "dhcp.restore subnet={} dropped {} invalid trusted_relays entries",
                s.network,
                s.trusted_relays.len() - relays.len()
            );
        }
        let trusted_json = serde_json::to_string(&relays).unwrap_or_else(|_| "[]".to_string());

        // Revalidate option overrides on restore, same as trusted_relays above.
        // rDHCP will refuse to start if invalid/reserved codes reach its config,
        // so we filter rather than abort the whole restore.
        let safe_options: Vec<_> = s
            .options
            .iter()
            .filter(|o| is_option_override_safe(o))
            .cloned()
            .collect();
        if safe_options.len() != s.options.len() {
            tracing::warn!(
                "dhcp.restore subnet={} dropped {} invalid option override(s)",
                s.network,
                s.options.len() - safe_options.len()
            );
        }
        let options_json =
            serde_json::to_string(&safe_options).unwrap_or_else(|_| "[]".to_string());
        sqlx::query(
            "INSERT INTO dhcp_subnets \
             (id, network, pool_start, pool_end, gateway, dns_servers, domain_name, \
              lease_time, max_lease_time, renewal_time, rebinding_time, preferred_time, \
              subnet_type, delegated_length, enabled, description, \
              trusted_relays, ntp_servers, options, created_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
        )
        .bind(&s.id)
        .bind(&s.network)
        .bind(&s.pool_start)
        .bind(&s.pool_end)
        .bind(&s.gateway)
        .bind(&s.dns_servers)
        .bind(&s.domain_name)
        .bind(s.lease_time.map(|v| v as i64))
        .bind(s.max_lease_time.map(|v| v as i64))
        .bind(s.renewal_time.map(|v| v as i64))
        .bind(s.rebinding_time.map(|v| v as i64))
        .bind(s.preferred_time.map(|v| v as i64))
        .bind(&s.subnet_type)
        .bind(s.delegated_length.map(|v| v as i64))
        .bind(s.enabled)
        .bind(&s.description)
        .bind(&trusted_json)
        .bind(&s.ntp_servers)
        .bind(&options_json)
        .bind(&s.created_at)
        .execute(&mut *conn)
        .await
        .map_err(|e| apply_fail(&format!("dhcp subnet {} restore", s.network), e))?;
    }

    // --- reservations ----------------------------------------
    for r in &dhcp.reservations {
        sqlx::query(
            "INSERT INTO dhcp_reservations (id, subnet_id, mac_address, ip_address, hostname, client_id, description, created_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)"
        )
        .bind(&r.id).bind(&r.subnet_id).bind(&r.mac_address).bind(&r.ip_address)
        .bind(&r.hostname).bind(&r.client_id).bind(&r.description).bind(&r.created_at)
        .execute(&mut *conn).await
        .map_err(|e| apply_fail(&format!("dhcp reservation {} restore", r.ip_address), e))?;
    }

    // --- DDNS ------------------------------------------------
    let d = &dhcp.ddns;
    for (k, v) in [
        (
            "enabled",
            if d.enabled {
                "true".to_string()
            } else {
                "false".to_string()
            },
        ),
        ("forward_zone", d.forward_zone.clone()),
        ("reverse_zone_v4", d.reverse_zone_v4.clone()),
        ("reverse_zone_v6", d.reverse_zone_v6.clone()),
        ("dns_server", d.dns_server.clone()),
        ("tsig_key", d.tsig_key.clone()),
        ("tsig_algorithm", d.tsig_algorithm.clone()),
        ("tsig_secret", d.tsig_secret.clone()),
        ("ttl", d.ttl.to_string()),
    ] {
        sqlx::query("INSERT OR REPLACE INTO dhcp_ddns_config (key, value) VALUES (?1, ?2)")
            .bind(k)
            .bind(v)
            .execute(&mut *conn)
            .await
            .map_err(|e| apply_fail(&format!("dhcp ddns config {k} restore"), e))?;
    }

    // --- DHCP HA ---------------------------------------------
    let h = &dhcp.dhcp_ha;
    for (k, v) in [
        ("mode", h.mode.clone()),
        ("peer", h.peer.clone().unwrap_or_default()),
        ("listen", h.listen.clone().unwrap_or_default()),
        (
            "scope_split",
            h.scope_split.map(|v| v.to_string()).unwrap_or_default(),
        ),
        ("mclt", h.mclt.map(|v| v.to_string()).unwrap_or_default()),
        (
            "partner_down_delay",
            h.partner_down_delay
                .map(|v| v.to_string())
                .unwrap_or_default(),
        ),
        (
            "node_id",
            h.node_id.map(|v| v.to_string()).unwrap_or_default(),
        ),
        (
            "peers",
            h.peers.as_ref().map(|v| v.join(",")).unwrap_or_default(),
        ),
        ("tls_cert", h.tls_cert.clone().unwrap_or_default()),
        ("tls_key", h.tls_key.clone().unwrap_or_default()),
        ("tls_ca", h.tls_ca.clone().unwrap_or_default()),
    ] {
        sqlx::query("INSERT OR REPLACE INTO dhcp_ha_config (key, value) VALUES (?1, ?2)")
            .bind(k)
            .bind(v)
            .execute(&mut *conn)
            .await
            .map_err(|e| apply_fail(&format!("dhcp ha config {k} restore"), e))?;
    }

    Ok(())
}

fn rule_from_config(rc: &aifw_core::config::RuleConfig) -> Option<aifw_common::Rule> {
    use aifw_common::*;
    let action = rc.action;
    let direction = rc.direction;
    let protocol = rc.protocol;
    let src_addr = rc
        .src_addr
        .as_deref()
        .map(Address::parse)
        .transpose()
        .ok()?
        .unwrap_or(Address::Any);
    let dst_addr = rc
        .dst_addr
        .as_deref()
        .map(Address::parse)
        .transpose()
        .ok()?
        .unwrap_or(Address::Any);
    let src_port = match (rc.src_port_start, rc.src_port_end) {
        (Some(s), Some(e)) => Some(PortRange { start: s, end: e }),
        (Some(s), None) => Some(PortRange { start: s, end: s }),
        _ => None,
    };
    let dst_port = match (rc.dst_port_start, rc.dst_port_end) {
        (Some(s), Some(e)) => Some(PortRange { start: s, end: e }),
        (Some(s), None) => Some(PortRange { start: s, end: s }),
        _ => None,
    };
    let tracking = rc.state_tracking;
    let status = rc.status;
    let id = uuid::Uuid::parse_str(&rc.id).unwrap_or_else(|_| uuid::Uuid::new_v4());
    let now = chrono::Utc::now();
    let ip_version = rc.ip_version;
    Some(Rule {
        id,
        priority: rc.priority,
        action,
        direction,
        ip_version,
        interface: rc.interface.clone().map(Interface),
        protocol,
        rule_match: RuleMatch {
            src_addr,
            src_port,
            dst_addr,
            dst_port,
        },
        src_invert: rc.src_invert,
        dst_invert: rc.dst_invert,
        log: rc.log,
        quick: rc.quick,
        label: rc.label.clone(),
        description: None,
        gateway: rc.gateway.clone(),
        state_options: StateOptions {
            tracking,
            ..Default::default()
        },
        status,
        schedule_id: rc.schedule_id.clone(),
        created_at: now,
        updated_at: now,
    })
}

fn nat_from_config(nc: &aifw_core::config::NatRuleConfig) -> Option<aifw_common::NatRule> {
    use aifw_common::*;
    let nat_type = nc.nat_type;
    let protocol = nc.protocol;
    let src_addr = nc
        .src_addr
        .as_deref()
        .map(Address::parse)
        .transpose()
        .ok()?
        .unwrap_or(Address::Any);
    let dst_addr = nc
        .dst_addr
        .as_deref()
        .map(Address::parse)
        .transpose()
        .ok()?
        .unwrap_or(Address::Any);
    let redirect_addr = Address::parse(&nc.redirect_addr).ok()?;
    let src_port = match (nc.src_port_start, nc.src_port_end) {
        (Some(s), Some(e)) => Some(PortRange { start: s, end: e }),
        (Some(s), None) => Some(PortRange { start: s, end: s }),
        _ => None,
    };
    let dst_port = match (nc.dst_port_start, nc.dst_port_end) {
        (Some(s), Some(e)) => Some(PortRange { start: s, end: e }),
        (Some(s), None) => Some(PortRange { start: s, end: s }),
        _ => None,
    };
    let redirect_port = match (nc.redirect_port_start, nc.redirect_port_end) {
        (Some(s), Some(e)) => Some(PortRange { start: s, end: e }),
        (Some(s), None) => Some(PortRange { start: s, end: s }),
        _ => None,
    };
    let status = nc.status;
    let id = uuid::Uuid::parse_str(&nc.id).unwrap_or_else(|_| uuid::Uuid::new_v4());
    let now = chrono::Utc::now();
    Some(NatRule {
        id,
        nat_type,
        interface: Interface(nc.interface.clone()),
        protocol,
        src_addr,
        src_port,
        dst_addr,
        dst_port,
        redirect: NatRedirect {
            address: redirect_addr,
            port: redirect_port,
        },
        label: nc.label.clone(),
        status,
        created_at: now,
        updated_at: now,
    })
}

fn queue_from_config(qc: &aifw_core::config::QueueConfigEntry) -> Option<aifw_common::QueueConfig> {
    use aifw_common::*;
    let queue_type = qc.queue_type;
    let unit = qc.bandwidth_unit;
    let traffic_class = qc.traffic_class;
    let status = qc.status;
    let id = uuid::Uuid::parse_str(&qc.id).unwrap_or_else(|_| uuid::Uuid::new_v4());
    let now = chrono::Utc::now();
    Some(QueueConfig {
        id,
        interface: Interface(qc.interface.clone()),
        queue_type,
        bandwidth: Bandwidth {
            value: qc.bandwidth_value,
            unit,
        },
        name: qc.name.clone(),
        traffic_class,
        bandwidth_pct: qc.bandwidth_pct,
        default: qc.default,
        status,
        created_at: now,
        updated_at: now,
        fq_codel: qc.fq_codel,
    })
}

fn rate_limit_from_config(
    rc: &aifw_core::config::RateLimitEntry,
) -> Option<aifw_common::RateLimitRule> {
    use aifw_common::*;
    let protocol = rc.protocol;
    let status = rc.status;
    let dst_port = match (rc.dst_port_start, rc.dst_port_end) {
        (Some(s), Some(e)) => Some(PortRange { start: s, end: e }),
        (Some(s), None) => Some(PortRange { start: s, end: s }),
        _ => None,
    };
    let id = uuid::Uuid::parse_str(&rc.id).unwrap_or_else(|_| uuid::Uuid::new_v4());
    let now = chrono::Utc::now();
    Some(RateLimitRule {
        id,
        name: rc.name.clone(),
        interface: rc.interface.clone().map(Interface),
        protocol,
        src_addr: Address::Any,
        dst_addr: Address::Any,
        dst_port,
        max_connections: rc.max_connections,
        window_secs: rc.window_secs,
        overload_table: rc.overload_table.clone(),
        flush_states: rc.flush_states,
        status,
        created_at: now,
        updated_at: now,
    })
}

fn sni_rule_from_config(sc: &aifw_core::config::SniRuleConfig) -> Option<aifw_common::SniRule> {
    use aifw_common::*;
    let id = uuid::Uuid::parse_str(&sc.id).unwrap_or_else(|_| uuid::Uuid::new_v4());
    let now = chrono::Utc::now();
    let mut rule = SniRule::new(sc.pattern.clone(), sc.action);
    rule.id = id;
    rule.label = sc.label.clone();
    rule.created_at = now;
    rule.updated_at = now;
    Some(rule)
}

fn carp_vip_from_config(vc: &aifw_core::config::CarpVipConfig) -> Option<aifw_common::CarpVip> {
    use aifw_common::*;
    let virtual_ip: std::net::IpAddr = vc.virtual_ip.parse().ok()?;
    let id = uuid::Uuid::parse_str(&vc.id).unwrap_or_else(|_| uuid::Uuid::new_v4());
    let now = chrono::Utc::now();
    Some(CarpVip {
        id,
        vhid: vc.vhid,
        virtual_ip,
        prefix: vc.prefix,
        interface: Interface(vc.interface.clone()),
        password: vc.password.clone(),
        status: CarpStatus::Init,
        created_at: now,
        updated_at: now,
    })
}

fn pfsync_from_config(pc: &aifw_core::config::PfsyncEntry) -> Option<aifw_common::PfsyncConfig> {
    use aifw_common::*;
    let sync_peer = pc
        .sync_peer
        .as_ref()
        .map(|s| s.parse::<std::net::IpAddr>())
        .transpose()
        .ok()?;
    let mut cfg = PfsyncConfig::new(Interface(pc.sync_interface.clone()));
    cfg.sync_peer = sync_peer;
    cfg.defer = pc.defer;
    Some(cfg)
}

fn cluster_node_from_config(
    nc: &aifw_core::config::ClusterNodeConfig,
) -> Option<aifw_common::ClusterNode> {
    use aifw_common::*;
    let address: std::net::IpAddr = nc.address.parse().ok()?;
    let role = ClusterRole::parse(&nc.role).ok()?;
    let id = uuid::Uuid::parse_str(&nc.id).unwrap_or_else(|_| uuid::Uuid::new_v4());
    let mut node = ClusterNode::new(nc.name.clone(), address, role);
    node.id = id;
    Some(node)
}

fn gethostname() -> Option<String> {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// ============================================================
// Auto-snapshot: mutating HTTP requests trigger a
// save_if_changed() so config history accrues without any
// per-endpoint plumbing. The middleware only runs AFTER a
// successful (2xx) response; snapshotting runs in a spawned
// task so the response is never blocked, and is debounced so
// a burst of mutations produces one snapshot (PERF-H8 #352).
// ============================================================

/// Routes where auto-snapshot would recurse or provide no value.
/// Config-management routes already manage their own versions;
/// WebSocket and streaming endpoints never change state; and
/// non-structural mutations (PERF-H8 #352) touch state that
/// `build_current_config` doesn't capture, so rebuilding + hashing
/// the config for them is guaranteed wasted work.
fn should_skip_auto_snapshot(path: &str) -> bool {
    path.starts_with("/api/v1/config/")         // own subsystem
        || path.starts_with("/api/v1/auth/login")
        || path.starts_with("/api/v1/auth/refresh")
        || path.starts_with("/api/v1/auth/logout")
        || path.starts_with("/api/v1/auth/register")
        || path.starts_with("/api/v1/auth/totp/login")
        || path.starts_with("/api/v1/auth/oauth/")
        || path.starts_with("/api/v1/auth/ws-ticket") // ephemeral ticket
        || path.starts_with("/api/v1/dns/stream")  // WebSocket
        || path.starts_with("/api/v1/ws")          // WebSocket
        || path.starts_with("/api/v1/pending/stream")
        || path.starts_with("/api/v1/updates/")    // ship-via-package ops, not config
        || path.starts_with("/api/v1/reload")      // no config delta
        || path.starts_with("/api/v1/metrics")
        || path.starts_with("/api/v1/ids/")        // alert acks/classifications, IDS state — not in FirewallConfig
        || path.starts_with("/api/v1/ai/")         // analysis triggers
        || path.starts_with("/api/v1/connections") // runtime state kills
        || path.ends_with("/test") // test-fire endpoints (smtp/s3/ai)
}

/// Debounce state for auto-snapshots (PERF-H8 #352). Mutations landing
/// while a snapshot is scheduled just fold into the pending one.
#[derive(Default)]
pub struct AutoSnapshotPending {
    scheduled: bool,
    coalesced: u32,
    last_comment: String,
}

/// How long a scheduled auto-snapshot waits so that a burst of mutations
/// (bulk edits, an admin clicking through the UI) produces one config
/// version instead of one per request.
const AUTO_SNAPSHOT_DEBOUNCE: std::time::Duration = std::time::Duration::from_secs(5);

pub async fn auto_snapshot_middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let mutating = matches!(
        &method,
        &Method::POST | &Method::PUT | &Method::DELETE | &Method::PATCH
    );

    let response = next.run(request).await;

    if !mutating || !response.status().is_success() {
        return response;
    }
    // PERF-M15: any successful mutation may change the exported config —
    // invalidate the cached cluster snapshot. Done before the skip list so
    // paths that skip auto-snapshot still invalidate correctly.
    state
        .config_generation
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    if should_skip_auto_snapshot(&path) {
        return response;
    }

    // Hand off to a background task so the client response isn't blocked
    // by rebuilding + hashing the config. PERF-H8 (#352): the rebuild does
    // ~15 DB list calls + full-JSON sha256, so it's debounced — the first
    // qualifying mutation schedules one snapshot AUTO_SNAPSHOT_DEBOUNCE
    // later, and everything arriving in between folds into it.
    let spawn_worker = {
        let mut pending = state.auto_snapshot_pending.lock().await;
        pending.coalesced += 1;
        pending.last_comment = format!("{method} {path}");
        !std::mem::replace(&mut pending.scheduled, true)
    };
    if !spawn_worker {
        return response;
    }

    let bg_state = state.clone();
    let bg_actor = "auto".to_string();
    tokio::spawn(async move {
        tokio::time::sleep(AUTO_SNAPSHOT_DEBOUNCE).await;
        let (coalesced, last_comment) = {
            let mut pending = bg_state.auto_snapshot_pending.lock().await;
            pending.scheduled = false;
            (
                std::mem::take(&mut pending.coalesced),
                std::mem::take(&mut pending.last_comment),
            )
        };
        let bg_comment = if coalesced > 1 {
            format!("{last_comment} (+{} coalesced)", coalesced - 1)
        } else {
            last_comment
        };
        let cfg = match build_current_config(&bg_state).await {
            Ok(c) => c,
            Err(_) => {
                tracing::debug!("auto-snapshot: build_current_config failed");
                return;
            }
        };
        let mgr = ConfigManager::new(bg_state.pool.clone());
        if let Err(e) = mgr.migrate().await {
            tracing::warn!(error = %e, "auto-snapshot: config manager migrate failed");
        }
        let version = match mgr
            .save_if_changed(&cfg, &bg_actor, Some(&bg_comment))
            .await
        {
            Ok(Some(v)) => v,
            Ok(None) => return, // config unchanged — no notification either
            Err(e) => {
                tracing::debug!("auto-snapshot failed: {e}");
                return;
            }
        };

        // Fire "saved" notification (opt-in — default disabled).
        aifw_core::smtp_notify::send_event(
            &bg_state.pool,
            aifw_core::smtp_notify::Event::BackupSaved,
            &format!("Version {version}: {bg_comment}"),
        )
        .await;

        // S3 upload if configured.
        let s3cfg = aifw_core::s3_backup::load(&bg_state.pool).await;
        if s3cfg.enabled {
            let now = chrono::Utc::now().to_rfc3339();
            match aifw_core::s3_backup::upload_version(&s3cfg, version, &now, &cfg.to_json()).await
            {
                Ok(key) => {
                    aifw_core::smtp_notify::send_event(
                        &bg_state.pool,
                        aifw_core::smtp_notify::Event::S3UploadOk,
                        &format!(
                            "Version {version} uploaded to s3://{}/{}",
                            s3cfg.bucket, key
                        ),
                    )
                    .await;
                }
                Err(e) => {
                    tracing::warn!(version, error = %e, "S3 upload failed");
                    aifw_core::smtp_notify::send_event(
                        &bg_state.pool,
                        aifw_core::smtp_notify::Event::S3UploadFailed,
                        &format!(
                            "Version {version} failed to upload to s3://{}: {e}",
                            s3cfg.bucket
                        ),
                    )
                    .await;
                }
            }
        }
    });

    response
}

// ============================================================
// Retention settings
// ============================================================

#[derive(Serialize)]
pub struct RetentionResponse {
    pub max_versions: u32,
    pub current_count: u64,
}

pub async fn get_retention(
    State(state): State<AppState>,
) -> Result<Json<RetentionResponse>, StatusCode> {
    let mgr = ConfigManager::new(state.pool.clone());
    mgr.migrate().await.map_err(|_| internal())?;
    let max_versions = mgr.retention_limit().await;
    let current_count = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM config_versions")
        .fetch_one(&state.pool)
        .await
        .map(|(n,)| n as u64)
        .unwrap_or(0);
    Ok(Json(RetentionResponse {
        max_versions,
        current_count,
    }))
}

#[derive(Deserialize)]
pub struct RetentionRequest {
    pub max_versions: u32,
}

pub async fn put_retention(
    State(state): State<AppState>,
    Json(req): Json<RetentionRequest>,
) -> Result<Json<RetentionResponse>, (StatusCode, String)> {
    let mgr = ConfigManager::new(state.pool.clone());
    mgr.migrate()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    mgr.set_retention_limit(req.max_versions)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    get_retention(State(state))
        .await
        .map_err(|c| (c, "read back failed".into()))
}

// ============================================================
// Cluster snapshot serialization (Task 5.3)
// ============================================================

/// Payload for cluster config replication snapshots.
/// Extends FirewallConfig with IDS rule overrides and suppressions
/// so peer nodes receive a complete picture of config state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterSnapshotPayload {
    pub firewall: FirewallConfig,
    pub ids_rule_overrides: Vec<IdsRuleOverride>,
    pub ids_suppressions: Vec<IdsSuppressionRecord>,
}

/// Minimal IDS rule override record for snapshot serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsRuleOverride {
    pub id: String,
    pub enabled: bool,
    pub action_override: Option<String>,
}

/// Minimal IDS suppression record for snapshot serialization.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdsSuppressionRecord {
    pub id: String,
    pub sid: i64,
    pub suppress_type: String,
    pub ip_cidr: Option<String>,
}

/// Build a ClusterSnapshotPayload from current live state.
/// Reuses build_current_config for the firewall section,
/// then appends IDS rule overrides + suppressions from the DB.
pub(crate) async fn cluster_export_payload(
    state: &AppState,
) -> Result<ClusterSnapshotPayload, StatusCode> {
    let firewall = build_current_config(state).await?;

    // IDS rule overrides: rows with non-default enabled or action_override
    let overrides: Vec<IdsRuleOverride> = sqlx::query_as::<_, (String, bool, Option<String>)>(
        "SELECT id, enabled, action_override FROM ids_rules WHERE enabled = 0 OR action_override IS NOT NULL"
    )
    .fetch_all(&state.pool)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|(id, enabled, action_override)| IdsRuleOverride { id, enabled, action_override })
    .collect();

    // IDS suppressions
    let suppressions: Vec<IdsSuppressionRecord> =
        sqlx::query_as::<_, (String, i64, String, Option<String>)>(
            "SELECT id, sid, suppress_type, ip_cidr FROM ids_suppressions ORDER BY rowid ASC",
        )
        .fetch_all(&state.pool)
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|(id, sid, suppress_type, ip_cidr)| IdsSuppressionRecord {
            id,
            sid,
            suppress_type,
            ip_cidr,
        })
        .collect();

    Ok(ClusterSnapshotPayload {
        firewall,
        ids_rule_overrides: overrides,
        ids_suppressions: suppressions,
    })
}

/// Apply a cluster snapshot payload (JSON string) to this node.
/// Parses the payload, applies the firewall config, then syncs
/// IDS rule overrides and suppressions from the DB.
pub(crate) async fn apply_cluster_snapshot(state: &AppState, body: &str) -> anyhow::Result<()> {
    let payload: ClusterSnapshotPayload =
        serde_json::from_str(body).map_err(|e| anyhow::anyhow!("snapshot parse error: {e}"))?;

    // Apply the same validation backup-import enforces (10k rule cap, schema
    // version match, hostname sanity, etc). A compromised peer or stolen
    // API key cannot push out-of-bounds rule sets, expiry-zero auth config,
    // or future-schema configs that would corrupt our DB.
    payload
        .firewall
        .validate()
        .map_err(|e| anyhow::anyhow!("snapshot failed validation: {e}"))?;

    // Per-peer API keys are LOCAL credentials — never replicate them.
    // apply_firewall_config wipes cluster_nodes and rebuilds from the snapshot
    // (which was captured on the master, where this node's outgoing key is absent).
    // We preserve them here and restore them after apply so this node can keep
    // authenticating to its peers.
    let saved_keys: Vec<(String, Option<String>, Option<String>)> =
        sqlx::query_as("SELECT id, peer_api_key, peer_api_key_hash FROM cluster_nodes")
            .fetch_all(&state.pool)
            .await
            .unwrap_or_default();

    // Apply firewall config using an identity interface map (same-box restore)
    let iface_map = std::collections::HashMap::new();
    apply_firewall_config(state, &payload.firewall, &iface_map)
        .await
        .map_err(|sc| anyhow::anyhow!("apply_firewall_config failed: {sc:?}"))?;

    // Restore local per-peer credentials wiped by apply_firewall_config.
    for (id, key, hash) in &saved_keys {
        if (key.is_some() || hash.is_some())
            && let Err(e) = sqlx::query(
                "UPDATE cluster_nodes SET peer_api_key = ?1, peer_api_key_hash = ?2 WHERE id = ?3",
            )
            .bind(key)
            .bind(hash)
            .bind(id)
            .execute(&state.pool)
            .await
        {
            tracing::warn!(node = %id, error = %e, "cluster snapshot: peer api key restore failed");
        }
    }

    // Sync IDS rule overrides: apply enabled/action_override to ids_rules rows
    for ov in &payload.ids_rule_overrides {
        if let Err(e) =
            sqlx::query("UPDATE ids_rules SET enabled = ?1, action_override = ?2 WHERE id = ?3")
                .bind(ov.enabled)
                .bind(&ov.action_override)
                .bind(&ov.id)
                .execute(&state.pool)
                .await
        {
            tracing::warn!(rule = %ov.id, error = %e, "cluster snapshot: ids rule override sync failed");
        }
    }

    // Sync IDS suppressions: wipe and re-insert atomically so the IDS daemon
    // never sees an empty table mid-replace (WAL readers see pre-tx state until commit).
    let mut tx = state.pool.begin().await?;
    sqlx::query("DELETE FROM ids_suppressions")
        .execute(&mut *tx)
        .await?;
    for s in &payload.ids_suppressions {
        sqlx::query(
            "INSERT OR IGNORE INTO ids_suppressions (id, sid, suppress_type, ip_cidr) VALUES (?1, ?2, ?3, ?4)"
        )
        .bind(&s.id)
        .bind(s.sid)
        .bind(&s.suppress_type)
        .bind(&s.ip_cidr)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;

    // Reload IDS config so suppressions take effect
    if let Err(e) = state.ids_client.reload().await {
        tracing::warn!(error = %e, "cluster snapshot: ids reload failed");
    }

    Ok(())
}

#[cfg(test)]
mod auto_snapshot_tests {
    use super::should_skip_auto_snapshot;

    // PERF-H8 (#352) regression: non-structural mutations (alert acks,
    // classifications, test-fire endpoints) must not trigger a full
    // config rebuild + hash.
    #[test]
    fn skips_non_structural_routes() {
        for path in [
            "/api/v1/ids/alerts/42/acknowledge",
            "/api/v1/ids/alerts/42/classify",
            "/api/v1/ids/suppressions",
            "/api/v1/ids/config",
            "/api/v1/ai/analyze",
            "/api/v1/connections/1234",
            "/api/v1/auth/ws-ticket",
            "/api/v1/notify/smtp/test",
            "/api/v1/settings/ai/test",
            "/api/v1/backup/s3/test",
            "/api/v1/config/save",
            "/api/v1/updates/install",
        ] {
            assert!(
                should_skip_auto_snapshot(path),
                "{path} should skip auto-snapshot"
            );
        }
    }

    #[test]
    fn snapshots_structural_routes() {
        for path in [
            "/api/v1/rules",
            "/api/v1/rules/reorder",
            "/api/v1/nat",
            "/api/v1/vpn/wg",
            "/api/v1/geoip",
            "/api/v1/aliases",
            "/api/v1/dhcp/v4/subnets",
            "/api/v1/settings/pf-tuning",
        ] {
            assert!(
                !should_skip_auto_snapshot(path),
                "{path} should auto-snapshot"
            );
        }
    }
}
