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
    active: bool,
    expires_at: String,
    seconds_remaining: u64,
    description: String,
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

    apply_firewall_config(&state, &config, &req.interface_map).await?;

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
        info.push(format!("{} IPsec SA(s)", ipsec.len()));
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
// OPNsense config import
// ============================================================

pub async fn import_opnsense(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let xml = payload
        .get("xml")
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let mut imported = Vec::new();

    // Interface mapping — user maps OPNsense names (wan, lan, opt1) to real interfaces
    let iface_map: std::collections::HashMap<String, String> = payload
        .get("interface_map")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let map_iface = |name: &str| -> String {
        iface_map
            .get(name)
            .cloned()
            .unwrap_or_else(|| name.to_string())
    };

    // Parse OPNsense XML config — extract rules, NAT, DNS, routes, interfaces
    // OPNsense uses <opnsense> or <pfsense> root with <filter><rule>, <nat><rule>, etc.

    // Extract firewall rules
    let mut rule_count = 0;
    for rule_xml in extract_xml_blocks(xml, "filter", "rule") {
        let action_str = extract_xml_value(&rule_xml, "type").unwrap_or_default();
        let action = match action_str.as_str() {
            "pass" => "pass",
            "block" => "block",
            "reject" => "block_return",
            _ => continue,
        };
        let direction =
            extract_xml_value(&rule_xml, "direction").unwrap_or_else(|| "in".to_string());
        let protocol =
            extract_xml_value(&rule_xml, "protocol").unwrap_or_else(|| "any".to_string());
        let src = extract_xml_value(&rule_xml, "source")
            .map(|s| parse_opn_addr(&s))
            .unwrap_or_default();
        let dst = extract_xml_value(&rule_xml, "destination")
            .map(|s| parse_opn_addr(&s))
            .unwrap_or_default();
        let interface = extract_xml_value(&rule_xml, "interface").map(|i| map_iface(&i));
        let descr = extract_xml_value(&rule_xml, "descr");
        let disabled = extract_xml_value(&rule_xml, "disabled").is_some();
        let log = extract_xml_value(&rule_xml, "log").is_some();

        let body = serde_json::json!({
            "action": action,
            "direction": direction,
            "protocol": protocol,
            "src_addr": if src.is_empty() { None } else { Some(&src) },
            "dst_addr": if dst.is_empty() { None } else { Some(&dst) },
            "interface": interface,
            "label": descr,
            "log": log,
            "status": if disabled { "disabled" } else { "active" },
        });

        // Create rule via internal logic
        let rule_json: crate::routes::CreateRuleRequest =
            serde_json::from_value(body).map_err(|_| internal())?;
        let _ = create_rule_internal(&state, rule_json).await;
        rule_count += 1;
    }
    if rule_count > 0 {
        imported.push(format!("{rule_count} firewall rules"));
    }

    // Extract NAT port forwards
    let mut nat_count = 0;
    for nat_xml in extract_xml_blocks(xml, "nat", "rule") {
        let interface = extract_xml_value(&nat_xml, "interface")
            .map(|i| map_iface(&i))
            .unwrap_or_else(|| "wan".to_string());
        let protocol = extract_xml_value(&nat_xml, "protocol").unwrap_or_else(|| "tcp".to_string());
        let target = extract_xml_value(&nat_xml, "target");
        let local_port = extract_xml_value(&nat_xml, "local-port");
        let _dst_port = extract_xml_value(&nat_xml, "destination");
        let descr = extract_xml_value(&nat_xml, "descr");

        if let (Some(target), Some(_lp)) = (&target, &local_port) {
            let redir = format!("{}:{}", target, local_port.as_deref().unwrap_or(""));
            let _ = sqlx::query(
                "INSERT INTO nat_rules (id, nat_type, interface, protocol, src_addr, dst_addr, redirect_addr, redirect_port, log, label, status, created_at, updated_at) VALUES (?1, 'port_forward', ?2, ?3, 'any', 'any', ?4, NULL, 0, ?5, 'active', ?6, ?6)"
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&interface)
            .bind(&protocol)
            .bind(&redir)
            .bind(descr.as_deref())
            .bind(chrono::Utc::now().to_rfc3339())
            .execute(&state.pool).await;
            nat_count += 1;
        }
    }
    if nat_count > 0 {
        imported.push(format!("{nat_count} NAT rules"));
    }

    // Extract DNS servers from <system><dnsserver>
    let mut dns_servers = Vec::new();
    let system_block = extract_xml_block(xml, "system").unwrap_or_default();
    for ns in extract_xml_values(&system_block, "dnsserver") {
        if !ns.is_empty() {
            dns_servers.push(ns);
        }
    }
    if !dns_servers.is_empty() {
        // Apply DNS servers to resolv.conf
        let resolv = dns_servers
            .iter()
            .map(|s| format!("nameserver {s}"))
            .collect::<Vec<_>>()
            .join("\n");
        let _ = tokio::fs::write("/etc/resolv.conf", &resolv).await;
        imported.push(format!("{} DNS servers (applied)", dns_servers.len()));
    }

    // Extract hostname
    if let Some(hostname) = extract_xml_value(&system_block, "hostname") {
        imported.push(format!("hostname: {hostname}"));
    }

    // Extract static routes from <staticroutes><route>
    let mut route_count = 0;
    for route_xml in extract_xml_blocks(xml, "staticroutes", "route") {
        let network = extract_xml_value(&route_xml, "network").unwrap_or_default();
        let gateway = extract_xml_value(&route_xml, "gateway").unwrap_or_default();
        let descr = extract_xml_value(&route_xml, "descr");
        let disabled = extract_xml_value(&route_xml, "disabled").is_some();

        if !network.is_empty() && !gateway.is_empty() {
            let _ = sqlx::query(
                "INSERT INTO static_routes (id, destination, gateway, interface, metric, enabled, description, created_at) VALUES (?1, ?2, ?3, NULL, 0, ?4, ?5, ?6)"
            )
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(&network).bind(&gateway)
            .bind(!disabled)
            .bind(descr.as_deref())
            .bind(chrono::Utc::now().to_rfc3339())
            .execute(&state.pool).await;
            route_count += 1;
        }
    }
    if route_count > 0 {
        imported.push(format!("{route_count} static routes"));
    }

    // Reload pf rules to apply imported firewall rules
    if rule_count > 0 || nat_count > 0 {
        let rules = state
            .rule_engine
            .list_rules()
            .await
            .map_err(|_| internal())?;
        let pf_rules: Vec<String> = rules.iter().map(|r| r.to_pf_rule("aifw")).collect();
        let _ = state.pf.load_rules("aifw", &pf_rules).await;
        imported.push("pf rules reloaded".to_string());
    }

    let msg = if imported.is_empty() {
        "No configuration could be parsed from OPNsense XML".to_string()
    } else {
        format!("Imported from OPNsense: {}", imported.join(", "))
    };

    Ok(Json(MessageResponse { message: msg }))
}

// ============================================================
// OPNsense Preview — parse XML and return summary without applying
// ============================================================

#[derive(Serialize)]
pub struct OpnPreview {
    valid: bool,
    rules: Vec<OpnPreviewRule>,
    nat_rules: Vec<OpnPreviewNat>,
    routes: Vec<OpnPreviewRoute>,
    dns_servers: Vec<String>,
    hostname: Option<String>,
    interfaces_found: Vec<String>,  // interfaces referenced in config
    interfaces_system: Vec<String>, // interfaces on this system
    interfaces_need_mapping: bool,  // true if config has interfaces not on this system
}

#[derive(Serialize)]
struct OpnPreviewRule {
    action: String,
    direction: String,
    protocol: String,
    src: String,
    dst: String,
    interface: Option<String>,
    label: Option<String>,
    disabled: bool,
    log: bool,
}
#[derive(Serialize)]
struct OpnPreviewNat {
    interface: String,
    protocol: String,
    target: String,
    port: String,
    label: Option<String>,
}
#[derive(Serialize)]
struct OpnPreviewRoute {
    network: String,
    gateway: String,
    description: Option<String>,
    disabled: bool,
}

pub async fn preview_opnsense(
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<OpnPreview>, StatusCode> {
    let xml = payload
        .get("xml")
        .and_then(|v| v.as_str())
        .ok_or(StatusCode::BAD_REQUEST)?;

    // Validate it looks like an OPNsense/pfSense config
    if !xml.contains("<opnsense") && !xml.contains("<pfsense") {
        return Ok(Json(OpnPreview {
            valid: false,
            rules: vec![],
            nat_rules: vec![],
            routes: vec![],
            dns_servers: vec![],
            hostname: None,
            interfaces_found: vec![],
            interfaces_system: vec![],
            interfaces_need_mapping: false,
        }));
    }

    let mut rules = Vec::new();
    let mut interfaces_found = std::collections::HashSet::new();

    for rule_xml in extract_xml_blocks(xml, "filter", "rule") {
        let action = extract_xml_value(&rule_xml, "type").unwrap_or_default();
        if !["pass", "block", "reject"].contains(&action.as_str()) {
            continue;
        }
        let iface = extract_xml_value(&rule_xml, "interface");
        if let Some(ref i) = iface {
            interfaces_found.insert(i.clone());
        }
        rules.push(OpnPreviewRule {
            action: match action.as_str() {
                "reject" => "block_return".into(),
                a => a.into(),
            },
            direction: extract_xml_value(&rule_xml, "direction").unwrap_or_else(|| "in".into()),
            protocol: extract_xml_value(&rule_xml, "protocol").unwrap_or_else(|| "any".into()),
            src: extract_xml_value(&rule_xml, "source")
                .map(|s| parse_opn_addr(&s))
                .unwrap_or_else(|| "any".into()),
            dst: extract_xml_value(&rule_xml, "destination")
                .map(|s| parse_opn_addr(&s))
                .unwrap_or_else(|| "any".into()),
            interface: iface,
            label: extract_xml_value(&rule_xml, "descr"),
            disabled: extract_xml_value(&rule_xml, "disabled").is_some(),
            log: extract_xml_value(&rule_xml, "log").is_some(),
        });
    }

    let mut nat_rules = Vec::new();
    for nat_xml in extract_xml_blocks(xml, "nat", "rule") {
        let iface = extract_xml_value(&nat_xml, "interface").unwrap_or_else(|| "wan".into());
        interfaces_found.insert(iface.clone());
        let target = extract_xml_value(&nat_xml, "target").unwrap_or_default();
        let port = extract_xml_value(&nat_xml, "local-port").unwrap_or_default();
        nat_rules.push(OpnPreviewNat {
            interface: iface,
            protocol: extract_xml_value(&nat_xml, "protocol").unwrap_or_else(|| "tcp".into()),
            target,
            port,
            label: extract_xml_value(&nat_xml, "descr"),
        });
    }

    let mut routes = Vec::new();
    for route_xml in extract_xml_blocks(xml, "staticroutes", "route") {
        routes.push(OpnPreviewRoute {
            network: extract_xml_value(&route_xml, "network").unwrap_or_default(),
            gateway: extract_xml_value(&route_xml, "gateway").unwrap_or_default(),
            description: extract_xml_value(&route_xml, "descr"),
            disabled: extract_xml_value(&route_xml, "disabled").is_some(),
        });
    }

    let system_block = extract_xml_block(xml, "system").unwrap_or_default();
    let dns_servers: Vec<String> = extract_xml_values(&system_block, "dnsserver")
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
    let hostname = extract_xml_value(&system_block, "hostname");

    // Get system interfaces
    let sys_ifaces: Vec<String> = if let Ok(output) = tokio::process::Command::new("ifconfig")
        .args(["-l"])
        .output()
        .await
    {
        String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .filter(|n| !n.starts_with("lo") && !n.starts_with("pflog"))
            .map(String::from)
            .collect()
    } else {
        vec![]
    };

    let config_ifaces: Vec<String> = interfaces_found.into_iter().collect();
    let need_mapping = config_ifaces.iter().any(|ci| {
        // OPNsense uses "wan", "lan", "opt1" etc. — not real interface names
        !sys_ifaces.contains(ci)
    });

    Ok(Json(OpnPreview {
        valid: true,
        rules,
        nat_rules,
        routes,
        dns_servers,
        hostname,
        interfaces_found: config_ifaces,
        interfaces_system: sys_ifaces,
        interfaces_need_mapping: need_mapping,
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

    // Snapshot current rules + NAT before the change
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
    let snapshot = FirewallConfig {
        rules: rules
            .iter()
            .map(|r| {
                use aifw_core::config::RuleConfig;
                RuleConfig {
                    id: r.id.to_string(),
                    priority: r.priority,
                    action: format!("{:?}", r.action).to_lowercase(),
                    direction: format!("{:?}", r.direction).to_lowercase(),
                    protocol: r.protocol.to_string(),
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
                    state_tracking: "keep_state".into(),
                    status: match r.status {
                        aifw_common::RuleStatus::Active => "active".into(),
                        _ => "disabled".into(),
                    },
                }
            })
            .collect(),
        nat: nat_rules
            .iter()
            .map(|n| {
                use aifw_core::config::NatRuleConfig;
                NatRuleConfig {
                    id: n.id.to_string(),
                    nat_type: format!("{:?}", n.nat_type).to_lowercase(),
                    interface: n.interface.0.clone(),
                    protocol: n.protocol.to_string(),
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
                    status: match n.status {
                        aifw_common::NatStatus::Active => "active".into(),
                        _ => "disabled".into(),
                    },
                }
            })
            .collect(),
        ..Default::default()
    };
    let snapshot_json = serde_json::to_string(&snapshot).map_err(|_| internal())?;

    let expires_at = chrono::Utc::now() + chrono::Duration::seconds(timeout_secs as i64);
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();

    // Store the rollback state
    {
        let mut store = commit_store().write().await;
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
                if let Some(inner) = store.write().await.take()
                    && let Ok(config) = serde_json::from_str::<FirewallConfig>(&inner.rollback_config) {
                        let _ = apply_firewall_config(&rollback_state, &config, &InterfaceMap::new()).await;
                        tracing::info!("Config rolled back successfully");
                    }
            }
            _ = cancel_rx => {
                // Confirmed — do nothing, config stays
                tracing::info!("Commit confirmed — config accepted");
            }
        }
    });

    Ok(Json(MessageResponse {
        message: format!(
            "Commit confirm started. You have {timeout_secs} seconds to confirm. If you do not log in and confirm, the configuration will automatically revert."
        ),
    }))
}

pub async fn commit_confirm_accept() -> Result<Json<MessageResponse>, StatusCode> {
    let mut store = commit_store().write().await;
    if let Some(inner) = store.take() {
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
    use aifw_core::{ha::ClusterEngine, shaping::ShapingEngine, tls::TlsEngine};

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

    let shaping = ShapingEngine::new(state.pool.clone(), state.pf.clone());
    let _ = shaping.migrate().await;
    let queues = shaping.list_queues().await.unwrap_or_default();
    let rate_limits = shaping.list_rate_limits().await.unwrap_or_default();

    let tls_engine = TlsEngine::new(state.pool.clone(), state.pf.clone());
    let _ = tls_engine.migrate().await;
    let sni_rules = tls_engine.list_sni_rules().await.unwrap_or_default();
    let ja3 = tls_engine.list_ja3_blocks().await.unwrap_or_default();

    let ha = ClusterEngine::new(state.pool.clone(), state.pf.clone());
    let _ = ha.migrate().await;
    let carp_vips = ha.list_carp_vips().await.unwrap_or_default();
    let cluster_nodes = ha.list_nodes().await.unwrap_or_default();
    let pfsync = ha.get_pfsync().await.ok().flatten();

    let max_states = aifw_core::pf_tuning::configured_max_states(&state.pool).await;

    let dns = tokio::fs::read_to_string("/etc/resolv.conf")
        .await
        .unwrap_or_default();
    let dns_servers: Vec<String> = dns
        .lines()
        .filter_map(|l| l.strip_prefix("nameserver").map(|s| s.trim().to_string()))
        .collect();

    let auth = &state.auth_settings;

    let mut wireguard: Vec<WireguardTunnelConfig> = Vec::with_capacity(wg_tunnels.len());
    for t in &wg_tunnels {
        let peers = state
            .vpn_engine
            .list_wg_peers(t.id)
            .await
            .unwrap_or_default();
        wireguard.push(WireguardTunnelConfig {
            id: t.id.to_string(),
            name: t.name.clone(),
            interface: t.interface.0.clone(),
            listen_port: t.listen_port,
            private_key: t.private_key.clone(),
            public_key: t.public_key.clone(),
            address: t.address.to_string(),
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
                action: enum_as_string(&r.action),
                direction: enum_as_string(&r.direction),
                protocol: enum_as_string(&r.protocol),
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
                state_tracking: enum_as_string(&r.state_options.tracking),
                status: enum_as_string(&r.status),
            })
            .collect(),
        nat: nat_rules
            .iter()
            .map(|n| NatRuleConfig {
                id: n.id.to_string(),
                nat_type: enum_as_string(&n.nat_type),
                interface: n.interface.0.clone(),
                protocol: enum_as_string(&n.protocol),
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
                status: enum_as_string(&n.status),
            })
            .collect(),
        queues: queues
            .iter()
            .map(|q| QueueConfigEntry {
                id: q.id.to_string(),
                name: q.name.clone(),
                interface: q.interface.0.clone(),
                queue_type: enum_as_string(&q.queue_type),
                bandwidth_value: q.bandwidth.value,
                bandwidth_unit: enum_as_string(&q.bandwidth.unit),
                traffic_class: enum_as_string(&q.traffic_class),
                bandwidth_pct: q.bandwidth_pct,
                default: q.default,
                status: enum_as_string(&q.status),
            })
            .collect(),
        rate_limits: rate_limits
            .iter()
            .map(|r| RateLimitEntry {
                id: r.id.to_string(),
                name: r.name.clone(),
                interface: r.interface.as_ref().map(|i| i.0.clone()),
                protocol: enum_as_string(&r.protocol),
                dst_port_start: r.dst_port.as_ref().map(|p| p.start),
                dst_port_end: r.dst_port.as_ref().map(|p| p.end),
                max_connections: r.max_connections,
                window_secs: r.window_secs,
                overload_table: r.overload_table.clone(),
                flush_states: r.flush_states,
                status: enum_as_string(&r.status),
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
                    protocol: enum_as_string(&s.protocol),
                    mode: enum_as_string(&s.mode),
                    enc_algo: s.enc_algo.clone(),
                    auth_algo: s.auth_algo.clone(),
                })
                .collect(),
        },
        geoip: geoip_rules
            .iter()
            .map(|g| GeoIpEntry {
                id: g.id.to_string(),
                country: g.country.0.clone(),
                action: enum_as_string(&g.action),
                label: g.label.clone(),
                status: enum_as_string(&g.status),
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
                    action: enum_as_string(&r.action),
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
    };

    Ok(config)
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
        "hex" => v.len() <= 510 && v.len() % 2 == 0 && v.chars().all(|c| c.is_ascii_hexdigit()),
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
pub(crate) async fn apply_firewall_config(
    state: &AppState,
    config: &FirewallConfig,
    iface_map: &InterfaceMap,
) -> Result<(), StatusCode> {
    use aifw_common::{
        Address, CountryCode, GeoIpAction, GeoIpRule, GeoIpRuleStatus, Interface, IpsecMode,
        IpsecProtocol, IpsecSa, VpnStatus, WgPeer, WgTunnel,
    };

    let _ = sqlx::query("DELETE FROM wg_peers")
        .execute(&state.pool)
        .await;
    let _ = sqlx::query("DELETE FROM wg_tunnels")
        .execute(&state.pool)
        .await;
    let _ = sqlx::query("DELETE FROM ipsec_sas")
        .execute(&state.pool)
        .await;
    let _ = sqlx::query("DELETE FROM geoip_rules")
        .execute(&state.pool)
        .await;
    let _ = sqlx::query("DELETE FROM rules").execute(&state.pool).await;
    let _ = sqlx::query("DELETE FROM nat_rules")
        .execute(&state.pool)
        .await;

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
            let _ = state.rule_engine.add_rule(rule).await;
        }
    }

    for nc in &config.nat {
        let Some(mapped_iface) = map_iface(&nc.interface, iface_map) else {
            continue;
        };
        let mut nc = nc.clone();
        nc.interface = mapped_iface;
        if let Some(nat) = nat_from_config(&nc) {
            let _ = state.nat_engine.add_rule(nat).await;
        }
    }

    for gc in &config.geoip {
        let Ok(country) = CountryCode::new(&gc.country) else {
            continue;
        };
        let Ok(action) = GeoIpAction::parse(&gc.action) else {
            continue;
        };
        let status = if gc.status == "disabled" {
            GeoIpRuleStatus::Disabled
        } else {
            GeoIpRuleStatus::Active
        };
        let id = uuid::Uuid::parse_str(&gc.id).unwrap_or_else(|_| uuid::Uuid::new_v4());
        let mut rule = GeoIpRule::new(country, action);
        rule.id = id;
        rule.label = gc.label.clone();
        rule.status = status;
        let _ = state.geoip_engine.add_rule(rule).await;
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
            dns: wg.dns.clone(),
            mtu: wg.mtu,
            listen_interface: None,
            split_routes: None,
            status: VpnStatus::Down,
            created_at: now,
            updated_at: now,
        };
        if state.vpn_engine.add_wg_tunnel(tunnel).await.is_err() {
            continue;
        }
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
            let _ = state.vpn_engine.add_wg_peer(peer).await;
        }
    }

    for sac in &config.vpn.ipsec {
        let Ok(src_addr) = Address::parse(&sac.src_addr) else {
            continue;
        };
        let Ok(dst_addr) = Address::parse(&sac.dst_addr) else {
            continue;
        };
        let Ok(protocol) = IpsecProtocol::parse(&sac.protocol) else {
            continue;
        };
        let mode = match sac.mode.as_str() {
            "transport" => IpsecMode::Transport,
            _ => IpsecMode::Tunnel,
        };
        let id = uuid::Uuid::parse_str(&sac.id).unwrap_or_else(|_| uuid::Uuid::new_v4());
        let mut sa = IpsecSa::new(sac.name.clone(), src_addr, dst_addr, protocol, mode);
        sa.id = id;
        sa.enc_algo = sac.enc_algo.clone();
        sa.auth_algo = sac.auth_algo.clone();
        let _ = state.vpn_engine.add_ipsec_sa(sa).await;
    }

    if !config.system.dns_servers.is_empty() {
        let content: String = config
            .system
            .dns_servers
            .iter()
            .map(|s| format!("nameserver {s}"))
            .collect::<Vec<_>>()
            .join("\n");
        let _ = tokio::fs::write("/etc/resolv.conf", &content).await;
    }

    let auth = &config.auth;
    let _ = sqlx::query(
        "INSERT OR REPLACE INTO auth_config (key, value) VALUES ('access_token_expiry_mins', ?1)",
    )
    .bind(auth.access_token_expiry_mins.to_string())
    .execute(&state.pool)
    .await;
    let _ = sqlx::query(
        "INSERT OR REPLACE INTO auth_config (key, value) VALUES ('refresh_token_expiry_days', ?1)",
    )
    .bind(auth.refresh_token_expiry_days.to_string())
    .execute(&state.pool)
    .await;
    let _ =
        sqlx::query("INSERT OR REPLACE INTO auth_config (key, value) VALUES ('require_totp', ?1)")
            .bind(if auth.require_totp { "true" } else { "false" })
            .execute(&state.pool)
            .await;

    // Traffic shaping: queues + per-IP rate limits
    let shaping = aifw_core::shaping::ShapingEngine::new(state.pool.clone(), state.pf.clone());
    let _ = shaping.migrate().await;
    let _ = sqlx::query("DELETE FROM queues").execute(&state.pool).await;
    let _ = sqlx::query("DELETE FROM rate_limits")
        .execute(&state.pool)
        .await;
    for qc in &config.queues {
        let Some(mapped) = map_iface(&qc.interface, iface_map) else {
            continue;
        };
        let mut qc = qc.clone();
        qc.interface = mapped;
        if let Some(q) = queue_from_config(&qc) {
            let _ = shaping.add_queue(q).await;
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
            let _ = shaping.add_rate_limit(r).await;
        }
    }
    let _ = shaping.apply_queues().await;
    let _ = shaping.apply_rate_limits().await;

    // TLS: SNI rules + JA3 blocklist
    let tls_engine = aifw_core::tls::TlsEngine::new(state.pool.clone(), state.pf.clone());
    let _ = tls_engine.migrate().await;
    let _ = sqlx::query("DELETE FROM sni_rules")
        .execute(&state.pool)
        .await;
    let _ = sqlx::query("DELETE FROM ja3_blocklist")
        .execute(&state.pool)
        .await;
    for sc in &config.tls.sni_rules {
        if let Some(sni) = sni_rule_from_config(sc) {
            let _ = tls_engine.add_sni_rule(sni).await;
        }
    }
    for hash in &config.tls.blocked_ja3 {
        let _ = tls_engine.add_ja3_block(hash, "restored from backup").await;
    }

    // HA: CARP VIPs + pfsync + cluster nodes
    let ha_engine = aifw_core::ha::ClusterEngine::new(state.pool.clone(), state.pf.clone());
    let _ = ha_engine.migrate().await;
    let _ = sqlx::query("DELETE FROM carp_vips")
        .execute(&state.pool)
        .await;
    let _ = sqlx::query("DELETE FROM pfsync_config")
        .execute(&state.pool)
        .await;
    let _ = sqlx::query("DELETE FROM cluster_nodes")
        .execute(&state.pool)
        .await;
    for vc in &config.ha.carp_vips {
        let Some(mapped) = map_iface(&vc.interface, iface_map) else {
            continue;
        };
        let mut vc = vc.clone();
        vc.interface = mapped;
        if let Some(vip) = carp_vip_from_config(&vc) {
            let _ = ha_engine.add_carp_vip(vip).await;
        }
    }
    if let Some(pc) = &config.ha.pfsync
        && let Some(mapped_sync) = map_iface(&pc.sync_interface, iface_map)
    {
        let mut pc = pc.clone();
        pc.sync_interface = mapped_sync;
        if let Some(pfsync) = pfsync_from_config(&pc) {
            let _ = ha_engine.set_pfsync(pfsync).await;
        }
    }
    for nc in &config.ha.nodes {
        if let Some(node) = cluster_node_from_config(nc) {
            let _ = ha_engine.add_node(node).await;
        }
    }

    // pf state-table tuning
    for t in &config.tuning {
        if t.enabled
            && t.key == "pf.max_states"
            && let Ok(val) = t.value.parse::<u64>()
        {
            let _ = aifw_core::pf_tuning::set_max_states(&state.pool, val).await;
        }
    }

    // DHCP: subnets, reservations, global/DDNS/HA config
    apply_dhcp_section(state, &config.dhcp).await;

    if let Ok(vpn_rules) = state.vpn_engine.collect_vpn_rules().await {
        state.rule_engine.set_extra_rules(vpn_rules).await;
    }
    let _ = state.rule_engine.apply_rules().await;
    let _ = state.nat_engine.apply_rules().await;
    let _ = state.geoip_engine.apply_rules().await;

    Ok(())
}

async fn apply_dhcp_section(state: &AppState, dhcp: &aifw_core::config::DhcpSection) {
    // Wipe + re-insert for a clean restore. `auto_apply` at the end regenerates
    // the rDHCP TOML config and restarts the service.
    let _ = sqlx::query("DELETE FROM dhcp_subnets")
        .execute(&state.pool)
        .await;
    let _ = sqlx::query("DELETE FROM dhcp_reservations")
        .execute(&state.pool)
        .await;
    let _ = sqlx::query("DELETE FROM dhcp_config")
        .execute(&state.pool)
        .await;
    let _ = sqlx::query("DELETE FROM dhcp_ddns_config")
        .execute(&state.pool)
        .await;
    let _ = sqlx::query("DELETE FROM dhcp_ha_config")
        .execute(&state.pool)
        .await;

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
        let _ = sqlx::query("INSERT OR REPLACE INTO dhcp_config (key, value) VALUES (?1, ?2)")
            .bind(k)
            .bind(v)
            .execute(&state.pool)
            .await;
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
        let _ = sqlx::query(
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
        .execute(&state.pool)
        .await;
    }

    // --- reservations ----------------------------------------
    for r in &dhcp.reservations {
        let _ = sqlx::query(
            "INSERT INTO dhcp_reservations (id, subnet_id, mac_address, ip_address, hostname, client_id, description, created_at) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8)"
        )
        .bind(&r.id).bind(&r.subnet_id).bind(&r.mac_address).bind(&r.ip_address)
        .bind(&r.hostname).bind(&r.client_id).bind(&r.description).bind(&r.created_at)
        .execute(&state.pool).await;
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
        let _ = sqlx::query("INSERT OR REPLACE INTO dhcp_ddns_config (key, value) VALUES (?1, ?2)")
            .bind(k)
            .bind(v)
            .execute(&state.pool)
            .await;
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
        let _ = sqlx::query("INSERT OR REPLACE INTO dhcp_ha_config (key, value) VALUES (?1, ?2)")
            .bind(k)
            .bind(v)
            .execute(&state.pool)
            .await;
    }

    // Regenerate rDHCP TOML + restart service so the restored config takes effect.
    crate::dhcp::auto_apply(state).await;
}

fn rule_from_config(rc: &aifw_core::config::RuleConfig) -> Option<aifw_common::Rule> {
    use aifw_common::*;
    let action: Action =
        serde_json::from_value(serde_json::Value::String(rc.action.clone())).ok()?;
    let direction: Direction =
        serde_json::from_value(serde_json::Value::String(rc.direction.clone())).ok()?;
    let protocol = Protocol::parse(&rc.protocol).ok()?;
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
    let tracking: StateTracking =
        serde_json::from_value(serde_json::Value::String(rc.state_tracking.clone()))
            .unwrap_or_default();
    let status = if rc.status == "disabled" {
        RuleStatus::Disabled
    } else {
        RuleStatus::Active
    };
    let id = uuid::Uuid::parse_str(&rc.id).unwrap_or_else(|_| uuid::Uuid::new_v4());
    let now = chrono::Utc::now();
    Some(Rule {
        id,
        priority: rc.priority,
        action,
        direction,
        ip_version: IpVersion::default(),
        interface: rc.interface.clone().map(Interface),
        protocol,
        rule_match: RuleMatch {
            src_addr,
            src_port,
            dst_addr,
            dst_port,
        },
        src_invert: false,
        dst_invert: false,
        log: rc.log,
        quick: rc.quick,
        label: rc.label.clone(),
        description: None,
        gateway: None,
        state_options: StateOptions {
            tracking,
            ..Default::default()
        },
        status,
        schedule_id: None,
        created_at: now,
        updated_at: now,
    })
}

fn nat_from_config(nc: &aifw_core::config::NatRuleConfig) -> Option<aifw_common::NatRule> {
    use aifw_common::*;
    let nat_type = NatType::parse(&nc.nat_type).ok()?;
    let protocol = Protocol::parse(&nc.protocol).ok()?;
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
    let status = if nc.status == "disabled" {
        NatStatus::Disabled
    } else {
        NatStatus::Active
    };
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
    let queue_type: QueueType =
        serde_json::from_value(serde_json::Value::String(qc.queue_type.clone())).ok()?;
    let unit: BandwidthUnit =
        serde_json::from_value(serde_json::Value::String(qc.bandwidth_unit.clone())).ok()?;
    let traffic_class: TrafficClass =
        serde_json::from_value(serde_json::Value::String(qc.traffic_class.clone())).ok()?;
    let status: QueueStatus =
        serde_json::from_value(serde_json::Value::String(qc.status.clone())).ok()?;
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
    })
}

fn rate_limit_from_config(
    rc: &aifw_core::config::RateLimitEntry,
) -> Option<aifw_common::RateLimitRule> {
    use aifw_common::*;
    let protocol = Protocol::parse(&rc.protocol).ok()?;
    let status: RateLimitStatus =
        serde_json::from_value(serde_json::Value::String(rc.status.clone())).ok()?;
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
    let action = SniAction::parse(&sc.action).ok()?;
    let id = uuid::Uuid::parse_str(&sc.id).unwrap_or_else(|_| uuid::Uuid::new_v4());
    let now = chrono::Utc::now();
    let mut rule = SniRule::new(sc.pattern.clone(), action);
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

async fn create_rule_internal(
    state: &AppState,
    req: crate::routes::CreateRuleRequest,
) -> Result<(), StatusCode> {
    use aifw_common::*;
    let action = match req.action.as_str() {
        "pass" => Action::Pass,
        "block" => Action::Block,
        "block_drop" | "block-drop" => Action::BlockDrop,
        "block_return" | "block-return" => Action::BlockReturn,
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    let direction = match req.direction.as_str() {
        "in" => Direction::In,
        "out" => Direction::Out,
        "any" => Direction::Any,
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    let protocol = Protocol::parse(&req.protocol).map_err(|_| StatusCode::BAD_REQUEST)?;
    let src_addr = req
        .src_addr
        .as_deref()
        .map(Address::parse)
        .transpose()
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .unwrap_or(Address::Any);
    let dst_addr = req
        .dst_addr
        .as_deref()
        .map(Address::parse)
        .transpose()
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .unwrap_or(Address::Any);
    let rule_match = RuleMatch {
        src_addr,
        src_port: None,
        dst_addr,
        dst_port: None,
    };
    let mut rule = Rule::new(action, direction, protocol, rule_match);
    rule.label = req.label;
    rule.interface = req.interface.map(Interface);
    if let Some(l) = req.log {
        rule.log = l;
    }
    let _ = state.rule_engine.add_rule(rule).await;
    Ok(())
}

fn gethostname() -> Option<String> {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

// Simple XML helpers (no external crate — OPNsense configs are relatively simple)
fn extract_xml_block(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)?;
    let end = xml.find(&close)?;
    Some(xml[start + open.len()..end].to_string())
}

fn extract_xml_blocks(xml: &str, parent: &str, child: &str) -> Vec<String> {
    let parent_block = match extract_xml_block(xml, parent) {
        Some(b) => b,
        None => return Vec::new(),
    };
    let open = format!("<{}>", child);
    let close = format!("</{}>", child);
    let mut results = Vec::new();
    let mut search = parent_block.as_str();
    while let Some(start) = search.find(&open) {
        if let Some(end) = search[start..].find(&close) {
            results.push(search[start + open.len()..start + end].to_string());
            search = &search[start + end + close.len()..];
        } else {
            break;
        }
    }
    results
}

fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)?;
    let end = xml[start..].find(&close)?;
    let value = xml[start + open.len()..start + end].trim().to_string();
    // Handle nested tags — just return the text content
    if value.contains('<') {
        Some(value.split('<').next().unwrap_or("").trim().to_string())
    } else {
        Some(value)
    }
}

fn extract_xml_values(xml: &str, tag: &str) -> Vec<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let mut results = Vec::new();
    let mut search = xml;
    while let Some(start) = search.find(&open) {
        if let Some(end) = search[start..].find(&close) {
            let val = search[start + open.len()..start + end].trim().to_string();
            if !val.is_empty() {
                results.push(val);
            }
            search = &search[start + end + close.len()..];
        } else {
            break;
        }
    }
    results
}

fn parse_opn_addr(s: &str) -> String {
    // OPNsense uses <address>x.x.x.x/y</address> or <any/>
    if s.contains("<any") || s.contains("any") {
        return "any".to_string();
    }
    // Try to extract an address
    if let Some(addr) = extract_xml_value(s, "address") {
        return addr;
    }
    if let Some(addr) = extract_xml_value(s, "network") {
        // OPNsense uses network names like "lan", "wan", "(self)"
        return match addr.as_str() {
            "(self)" => "self".to_string(),
            _ => addr,
        };
    }
    s.trim().to_string()
}

// ============================================================
// Auto-snapshot: every mutating HTTP request triggers a
// save_if_changed() so config history accrues without any
// per-endpoint plumbing. The middleware only runs AFTER a
// successful (2xx) response, and snapshotting runs in a
// spawned task so the response is never blocked.
// ============================================================

/// Routes where auto-snapshot would recurse or provide no value.
/// Config-management routes already manage their own versions;
/// WebSocket and streaming endpoints never change state.
fn should_skip_auto_snapshot(path: &str) -> bool {
    path.starts_with("/api/v1/config/")         // own subsystem
        || path.starts_with("/api/v1/auth/login")
        || path.starts_with("/api/v1/auth/refresh")
        || path.starts_with("/api/v1/auth/logout")
        || path.starts_with("/api/v1/auth/register")
        || path.starts_with("/api/v1/auth/totp/login")
        || path.starts_with("/api/v1/auth/oauth/")
        || path.starts_with("/api/v1/dns/stream")  // WebSocket
        || path.starts_with("/api/v1/ws")          // WebSocket
        || path.starts_with("/api/v1/pending/stream")
        || path.starts_with("/api/v1/updates/")    // ship-via-package ops, not config
        || path.starts_with("/api/v1/reload")      // no config delta
        || path.starts_with("/api/v1/metrics")
}

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

    if !mutating || should_skip_auto_snapshot(&path) {
        return response;
    }
    if !response.status().is_success() {
        return response;
    }

    // Hand off to a background task so the client response isn't blocked
    // by rebuilding + hashing the config. `save_if_changed` is a no-op if
    // the hash is unchanged, which most endpoints will be.
    let bg_state = state.clone();
    let bg_actor = "auto".to_string();
    let bg_comment = format!("{method} {path}");
    tokio::spawn(async move {
        let cfg = match build_current_config(&bg_state).await {
            Ok(c) => c,
            Err(_) => {
                tracing::debug!("auto-snapshot: build_current_config failed");
                return;
            }
        };
        let mgr = ConfigManager::new(bg_state.pool.clone());
        let _ = mgr.migrate().await;
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
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e))?;
    mgr.set_retention_limit(req.max_versions)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;
    get_retention(State(state))
        .await
        .map_err(|c| (c, "read back failed".into()))
}
