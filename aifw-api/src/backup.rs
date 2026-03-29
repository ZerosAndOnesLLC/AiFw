use axum::{extract::{Query, State}, http::StatusCode, Json};
use aifw_core::config_manager::{ConfigManager, ConfigVersion, ConfigDiff};
use aifw_core::config::FirewallConfig;
use serde::{Deserialize, Serialize};

use crate::AppState;

fn internal() -> StatusCode { StatusCode::INTERNAL_SERVER_ERROR }

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
    let history = mgr.history(params.limit.unwrap_or(50)).await.map_err(|_| internal())?;
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
    let config = mgr.get_version(params.version).await.map_err(|_| StatusCode::NOT_FOUND)?;
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
    let summary = mgr.diff(params.v1, params.v2).await.map_err(|_| internal())?;
    let c1 = mgr.get_version(params.v1).await.map_err(|_| internal())?;
    let c2 = mgr.get_version(params.v2).await.map_err(|_| internal())?;
    let v1_json = serde_json::to_value(&c1).map_err(|_| internal())?;
    let v2_json = serde_json::to_value(&c2).map_err(|_| internal())?;

    Ok(Json(ApiResponse {
        data: DetailedDiff { summary, v1_json, v2_json },
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
    let version = mgr.save_version(&config, "admin", req.comment.as_deref())
        .await.map_err(|_| internal())?;
    mgr.mark_applied(version).await.map_err(|_| internal())?;
    Ok(Json(MessageResponse { message: format!("Config saved as version {version}") }))
}

// ============================================================
// Restore to a previous version
// ============================================================

#[derive(Deserialize)]
pub struct RestoreRequest {
    pub version: i64,
}

pub async fn restore_version(
    State(state): State<AppState>,
    Json(req): Json<RestoreRequest>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let mgr = ConfigManager::new(state.pool.clone());
    let config = mgr.get_version(req.version).await.map_err(|_| StatusCode::NOT_FOUND)?;

    // Apply the config: clear current rules/nat/routes and re-import from the version
    apply_firewall_config(&state, &config).await?;

    mgr.mark_applied(req.version).await.map_err(|_| internal())?;

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
    let rules = state.rule_engine.list_rules().await.map_err(|_| internal())?;
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
    let nat_rules = state.nat_engine.list_rules().await.map_err(|_| internal())?;
    info.push(format!("{} NAT rules configured", nat_rules.len()));

    // Check for duplicate NAT port forwards
    let mut seen_ports: std::collections::HashSet<String> = std::collections::HashSet::new();
    for nat in &nat_rules {
        {
            let key = format!("{}:{:?}:{}", nat.interface, nat.protocol, nat.redirect);
            if !seen_ports.insert(key.clone()) {
                warnings.push(format!("Possible duplicate NAT forward on {}", nat.interface));
            }
        }
    }

    // Check GeoIP
    let geoip_rules = state.geoip_engine.list_rules().await.map_err(|_| internal())?;
    if !geoip_rules.is_empty() {
        info.push(format!("{} Geo-IP rules configured", geoip_rules.len()));
    }

    // Check VPN
    let wg = state.vpn_engine.list_wg_tunnels().await.map_err(|_| internal())?;
    let ipsec = state.vpn_engine.list_ipsec_sas().await.map_err(|_| internal())?;
    if !wg.is_empty() { info.push(format!("{} WireGuard tunnel(s)", wg.len())); }
    if !ipsec.is_empty() { info.push(format!("{} IPsec SA(s)", ipsec.len())); }

    // Check DNS
    let dns = tokio::fs::read_to_string("/etc/resolv.conf").await.unwrap_or_default();
    let dns_count = dns.lines().filter(|l| l.starts_with("nameserver")).count();
    if dns_count == 0 {
        errors.push("No DNS nameservers configured in /etc/resolv.conf".to_string());
    } else {
        info.push(format!("{} DNS nameserver(s) configured", dns_count));
    }

    // Check static routes
    let routes = sqlx::query_as::<_, (i64,)>("SELECT COUNT(*) FROM static_routes WHERE enabled = 1")
        .fetch_one(&state.pool).await.map(|r| r.0).unwrap_or(0);
    if routes > 0 { info.push(format!("{} static route(s)", routes)); }

    // Check pf status
    let pf_ok = state.pf.get_stats().await.is_ok();
    if pf_ok {
        info.push("pf firewall is responding".to_string());
    } else {
        warnings.push("pf firewall is not responding — rules may not be loaded".to_string());
    }

    // Check for empty ruleset
    if rules.is_empty() {
        warnings.push("No firewall rules configured — all traffic may be blocked or allowed by default".to_string());
    }

    let valid = errors.is_empty();

    Ok(Json(ApiResponse {
        data: ConfigCheck { valid, errors, warnings, info },
    }))
}

// ============================================================
// OPNsense config import
// ============================================================

pub async fn import_opnsense(
    State(state): State<AppState>,
    Json(payload): Json<serde_json::Value>,
) -> Result<Json<MessageResponse>, StatusCode> {
    let xml = payload.get("xml").and_then(|v| v.as_str()).ok_or(StatusCode::BAD_REQUEST)?;
    let mut imported = Vec::new();

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
        let direction = extract_xml_value(&rule_xml, "direction").unwrap_or_else(|| "in".to_string());
        let protocol = extract_xml_value(&rule_xml, "protocol").unwrap_or_else(|| "any".to_string());
        let src = extract_xml_value(&rule_xml, "source").map(|s| parse_opn_addr(&s)).unwrap_or_default();
        let dst = extract_xml_value(&rule_xml, "destination").map(|s| parse_opn_addr(&s)).unwrap_or_default();
        let interface = extract_xml_value(&rule_xml, "interface");
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
        let rule_json: crate::routes::CreateRuleRequest = serde_json::from_value(body).map_err(|_| internal())?;
        let _ = create_rule_internal(&state, rule_json).await;
        rule_count += 1;
    }
    if rule_count > 0 { imported.push(format!("{rule_count} firewall rules")); }

    // Extract NAT port forwards
    let mut nat_count = 0;
    for nat_xml in extract_xml_blocks(xml, "nat", "rule") {
        let interface = extract_xml_value(&nat_xml, "interface").unwrap_or_else(|| "wan".to_string());
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
    if nat_count > 0 { imported.push(format!("{nat_count} NAT rules")); }

    // Extract DNS servers from <system><dnsserver>
    let mut dns_servers = Vec::new();
    let system_block = extract_xml_block(xml, "system").unwrap_or_default();
    for ns in extract_xml_values(&system_block, "dnsserver") {
        if !ns.is_empty() { dns_servers.push(ns); }
    }
    if !dns_servers.is_empty() {
        imported.push(format!("{} DNS servers", dns_servers.len()));
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
    if route_count > 0 { imported.push(format!("{route_count} static routes")); }

    let msg = if imported.is_empty() {
        "No configuration could be parsed from OPNsense XML".to_string()
    } else {
        format!("Imported from OPNsense: {}", imported.join(", "))
    };

    Ok(Json(MessageResponse { message: msg }))
}

// ============================================================
// Helpers
// ============================================================

/// Build a FirewallConfig from current live state
async fn build_current_config(state: &AppState) -> Result<FirewallConfig, StatusCode> {
    let rules = state.rule_engine.list_rules().await.map_err(|_| internal())?;
    let nat_rules = state.nat_engine.list_rules().await.map_err(|_| internal())?;
    let geoip_rules = state.geoip_engine.list_rules().await.map_err(|_| internal())?;
    let wg_tunnels = state.vpn_engine.list_wg_tunnels().await.map_err(|_| internal())?;
    let ipsec_sas = state.vpn_engine.list_ipsec_sas().await.map_err(|_| internal())?;

    let dns = tokio::fs::read_to_string("/etc/resolv.conf").await.unwrap_or_default();
    let dns_servers: Vec<String> = dns.lines()
        .filter_map(|l| l.strip_prefix("nameserver").map(|s| s.trim().to_string())).collect();

    let auth = &state.auth_settings;

    use aifw_core::config::*;

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
        },
        auth: AuthConfig {
            access_token_expiry_mins: auth.access_token_expiry_mins,
            refresh_token_expiry_days: auth.refresh_token_expiry_days,
            require_totp: auth.require_totp,
            require_totp_for_oauth: false,
            auto_create_oauth_users: true,
        },
        rules: rules.iter().map(|r| RuleConfig {
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
            state_tracking: format!("{:?}", r.state_options.tracking).to_lowercase(),
            status: if r.status == aifw_common::RuleStatus::Active { "active".to_string() } else { "disabled".to_string() },
        }).collect(),
        nat: nat_rules.iter().map(|n| NatRuleConfig {
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
            status: if n.status == aifw_common::NatStatus::Active { "active".to_string() } else { "disabled".to_string() },
        }).collect(),
        queues: Vec::new(),
        rate_limits: Vec::new(),
        vpn: VpnConfig {
            wireguard: wg_tunnels.iter().map(|t| WireguardTunnelConfig {
                id: t.id.to_string(),
                name: t.name.clone(),
                interface: t.interface.0.clone(),
                listen_port: t.listen_port,
                private_key: String::new(),
                public_key: t.public_key.clone(),
                address: t.address.to_string(),
                dns: t.dns.clone(),
                mtu: t.mtu,
                peers: Vec::new(), // peers fetched separately
            }).collect(),
            ipsec: ipsec_sas.iter().map(|s| IpsecSaConfig {
                id: s.id.to_string(),
                name: s.name.clone(),
                src_addr: s.src_addr.to_string(),
                dst_addr: s.dst_addr.to_string(),
                protocol: format!("{:?}", s.protocol).to_lowercase(),
                mode: format!("{:?}", s.mode).to_lowercase(),
                enc_algo: s.enc_algo.clone(),
                auth_algo: s.auth_algo.clone(),
            }).collect(),
        },
        geoip: geoip_rules.iter().map(|g| GeoIpEntry {
            id: g.id.to_string(),
            country: g.country.0.clone(),
            action: format!("{:?}", g.action).to_lowercase(),
            label: g.label.clone(),
            status: if g.status == aifw_common::GeoIpRuleStatus::Active { "active".to_string() } else { "disabled".to_string() },
        }).collect(),
        tls: TlsConfig::default(),
        ha: HaConfig::default(),
        tuning: Vec::new(),
    };

    Ok(config)
}

/// Apply a FirewallConfig by importing rules/nat/routes
async fn apply_firewall_config(state: &AppState, config: &FirewallConfig) -> Result<(), StatusCode> {
    // Clear existing rules
    let _ = sqlx::query("DELETE FROM rules").execute(&state.pool).await;
    let _ = sqlx::query("DELETE FROM nat_rules").execute(&state.pool).await;

    // Re-import rules
    for rc in &config.rules {
        let body = serde_json::json!({
            "action": rc.action,
            "direction": rc.direction,
            "protocol": rc.protocol,
            "src_addr": rc.src_addr,
            "dst_addr": rc.dst_addr,
            "interface": rc.interface,
            "label": rc.label,
            "log": rc.log,
            "quick": rc.quick,
            "status": rc.status,
        });
        if let Ok(req) = serde_json::from_value::<crate::routes::CreateRuleRequest>(body) {
            let _ = create_rule_internal(state, req).await;
        }
    }

    // Re-import NAT
    for nc in &config.nat {
        let id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let _ = sqlx::query(
            "INSERT INTO nat_rules (id, nat_type, interface, protocol, src_addr, dst_addr, redirect_addr, redirect_port_start, redirect_port_end, log, label, status, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10, ?11, ?12, ?12)"
        )
        .bind(&id).bind(&nc.nat_type).bind(&nc.interface).bind(&nc.protocol)
        .bind(nc.src_addr.as_deref()).bind(nc.dst_addr.as_deref())
        .bind(&nc.redirect_addr)
        .bind(nc.redirect_port_start.map(|p| p as i64))
        .bind(nc.redirect_port_end.map(|p| p as i64))
        .bind(nc.label.as_deref())
        .bind(&nc.status)
        .bind(&now)
        .execute(&state.pool).await;
    }

    // Reload pf rules
    let rules = state.rule_engine.list_rules().await.map_err(|_| internal())?;
    let pf_rules: Vec<String> = rules.iter().map(|r| r.to_pf_rule("aifw")).collect();
    let _ = state.pf.load_rules("aifw", &pf_rules).await;

    Ok(())
}

async fn create_rule_internal(state: &AppState, req: crate::routes::CreateRuleRequest) -> Result<(), StatusCode> {
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
    let src_addr = req.src_addr.as_deref().map(Address::parse).transpose().map_err(|_| StatusCode::BAD_REQUEST)?.unwrap_or(Address::Any);
    let dst_addr = req.dst_addr.as_deref().map(Address::parse).transpose().map_err(|_| StatusCode::BAD_REQUEST)?.unwrap_or(Address::Any);
    let rule_match = RuleMatch { src_addr, src_port: None, dst_addr, dst_port: None };
    let mut rule = Rule::new(action, direction, protocol, rule_match);
    rule.label = req.label;
    rule.interface = req.interface.map(Interface);
    if let Some(l) = req.log { rule.log = l; }
    let _ = state.rule_engine.add_rule(rule).await;
    Ok(())
}

fn gethostname() -> Option<String> {
    std::fs::read_to_string("/etc/hostname").ok().map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
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
            if !val.is_empty() { results.push(val); }
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
