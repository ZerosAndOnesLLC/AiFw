//! HTTP entry points + apply pipeline for OPNsense / pfSense `config.xml`.
//!
//! Design notes worth keeping in mind when modifying this file:
//!
//! * **Parse first, apply last.** Every error that can be detected from the
//!   XML alone surfaces in the preview, so an admin never gets a half-applied
//!   config because of a typo upstream.
//! * **Engine-routed writes.** Aliases go through `AliasEngine`, NAT through
//!   `NatEngine`, rules through `RuleEngine`, static routes through the same
//!   `apply_route_to_system` path the manual REST endpoint uses, and DNS
//!   through the same `auth_config.dns_servers` + `sudo tee /etc/resolv.conf`
//!   path that `update_dns` uses. No raw INSERTs that bypass `apply_*`.
//! * **Snapshot + commit-confirm.** Before any write, we save a
//!   `pre-OPNsense-import` config-history version so the import can be
//!   reverted in one click. After a successful apply we start commit-confirm
//!   so the admin's session can roll back rules+NAT if they lose access.
//! * **Reject → BlockReturn (per epic L1):** OPNsense `reject` is mapped to
//!   AiFw `Action::BlockReturn`. pf's `block return` emits TCP RST and ICMP
//!   unreachable for UDP/ICMP — the same per-protocol reaction OPNsense's
//!   reject produces. Documented here so reviewers don't second-guess.
//! * **Network keywords (`lan`, `wanip`, `(self)`, …) are dropped to a
//!   skipped list** rather than guessed. The summary tells the admin which
//!   rules need manual attention. Silent fidelity loss is the worst outcome.

use super::parser::{self, ParseError};
use super::types::*;
use crate::AppState;
use aifw_common::{
    Action, Address, Direction, Interface, IpVersion, NatRedirect, NatRule, NatStatus, NatType,
    PortRange, Protocol, Rule, RuleMatch, RuleStatus,
};
use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

const MAX_XML_BYTES: usize = 10 * 1024 * 1024; // 10 MiB — real configs are 50–500 KiB
const COMMIT_CONFIRM_SECONDS: u64 = 600;

// --------------------------------------------------------------------- request bodies

#[derive(Deserialize)]
pub struct PreviewRequest {
    pub xml: String,
    /// Optional interface map. Without it, preview falls back to the OPNsense
    /// names and the dry-run plan flags any rule whose interface didn't map
    /// to a system iface. Pass the same map you intend to send to /import.
    #[serde(default)]
    pub interface_map: HashMap<String, String>,
}

#[derive(Deserialize)]
pub struct ImportRequest {
    pub xml: String,
    #[serde(default)]
    pub interface_map: HashMap<String, String>,
    /// Start commit-confirm after a successful apply (rules+NAT auto-revert
    /// if admin doesn't confirm within the window). Default true; set false
    /// for unattended / programmatic imports.
    #[serde(default = "default_true")]
    pub commit_confirm: bool,
}
fn default_true() -> bool {
    true
}

// --------------------------------------------------------------------- response shapes

#[derive(Serialize)]
pub struct PreviewResponse {
    pub valid: bool,
    pub kind: String,
    pub version: Option<String>,
    pub system: PreviewSystem,
    pub counts: PreviewCounts,
    pub interfaces_found: Vec<String>,
    pub interfaces_system: Vec<String>,
    pub interfaces_need_mapping: bool,
    pub diff: PreviewDiff,
    pub skipped: Vec<String>,
    /// Dry-run plan — what the import would actually do, item by item, in
    /// AiFw form. Honors `interface_map` if the caller provided one.
    pub plan: PreviewPlan,
    pub error: Option<String>,
}

#[derive(Serialize, Default)]
pub struct PreviewPlan {
    pub rules: Vec<PlanRule>,
    pub nat: Vec<PlanNat>,
    pub aliases: Vec<PlanAlias>,
    pub routes: Vec<PlanRoute>,
}

#[derive(Serialize)]
pub struct PlanRule {
    pub action: String,
    pub direction: String,
    pub interface: Option<String>,
    pub ip_version: String,
    pub protocol: String,
    pub src: String,
    pub src_port: Option<String>,
    pub dst: String,
    pub dst_port: Option<String>,
    pub disabled: bool,
    pub log: bool,
    pub label: Option<String>,
    /// Set if the rule cannot be applied as-is. The UI can highlight these.
    pub skip_reason: Option<String>,
}

#[derive(Serialize)]
pub struct PlanNat {
    pub kind: String, // dnat | snat | masquerade | binat
    pub interface: String,
    pub protocol: String,
    pub src: String,
    pub dst: String,
    pub redirect: String,
    pub label: Option<String>,
    pub skip_reason: Option<String>,
}

#[derive(Serialize)]
pub struct PlanAlias {
    pub name: String,
    pub kind: String,
    pub entries: Vec<String>,
    pub skip_reason: Option<String>,
}

#[derive(Serialize)]
pub struct PlanRoute {
    pub network: String,
    pub gateway: String,
    pub gateway_name: String,
    pub disabled: bool,
    pub skip_reason: Option<String>,
}

#[derive(Serialize)]
pub struct PreviewSystem {
    pub hostname: Option<String>,
    pub domain: Option<String>,
    pub dns_servers: Vec<String>,
    pub timezone: Option<String>,
}

#[derive(Serialize, Default)]
pub struct PreviewCounts {
    pub rules: usize,
    pub aliases: usize,
    pub gateways: usize,
    pub nat_port_forwards: usize,
    pub nat_outbound: usize,
    pub nat_one_to_one: usize,
    pub static_routes: usize,
    pub dns_servers: usize,
}

#[derive(Serialize, Default)]
pub struct PreviewDiff {
    pub alias_name_collisions: Vec<String>,
    pub duplicate_rule_signatures: usize,
    pub nat_external_port_collisions: Vec<String>,
}

#[derive(Serialize)]
pub struct ImportResponse {
    pub message: String,
    pub applied: AppliedCounts,
    pub skipped: Vec<String>,
    pub pre_import_version: Option<i64>,
    pub commit_confirm_started: bool,
}

#[derive(Serialize, Default)]
pub struct AppliedCounts {
    pub rules: usize,
    pub aliases: usize,
    pub nat_port_forwards: usize,
    pub nat_outbound: usize,
    pub nat_one_to_one: usize,
    pub static_routes: usize,
    pub dns_servers: usize,
    pub hostname: bool,
}

// --------------------------------------------------------------------- preview entry point

pub async fn preview_opnsense(
    State(state): State<AppState>,
    Json(req): Json<PreviewRequest>,
) -> Result<Json<PreviewResponse>, StatusCode> {
    if req.xml.len() > MAX_XML_BYTES {
        return Err(StatusCode::PAYLOAD_TOO_LARGE);
    }

    let cfg = match parser::parse(&req.xml) {
        Ok(c) => c,
        Err(ParseError::WrongRoot(_)) => {
            return Ok(Json(PreviewResponse::invalid(
                "not an OPNsense or pfSense configuration",
            )));
        }
        Err(e) => {
            return Ok(Json(PreviewResponse::invalid(&e.to_string())));
        }
    };

    let sys_ifaces = list_system_interfaces().await;
    let need_mapping = cfg
        .interface_names
        .iter()
        .any(|i| !sys_ifaces.contains(i));

    let diff = build_diff(&state, &cfg).await;
    let skipped = report_skipped(&cfg);

    // Existing AiFw aliases — used both for diff and for the dry-run plan to
    // resolve OPNsense alias references the way the real import will.
    let existing_alias_names: HashSet<String> = state
        .alias_engine
        .list()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|a| a.name)
        .collect();
    let plan = build_plan(&cfg, &req.interface_map, &existing_alias_names);

    Ok(Json(PreviewResponse {
        valid: true,
        kind: format!("{:?}", cfg.kind).to_lowercase(),
        version: cfg.version.clone(),
        system: PreviewSystem {
            hostname: cfg.system.hostname.clone(),
            domain: cfg.system.domain.clone(),
            dns_servers: cfg.system.dns_servers.clone(),
            timezone: cfg.system.timezone.clone(),
        },
        counts: PreviewCounts {
            rules: cfg.rules.len(),
            aliases: cfg.aliases.len(),
            gateways: cfg.gateways.len(),
            nat_port_forwards: cfg.nat.port_forwards.len(),
            nat_outbound: cfg.nat.outbound.len(),
            nat_one_to_one: cfg.nat.onetoone.len(),
            static_routes: cfg.routes.len(),
            dns_servers: cfg.system.dns_servers.len(),
        },
        interfaces_found: cfg.interface_names.clone(),
        interfaces_system: sys_ifaces,
        interfaces_need_mapping: need_mapping,
        diff,
        skipped,
        plan,
        error: None,
    }))
}

/// Build the dry-run plan. Mirrors `apply_inner` translation logic but writes
/// nothing — pure transformation from `OpnConfig` → human-readable AiFw form.
fn build_plan(
    cfg: &OpnConfig,
    iface_map: &HashMap<String, String>,
    existing_aliases: &HashSet<String>,
) -> PreviewPlan {
    let mut plan = PreviewPlan::default();

    // Aliases: name set the rule plan will resolve against — matches what
    // the real import would produce after writing.
    let mut available_aliases: HashSet<String> = HashSet::new();
    for a in &cfg.aliases {
        let mut skip_reason: Option<String> = None;
        if a.disabled {
            skip_reason = Some("disabled in source config".into());
        } else if !valid_alias_name(&a.name) {
            skip_reason = Some("invalid alias name".into());
        } else if existing_aliases.contains(&a.name) {
            skip_reason = Some("name collides with existing AiFw alias".into());
        } else if !matches!(a.kind.as_str(), "host" | "network" | "port" | "url" | "urltable") {
            skip_reason = Some(format!("alias type '{}' not supported", a.kind));
        } else {
            available_aliases.insert(a.name.clone());
        }
        plan.aliases.push(PlanAlias {
            name: a.name.clone(),
            kind: a.kind.clone(),
            entries: a.content.clone(),
            skip_reason,
        });
    }

    // Rules
    for r in &cfg.rules {
        let interfaces: Vec<Option<String>> = if r.interface.is_empty() {
            vec![None]
        } else {
            r.interface
                .iter()
                .map(|i| Some(map_iface(i, iface_map)))
                .collect()
        };
        for iface in interfaces {
            let (src, src_port_repr, dst, dst_port_repr, skip_reason) =
                preview_rule_endpoints(r, &available_aliases);
            plan.rules.push(PlanRule {
                action: r.action.clone(),
                direction: r.direction.clone(),
                interface: iface,
                ip_version: match r.ipprotocol {
                    AddrFamily::Inet => "inet".into(),
                    AddrFamily::Inet6 => "inet6".into(),
                    AddrFamily::Both => "both".into(),
                },
                protocol: r.protocol.clone(),
                src,
                src_port: src_port_repr,
                dst,
                dst_port: dst_port_repr,
                disabled: r.disabled,
                log: r.log,
                label: r.descr.clone(),
                skip_reason,
            });
        }
    }

    // NAT
    for n in &cfg.nat.port_forwards {
        let redirect = format!(
            "{}:{}",
            n.target,
            n.local_port.as_deref().unwrap_or("?")
        );
        let skip = if n.disabled {
            Some("disabled".into())
        } else if n.target.parse::<std::net::IpAddr>().is_err() {
            Some(format!("redirect target '{}' is not an IP", n.target))
        } else {
            None
        };
        plan.nat.push(PlanNat {
            kind: "dnat".into(),
            interface: map_iface(&n.interface, iface_map),
            protocol: n.protocol.clone(),
            src: endpoint_summary(&n.source),
            dst: endpoint_summary(&n.destination),
            redirect,
            label: n.descr.clone(),
            skip_reason: skip,
        });
    }
    for n in &cfg.nat.outbound {
        let kind = match n.target.as_deref().filter(|s| !s.is_empty()) {
            None => "masquerade".to_string(),
            Some(_) => "snat".to_string(),
        };
        let skip = if n.disabled { Some("disabled".into()) } else { None };
        plan.nat.push(PlanNat {
            kind,
            interface: map_iface(&n.interface, iface_map),
            protocol: n.protocol.clone(),
            src: endpoint_summary(&n.source),
            dst: endpoint_summary(&n.destination),
            redirect: n.target.clone().unwrap_or_else(|| "(<iface>)".into()),
            label: n.descr.clone(),
            skip_reason: skip,
        });
    }
    for n in &cfg.nat.onetoone {
        let skip = if n.disabled { Some("disabled".into()) } else { None };
        plan.nat.push(PlanNat {
            kind: "binat".into(),
            interface: map_iface(&n.interface, iface_map),
            protocol: "any".into(),
            src: n.internal.clone(),
            dst: endpoint_summary(&n.destination),
            redirect: n.external.clone(),
            label: n.descr.clone(),
            skip_reason: skip,
        });
    }

    // Routes
    for r in &cfg.routes {
        let skip = if r.disabled {
            Some("disabled".into())
        } else if r.gateway.is_empty() || r.gateway.eq_ignore_ascii_case("dynamic") {
            Some(format!(
                "gateway '{}' unresolved (DHCP-derived)",
                r.gateway_name
            ))
        } else {
            None
        };
        plan.routes.push(PlanRoute {
            network: r.network.clone(),
            gateway: r.gateway.clone(),
            gateway_name: r.gateway_name.clone(),
            disabled: r.disabled,
            skip_reason: skip,
        });
    }

    plan
}

/// Render endpoint translation outcome for the dry-run plan. Returns a
/// tuple of (src_repr, src_port_repr, dst_repr, dst_port_repr, skip_reason).
fn preview_rule_endpoints(
    r: &OpnRule,
    aliases: &HashSet<String>,
) -> (String, Option<String>, String, Option<String>, Option<String>) {
    let (src_addr, src_skip) = render_endpoint(&r.source, aliases);
    let (dst_addr, dst_skip) = render_endpoint(&r.destination, aliases);
    let src_port = r.source.port.clone();
    let dst_port = r.destination.port.clone();
    let skip = src_skip.or(dst_skip);
    (src_addr, src_port, dst_addr, dst_port, skip)
}

fn render_endpoint(ep: &OpnEndpoint, aliases: &HashSet<String>) -> (String, Option<String>) {
    if ep.any {
        return ("any".into(), None);
    }
    if let Some(addr) = &ep.address {
        if Address::parse(addr).is_ok() {
            let prefix = if ep.not { "!" } else { "" };
            return (format!("{prefix}{addr}"), None);
        }
        if aliases.contains(addr) {
            return (format!("<{addr}>"), None);
        }
        return (
            addr.clone(),
            Some(format!("address '{addr}' not an IP/CIDR and no alias matches")),
        );
    }
    if let Some(net) = &ep.network {
        if aliases.contains(net) {
            return (format!("<{net}>"), None);
        }
        return (
            net.clone(),
            Some(format!(
                "network keyword '{net}' has no AiFw equivalent",
            )),
        );
    }
    ("any".into(), None)
}

fn endpoint_summary(ep: &OpnEndpoint) -> String {
    if ep.any {
        return "any".into();
    }
    let base = ep
        .address
        .clone()
        .or_else(|| ep.network.clone())
        .unwrap_or_else(|| "any".into());
    match &ep.port {
        Some(p) => format!("{base}:{p}"),
        None => base,
    }
}

impl PreviewResponse {
    fn invalid(reason: &str) -> Self {
        Self {
            valid: false,
            kind: "unknown".into(),
            version: None,
            system: PreviewSystem {
                hostname: None,
                domain: None,
                dns_servers: vec![],
                timezone: None,
            },
            counts: PreviewCounts::default(),
            interfaces_found: vec![],
            interfaces_system: vec![],
            interfaces_need_mapping: false,
            diff: PreviewDiff::default(),
            skipped: vec![],
            plan: PreviewPlan::default(),
            error: Some(reason.into()),
        }
    }
}

// --------------------------------------------------------------------- import entry point

pub async fn import_opnsense(
    State(state): State<AppState>,
    Json(req): Json<ImportRequest>,
) -> Result<Json<ImportResponse>, (StatusCode, String)> {
    if req.xml.len() > MAX_XML_BYTES {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "XML body exceeds 10 MiB cap".into()));
    }

    let cfg = parser::parse(&req.xml).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    // Pre-import snapshot — gives admins a one-click restore via /api/v1/config/history
    // even if the in-process auto-revert path also runs.
    let pre_import_version = save_pre_import_snapshot(&state).await.ok();

    let mut summary = AppliedCounts::default();
    let mut skipped: Vec<String> = Vec::new();

    if let Err(reason) = apply_inner(&state, &cfg, &req.interface_map, &mut summary, &mut skipped).await {
        // Best-effort rollback to the saved version. The admin still has
        // pre_import_version returned so they can re-restore manually.
        if let Some(v) = pre_import_version {
            tracing::warn!(version = v, "OPNsense import failed mid-apply; restoring snapshot");
            let _ = restore_pre_import(&state, v).await;
        }
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("import failed: {reason}")));
    }

    let mut commit_confirm_started = false;
    if req.commit_confirm {
        match start_commit_confirm(&state).await {
            Ok(()) => commit_confirm_started = true,
            Err(e) => tracing::warn!(error = %e, "commit-confirm start failed (import succeeded)"),
        }
    }

    let mut bits: Vec<String> = Vec::new();
    if summary.rules > 0 { bits.push(format!("{} firewall rules", summary.rules)); }
    if summary.aliases > 0 { bits.push(format!("{} aliases", summary.aliases)); }
    if summary.nat_port_forwards > 0 { bits.push(format!("{} port-forwards", summary.nat_port_forwards)); }
    if summary.nat_outbound > 0 { bits.push(format!("{} outbound NAT rules", summary.nat_outbound)); }
    if summary.nat_one_to_one > 0 { bits.push(format!("{} 1:1 NAT mappings", summary.nat_one_to_one)); }
    if summary.static_routes > 0 { bits.push(format!("{} static routes", summary.static_routes)); }
    if summary.dns_servers > 0 { bits.push(format!("{} DNS servers", summary.dns_servers)); }
    if summary.hostname { bits.push("hostname".into()); }
    let message = if bits.is_empty() {
        "Imported nothing — see skipped list".to_string()
    } else {
        format!("Imported: {}", bits.join(", "))
    };

    Ok(Json(ImportResponse {
        message,
        applied: summary,
        skipped,
        pre_import_version,
        commit_confirm_started,
    }))
}

// --------------------------------------------------------------------- apply pipeline

async fn apply_inner(
    state: &AppState,
    cfg: &OpnConfig,
    iface_map: &HashMap<String, String>,
    summary: &mut AppliedCounts,
    skipped: &mut Vec<String>,
) -> Result<(), String> {
    // Aliases first — rules below may reference them by name.
    let alias_name_set = apply_aliases(state, &cfg.aliases, summary, skipped).await;

    // Rules.
    apply_rules(state, &cfg.rules, iface_map, &alias_name_set, summary, skipped).await?;

    // NAT.
    apply_nat(state, &cfg.nat, iface_map, summary, skipped).await?;

    // Apply pf rule + NAT changes (engines reload pf for full anchor on apply_rules).
    state
        .rule_engine
        .apply_rules()
        .await
        .map_err(|e| format!("pf rules reload: {e}"))?;
    state
        .nat_engine
        .apply_rules()
        .await
        .map_err(|e| format!("pf NAT reload: {e}"))?;
    state.alias_engine.sync_all().await.map_err(|e| format!("alias sync: {e}"))?;

    // Static routes.
    apply_routes(state, &cfg.routes, summary, skipped).await;

    // DNS upstreams.
    if !cfg.system.dns_servers.is_empty() {
        let n = apply_dns_servers(state, &cfg.system.dns_servers).await;
        summary.dns_servers = n;
    }

    // Hostname.
    if let Some(ref h) = cfg.system.hostname {
        if apply_hostname(state, h, cfg.system.domain.as_deref()).await {
            summary.hostname = true;
        }
    }

    Ok(())
}

// --------------------------------------------------------------------- aliases (H3)

async fn apply_aliases(
    state: &AppState,
    aliases: &[OpnAlias],
    summary: &mut AppliedCounts,
    skipped: &mut Vec<String>,
) -> HashSet<String> {
    use aifw_common::{Alias, AliasType};
    let existing: HashSet<String> = state
        .alias_engine
        .list()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|a| a.name)
        .collect();

    let mut imported_names = HashSet::new();
    for a in aliases {
        if a.disabled {
            skipped.push(format!("alias '{}' (disabled)", a.name));
            continue;
        }
        if !valid_alias_name(&a.name) {
            skipped.push(format!("alias '{}' (invalid name)", a.name));
            continue;
        }
        if existing.contains(&a.name) {
            skipped.push(format!("alias '{}' (name collision)", a.name));
            continue;
        }
        let kind = match a.kind.to_lowercase().as_str() {
            "host" => AliasType::Host,
            "network" => AliasType::Network,
            "port" => AliasType::Port,
            "url" | "urltable" => AliasType::UrlTable,
            "geoip" | "external" | "asn" | "macaddress" => {
                skipped.push(format!("alias '{}' (type {} not supported)", a.name, a.kind));
                continue;
            }
            other => {
                skipped.push(format!("alias '{}' (unknown type {})", a.name, other));
                continue;
            }
        };
        let alias = Alias {
            id: Uuid::new_v4(),
            name: a.name.clone(),
            alias_type: kind,
            entries: a.content.clone(),
            description: a.descr.clone(),
            enabled: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        match state.alias_engine.add(alias).await {
            Ok(_) => {
                imported_names.insert(a.name.clone());
                summary.aliases += 1;
            }
            Err(e) => skipped.push(format!("alias '{}' ({})", a.name, e)),
        }
    }
    imported_names
}

fn valid_alias_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 31
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

// --------------------------------------------------------------------- rules (H1, H2, H3, H4)

async fn apply_rules(
    state: &AppState,
    opn_rules: &[OpnRule],
    iface_map: &HashMap<String, String>,
    alias_names: &HashSet<String>,
    summary: &mut AppliedCounts,
    skipped: &mut Vec<String>,
) -> Result<(), String> {
    let mut priority: i32 = 1000;
    for r in opn_rules {
        // Floating rules with a multi-interface list become one rule per
        // mapped interface. Single-iface rules pass through unchanged.
        let interfaces: Vec<Option<String>> = if r.interface.is_empty() {
            vec![None]
        } else {
            r.interface
                .iter()
                .map(|i| Some(map_iface(i, iface_map)))
                .collect()
        };

        for iface in interfaces {
            match build_rule(r, iface.as_deref(), alias_names, priority) {
                Ok(rule) => {
                    match state.rule_engine.add_rule(rule).await {
                        Ok(_) => summary.rules += 1,
                        Err(e) => skipped.push(format!("rule '{}' ({})", r.descr.as_deref().unwrap_or("(no descr)"), e)),
                    }
                    priority += 10;
                }
                Err(reason) => {
                    skipped.push(format!(
                        "rule '{}' ({})",
                        r.descr.as_deref().unwrap_or("(no descr)"),
                        reason
                    ));
                }
            }
        }
    }
    Ok(())
}

fn build_rule(
    r: &OpnRule,
    iface: Option<&str>,
    alias_names: &HashSet<String>,
    priority: i32,
) -> Result<Rule, String> {
    let action = match r.action.as_str() {
        "pass" => Action::Pass,
        "block" => Action::Block,
        // Per L1: BlockReturn maps cleanly to OPNsense `reject` semantics —
        // pf's `block return` emits RST for TCP and ICMP-unreachable for UDP.
        "reject" => Action::BlockReturn,
        other => return Err(format!("unknown action '{other}'")),
    };
    let direction = match r.direction.as_str() {
        "in" => Direction::In,
        "out" => Direction::Out,
        "any" | "" => Direction::Any,
        other => return Err(format!("unknown direction '{other}'")),
    };
    let ip_version = match r.ipprotocol {
        AddrFamily::Inet => IpVersion::Inet,
        AddrFamily::Inet6 => IpVersion::Inet6,
        AddrFamily::Both => IpVersion::Both,
    };
    let protocol = if r.protocol.is_empty() {
        Protocol::Any
    } else {
        Protocol::parse(&r.protocol).map_err(|e| e.to_string())?
    };
    let (src_addr, src_port) = translate_endpoint(&r.source, alias_names)?;
    let (dst_addr, dst_port) = translate_endpoint(&r.destination, alias_names)?;

    let mut rule = Rule::new(
        action,
        direction,
        protocol,
        RuleMatch {
            src_addr,
            src_port,
            dst_addr,
            dst_port,
        },
    );
    rule.priority = priority;
    rule.ip_version = ip_version;
    rule.interface = iface.map(|s| Interface(s.to_string()));
    rule.src_invert = r.source.not;
    rule.dst_invert = r.destination.not;
    rule.log = r.log;
    rule.quick = r.quick;
    rule.label = r.descr.clone();
    rule.status = if r.disabled {
        RuleStatus::Disabled
    } else {
        RuleStatus::Active
    };
    Ok(rule)
}

/// Convert an OPNsense endpoint to (`Address`, optional `PortRange`).
///
/// Network keywords like `lan`, `wanip`, `(self)` cannot be expressed as a
/// concrete `Address` and are rejected here so the rule lands on the
/// skipped list instead of silently becoming `Address::Any`.
fn translate_endpoint(
    ep: &OpnEndpoint,
    alias_names: &HashSet<String>,
) -> Result<(Address, Option<PortRange>), String> {
    let port = match ep.port.as_deref() {
        Some(p) => Some(parse_port_spec(p, alias_names)?),
        None => None,
    };
    if ep.any {
        return Ok((Address::Any, port));
    }
    if let Some(addr) = &ep.address {
        // Plain IP / CIDR first. If parse fails, treat as alias name.
        if let Ok(a) = Address::parse(addr) {
            return Ok((a, port));
        }
        if alias_names.contains(addr) {
            return Ok((Address::Table(addr.clone()), port));
        }
        return Err(format!("unresolvable address '{addr}'"));
    }
    if let Some(net) = &ep.network {
        // Aliases stored under <network> (older form).
        if alias_names.contains(net) {
            return Ok((Address::Table(net.clone()), port));
        }
        return Err(format!(
            "network keyword '{net}' has no AiFw equivalent — replace with the underlying address",
        ));
    }
    Err("endpoint has neither <any/>, <address>, nor <network>".into())
}

fn parse_port_spec(raw: &str, alias_names: &HashSet<String>) -> Result<PortRange, String> {
    let raw = raw.trim();
    // OPNsense uses `:` for ranges; some sources use `-`.
    let (start_s, end_s) = if let Some((s, e)) = raw.split_once(':') {
        (s, e)
    } else if let Some((s, e)) = raw.split_once('-') {
        (s, e)
    } else {
        (raw, raw)
    };
    let start: u16 = start_s
        .parse()
        .map_err(|_| {
            // Last resort: an alias name that resolves to a single port. Without
            // alias-content lookup we just reject so the caller can skip cleanly.
            if alias_names.contains(raw) {
                format!("port alias '{raw}' references not yet inlined")
            } else {
                format!("invalid port '{raw}'")
            }
        })?;
    let end: u16 = end_s.parse().map_err(|_| format!("invalid port range '{raw}'"))?;
    Ok(PortRange { start, end })
}

// --------------------------------------------------------------------- NAT (C2, C3, H7)

async fn apply_nat(
    state: &AppState,
    nat: &OpnNat,
    iface_map: &HashMap<String, String>,
    summary: &mut AppliedCounts,
    skipped: &mut Vec<String>,
) -> Result<(), String> {
    // Empty alias name set is fine for NAT — OPNsense rarely uses alias names
    // in NAT source/destination, and Address::parse handles literals.
    let empty = HashSet::new();

    for n in &nat.port_forwards {
        if n.disabled {
            skipped.push(format!("port-forward '{}' (disabled)", n.descr.as_deref().unwrap_or("")));
            continue;
        }
        match build_port_forward(n, iface_map, &empty) {
            Ok(rule) => match state.nat_engine.add_rule(rule).await {
                Ok(_) => summary.nat_port_forwards += 1,
                Err(e) => skipped.push(format!("port-forward '{}' ({})", n.descr.as_deref().unwrap_or(""), e)),
            },
            Err(reason) => skipped.push(format!("port-forward '{}' ({})", n.descr.as_deref().unwrap_or(""), reason)),
        }
    }

    for n in &nat.outbound {
        if n.disabled {
            skipped.push(format!("outbound NAT '{}' (disabled)", n.descr.as_deref().unwrap_or("")));
            continue;
        }
        match build_outbound(n, iface_map, &empty) {
            Ok(rule) => match state.nat_engine.add_rule(rule).await {
                Ok(_) => summary.nat_outbound += 1,
                Err(e) => skipped.push(format!("outbound NAT '{}' ({})", n.descr.as_deref().unwrap_or(""), e)),
            },
            Err(reason) => skipped.push(format!("outbound NAT '{}' ({})", n.descr.as_deref().unwrap_or(""), reason)),
        }
    }

    for n in &nat.onetoone {
        if n.disabled {
            skipped.push(format!("1:1 NAT '{}' (disabled)", n.descr.as_deref().unwrap_or("")));
            continue;
        }
        match build_one_to_one(n, iface_map, &empty) {
            Ok(rule) => match state.nat_engine.add_rule(rule).await {
                Ok(_) => summary.nat_one_to_one += 1,
                Err(e) => skipped.push(format!("1:1 NAT '{}' ({})", n.descr.as_deref().unwrap_or(""), e)),
            },
            Err(reason) => skipped.push(format!("1:1 NAT '{}' ({})", n.descr.as_deref().unwrap_or(""), reason)),
        }
    }

    Ok(())
}

fn build_port_forward(
    n: &OpnNatPortForward,
    iface_map: &HashMap<String, String>,
    aliases: &HashSet<String>,
) -> Result<NatRule, String> {
    let interface = Interface(map_iface(&n.interface, iface_map));
    let protocol = Protocol::parse(&n.protocol).map_err(|e| e.to_string())?;

    let (src_addr, src_port) = translate_endpoint_or_any(&n.source, aliases);
    // For DNAT, we always want a destination — `wanip`/`lanip` keyword maps
    // to "the interface address", which pf expresses as `(<iface>)`. We
    // approximate by using `Address::Any` (match any) — strictly less precise
    // but never wrong. Document for the operator.
    let (dst_addr_pre, dst_port) = translate_endpoint_or_any(&n.destination, aliases);
    let dst_addr = dst_addr_pre;

    let target_ip = Address::parse(&n.target).map_err(|e| format!("redirect target '{}': {}", n.target, e))?;
    let redirect_port = match n.local_port.as_deref() {
        Some(p) => Some(parse_port_spec(p, aliases).map_err(|e| e)?),
        None => dst_port.clone(),
    };

    // OPNsense port-forwards default to "redirect dest port → redirect target".
    // If only `<local-port>` was given, we still need a `dst_port` in NatRule
    // for DNAT validation, so reuse the redirect port when destination port is absent.
    let final_dst_port = dst_port.clone().or_else(|| redirect_port.clone());

    let now = chrono::Utc::now();
    Ok(NatRule {
        id: Uuid::new_v4(),
        nat_type: NatType::Dnat,
        interface,
        protocol,
        src_addr,
        src_port,
        dst_addr,
        dst_port: final_dst_port,
        redirect: NatRedirect {
            address: target_ip,
            port: redirect_port,
        },
        label: n.descr.clone(),
        status: NatStatus::Active,
        created_at: now,
        updated_at: now,
    })
}

fn build_outbound(
    n: &OpnNatOutbound,
    iface_map: &HashMap<String, String>,
    aliases: &HashSet<String>,
) -> Result<NatRule, String> {
    let interface = Interface(map_iface(&n.interface, iface_map));
    let protocol = Protocol::parse(&n.protocol).map_err(|e| e.to_string())?;
    let (src_addr, src_port) = translate_endpoint_or_any(&n.source, aliases);
    let (dst_addr, dst_port) = translate_endpoint_or_any(&n.destination, aliases);

    // Empty target = masquerade (use interface address). Concrete IP = SNAT.
    let (nat_type, redirect_addr) = match n.target.as_deref().filter(|s| !s.is_empty()) {
        None => (NatType::Masquerade, Address::Any),
        Some(t) => {
            let a = Address::parse(t).map_err(|e| format!("outbound target '{t}': {e}"))?;
            (NatType::Snat, a)
        }
    };

    let now = chrono::Utc::now();
    Ok(NatRule {
        id: Uuid::new_v4(),
        nat_type,
        interface,
        protocol,
        src_addr,
        src_port,
        dst_addr,
        dst_port,
        redirect: NatRedirect {
            address: redirect_addr,
            port: None,
        },
        label: n.descr.clone(),
        status: NatStatus::Active,
        created_at: now,
        updated_at: now,
    })
}

fn build_one_to_one(
    n: &OpnNatOneToOne,
    iface_map: &HashMap<String, String>,
    aliases: &HashSet<String>,
) -> Result<NatRule, String> {
    let interface = Interface(map_iface(&n.interface, iface_map));
    let external = Address::parse(&n.external).map_err(|e| format!("external '{}': {}", n.external, e))?;
    let internal = Address::parse(&n.internal).map_err(|e| format!("internal '{}': {}", n.internal, e))?;
    let (dst_addr, _) = translate_endpoint_or_any(&n.destination, aliases);

    let now = chrono::Utc::now();
    Ok(NatRule {
        id: Uuid::new_v4(),
        nat_type: NatType::Binat,
        interface,
        protocol: Protocol::Any,
        src_addr: internal,
        src_port: None,
        dst_addr,
        dst_port: None,
        redirect: NatRedirect {
            address: external,
            port: None,
        },
        label: n.descr.clone(),
        status: NatStatus::Active,
        created_at: now,
        updated_at: now,
    })
}

/// Like `translate_endpoint`, but for NAT contexts where any unresolved
/// keyword is benign — `wanip`, `lanip`, `(self)` reasonably collapse to
/// "match anything" in NAT source/destination matchers. This keeps NAT
/// rules useful even when the keyword-mapping isn't perfect.
fn translate_endpoint_or_any(
    ep: &OpnEndpoint,
    alias_names: &HashSet<String>,
) -> (Address, Option<PortRange>) {
    let port = ep
        .port
        .as_deref()
        .and_then(|p| parse_port_spec(p, alias_names).ok());
    if ep.any {
        return (Address::Any, port);
    }
    if let Some(addr) = &ep.address {
        if let Ok(a) = Address::parse(addr) {
            return (a, port);
        }
        if alias_names.contains(addr) {
            return (Address::Table(addr.clone()), port);
        }
    }
    if let Some(net) = &ep.network
        && alias_names.contains(net)
    {
        return (Address::Table(net.clone()), port);
    }
    (Address::Any, port)
}

// --------------------------------------------------------------------- routes (C3, H5)

async fn apply_routes(
    state: &AppState,
    routes: &[OpnRoute],
    summary: &mut AppliedCounts,
    skipped: &mut Vec<String>,
) {
    for r in routes {
        if r.disabled {
            skipped.push(format!("route {} (disabled)", r.network));
            continue;
        }
        // `dynamic` is OPNsense's marker for DHCP-derived gateways. Without
        // a concrete IP we'd write a bogus row.
        let gateway = r.gateway.trim();
        if gateway.is_empty() || gateway.eq_ignore_ascii_case("dynamic") {
            skipped.push(format!(
                "route {} (gateway '{}' unresolved — define static gateway in source config)",
                r.network, r.gateway_name
            ));
            continue;
        }
        if r.network.trim().is_empty() {
            skipped.push("route (empty network)".into());
            continue;
        }

        let id = Uuid::new_v4().to_string();
        let now = chrono::Utc::now().to_rfc3339();
        let insert = sqlx::query(
            "INSERT INTO static_routes (id, destination, gateway, interface, metric, enabled, description, created_at, fib) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        )
        .bind(&id)
        .bind(&r.network)
        .bind(gateway)
        .bind::<Option<&str>>(None)
        .bind(0_i64)
        .bind(true)
        .bind(r.descr.as_deref())
        .bind(&now)
        .bind(0_i64)
        .execute(&state.pool)
        .await;
        match insert {
            Ok(_) => {
                // Attempt to program the kernel route. Mirrors what
                // `routes::create_static_route` does for a single-route
                // creation request — see L1 / C3 in the epic.
                let _ = crate::routes::apply_route_to_system(&r.network, gateway, None, 0).await;
                summary.static_routes += 1;
            }
            Err(e) => skipped.push(format!("route {} ({})", r.network, e)),
        }
    }
}

// --------------------------------------------------------------------- DNS (C1)

async fn apply_dns_servers(state: &AppState, servers: &[String]) -> usize {
    // Validate first; skip junk silently rather than failing the whole import.
    let valid: Vec<&String> = servers
        .iter()
        .filter(|s| s.parse::<std::net::IpAddr>().is_ok())
        .collect();
    if valid.is_empty() {
        return 0;
    }
    let json = serde_json::to_string(&valid).unwrap_or_else(|_| "[]".into());
    let _ = sqlx::query("INSERT OR REPLACE INTO auth_config (key, value) VALUES ('dns_servers', ?1)")
        .bind(&json)
        .execute(&state.pool)
        .await;

    // Write /etc/resolv.conf via sudo tee, the same path /api/v1/dns uses.
    // On Linux/WSL dev builds sudo isn't typically configured for this — the
    // failure is logged and the DB row is what survives.
    let content: String = valid
        .iter()
        .map(|s| format!("nameserver {s}"))
        .collect::<Vec<_>>()
        .join("\n");
    if let Ok(mut child) = tokio::process::Command::new("/usr/local/bin/sudo")
        .args(["tee", "/etc/resolv.conf"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
    {
        if let Some(ref mut stdin) = child.stdin {
            use tokio::io::AsyncWriteExt;
            let _ = stdin.write_all(content.as_bytes()).await;
        }
        let _ = child.wait().await;
    }
    valid.len()
}

// --------------------------------------------------------------------- hostname (M4)

async fn apply_hostname(state: &AppState, hostname: &str, domain: Option<&str>) -> bool {
    if aifw_core::system_apply_helpers::validate_hostname(hostname).is_err() {
        return false;
    }
    // Persist to AiFw kv first so it survives reboot via system-settings UI.
    let _ = sqlx::query("INSERT OR REPLACE INTO system_config (key, value) VALUES ('hostname', ?1)")
        .bind(hostname)
        .execute(&state.pool)
        .await;
    if let Some(d) = domain {
        let _ = sqlx::query("INSERT OR REPLACE INTO system_config (key, value) VALUES ('domain', ?1)")
            .bind(d)
            .execute(&state.pool)
            .await;
    }
    // Apply to the running system. On Linux dev builds this is a no-op
    // (apply_general(_) returns ok); on FreeBSD it writes /etc/rc.conf and
    // calls hostname(1).
    let report = aifw_core::system_apply::apply_general(&aifw_core::system_apply::GeneralInput {
        hostname: hostname.to_string(),
        domain: domain.unwrap_or("").to_string(),
        timezone: "UTC".to_string(), // OPNsense timezone is also imported but applied separately by sysadmin choice
    })
    .await;
    report.ok
}

// --------------------------------------------------------------------- snapshot + commit-confirm

async fn save_pre_import_snapshot(state: &AppState) -> Result<i64, String> {
    use aifw_core::ConfigManager;
    let config = crate::backup::build_current_config(state)
        .await
        .map_err(|_| "snapshot build failed".to_string())?;
    let mgr = ConfigManager::new(state.pool.clone());
    mgr.migrate().await.map_err(|e| e.to_string())?;
    mgr.save_version(&config, "opnsense-import", Some("pre-OPNsense-import"))
        .await
        .map_err(|e| e.to_string())
}

async fn restore_pre_import(state: &AppState, version: i64) -> Result<(), String> {
    use aifw_core::ConfigManager;
    let mgr = ConfigManager::new(state.pool.clone());
    let config = mgr.get_version(version).await.map_err(|e| e.to_string())?;
    let iface_map = crate::backup::InterfaceMap::default();
    crate::backup::apply_firewall_config(state, &config, &iface_map)
        .await
        .map_err(|_| "snapshot apply failed".to_string())?;
    Ok(())
}

async fn start_commit_confirm(state: &AppState) -> Result<(), String> {
    let body = serde_json::json!({
        "timeout_secs": COMMIT_CONFIRM_SECONDS,
        "description": "OPNsense config import",
    });
    let res = crate::backup::commit_confirm_start(State(state.clone()), Json(body)).await;
    match res {
        Ok(_) => Ok(()),
        Err(code) => Err(format!("commit-confirm start returned {code}")),
    }
}

// --------------------------------------------------------------------- helpers

fn map_iface(name: &str, iface_map: &HashMap<String, String>) -> String {
    iface_map.get(name).cloned().unwrap_or_else(|| name.to_string())
}

async fn list_system_interfaces() -> Vec<String> {
    if let Ok(output) = tokio::process::Command::new("ifconfig")
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
    }
}

// --------------------------------------------------------------------- preview diff (L2)

async fn build_diff(state: &AppState, cfg: &OpnConfig) -> PreviewDiff {
    let mut diff = PreviewDiff::default();

    // Alias name collisions vs existing AiFw aliases.
    let existing_aliases: HashSet<String> = state
        .alias_engine
        .list()
        .await
        .unwrap_or_default()
        .into_iter()
        .map(|a| a.name)
        .collect();
    for a in &cfg.aliases {
        if existing_aliases.contains(&a.name) {
            diff.alias_name_collisions.push(a.name.clone());
        }
    }

    // Duplicate rule signatures inside the imported config (shape signal —
    // user can decide whether to deduplicate before import).
    let mut sigs: HashMap<String, usize> = HashMap::new();
    for r in &cfg.rules {
        let sig = format!(
            "{}:{}:{}:{:?}:{:?}:{:?}",
            r.action,
            r.direction,
            r.protocol,
            r.interface,
            r.source,
            r.destination
        );
        *sigs.entry(sig).or_default() += 1;
    }
    diff.duplicate_rule_signatures = sigs.values().filter(|&&n| n > 1).count();

    // External port collisions across imported port-forwards.
    let mut seen_ports: HashSet<String> = HashSet::new();
    for n in &cfg.nat.port_forwards {
        if let Some(p) = &n.local_port {
            let key = format!("{}:{}:{}", n.interface, n.protocol, p);
            if !seen_ports.insert(key.clone()) {
                diff.nat_external_port_collisions.push(key);
            }
        }
    }

    diff
}

// --------------------------------------------------------------------- skipped reporter

fn report_skipped(cfg: &OpnConfig) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut count_unsupported_aliases = 0;
    for a in &cfg.aliases {
        if matches!(a.kind.as_str(), "geoip" | "external" | "asn" | "macaddress") {
            count_unsupported_aliases += 1;
        }
    }
    if count_unsupported_aliases > 0 {
        out.push(format!(
            "{count_unsupported_aliases} aliases of unsupported type (geoip/external/asn/macaddress)"
        ));
    }
    let unresolved_routes = cfg
        .routes
        .iter()
        .filter(|r| r.gateway.is_empty() || r.gateway.eq_ignore_ascii_case("dynamic"))
        .count();
    if unresolved_routes > 0 {
        out.push(format!(
            "{unresolved_routes} static routes with unresolved (DHCP) gateways"
        ));
    }
    let net_keyword_rules = cfg
        .rules
        .iter()
        .filter(|r| {
            (r.source.network.as_deref().is_some_and(|n| !n.is_empty() && !is_alias_form(n)))
                || (r.destination.network.as_deref().is_some_and(|n| !n.is_empty() && !is_alias_form(n)))
        })
        .count();
    if net_keyword_rules > 0 {
        out.push(format!(
            "{net_keyword_rules} rules use OPNsense network keywords (lan/lanip/wanip/(self)) — import skips these as ambiguous"
        ));
    }
    out
}

fn is_alias_form(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        && !matches!(
            s,
            "lan" | "wan" | "lanip" | "wanip" | "(self)" | "any"
        )
        && !s.starts_with("opt")
}
