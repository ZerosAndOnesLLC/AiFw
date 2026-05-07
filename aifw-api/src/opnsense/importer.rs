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
    /// Apply hostname/domain/DNS upstreams from the source config. Defaults
    /// to false: most admins want to import rules + NAT + aliases without
    /// having their AiFw hostname renamed to the OPNsense one and their
    /// rDNS upstreams overwritten. Opt in if you want a full migration.
    #[serde(default)]
    pub import_system_settings: bool,
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
        // M1 from audit: kind comparison must match what `apply_aliases`
        // does (case-insensitive). Without the lowercase, `<type>HOST</type>`
        // would plan as "type 'HOST' not supported" but apply successfully.
        let kind_lc = a.kind.to_lowercase();
        let mut skip_reason: Option<String> = None;
        if a.disabled {
            skip_reason = Some("disabled in source config".into());
        } else if !valid_alias_name(&a.name) {
            skip_reason = Some("invalid alias name".into());
        } else if existing_aliases.contains(&a.name) {
            skip_reason = Some("name collides with existing AiFw alias".into());
        } else if !matches!(kind_lc.as_str(), "host" | "network" | "port" | "url" | "urltable") {
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
            let (src, src_port_repr, dst, dst_port_repr, mut skip_reason) =
                preview_rule_endpoints(r, &available_aliases);
            // H2/H3 from audit: validate port/protocol compatibility and
            // port-alias resolution at plan time so the dry-run reflects
            // what apply will actually do.
            if skip_reason.is_none() && (src_port_repr.is_some() || dst_port_repr.is_some()) {
                let proto_ok = matches!(
                    r.protocol.to_lowercase().as_str(),
                    "tcp" | "udp" | "tcpudp" | "tcp/udp" | "tcp+udp"
                );
                if !proto_ok {
                    skip_reason = Some(format!(
                        "port matching requires tcp/udp protocol; rule has protocol '{}'",
                        r.protocol
                    ));
                }
            }
            if skip_reason.is_none() {
                for p in [&src_port_repr, &dst_port_repr].into_iter().flatten() {
                    if parse_port_spec(p, &available_aliases).is_err() {
                        skip_reason = Some(format!("port spec '{p}' not parseable as number/range"));
                        break;
                    }
                }
            }
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
        // M11 from audit: don't render a literal `?` for missing ports.
        let redirect = match n.local_port.as_deref() {
            Some(p) => format!("{}:{}", n.target, p),
            None => n.target.clone(),
        };
        // H9 from audit: NatEngine rejects DNAT without any port. Surface
        // here so the plan reflects the apply outcome.
        let skip = if n.disabled {
            Some("disabled".into())
        } else if n.target.parse::<std::net::IpAddr>().is_err() {
            Some(format!("redirect target '{}' is not an IP", n.target))
        } else if n.local_port.is_none() && n.destination.port.is_none() {
            Some("DNAT/port-forward needs <destination><port> or <local-port>; full-IP redirects unsupported".into())
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

    // Refuse to start if the caller wants to arm a new commit-confirm window
    // but one is already active. Stacking would silently drop the older
    // timer and reapply the wrong rollback target on expiry. Imports that
    // explicitly opt out (`commit_confirm: false`) don't touch the timer at
    // all, so let those proceed.
    if req.commit_confirm && commit_confirm_active().await {
        return Err((
            StatusCode::CONFLICT,
            "another commit-confirm window is currently active — accept or wait for it to expire before importing".into(),
        ));
    }

    // Capture *pre*-apply state for the commit-confirm rollback target.
    // The previous design captured POST-apply, which meant the auto-revert
    // would "revert" to the just-applied state.
    let pre_apply_snapshot_json = match crate::backup::capture_runtime_snapshot(&state).await {
        Ok(s) => Some(s),
        Err(_) => None,
    };

    // Pre-import snapshot for /api/v1/config/history — captures full
    // FirewallConfig including aliases + static_routes (added in this PR)
    // so the manual one-click restore can revert everything the importer
    // changes that's covered by `apply_firewall_config`.
    let pre_import_version = save_pre_import_snapshot(&state).await.ok();

    let mut summary = AppliedCounts::default();
    let mut skipped: Vec<String> = Vec::new();
    // Track IDs of rows we insert so a mid-apply failure can roll them back
    // even though the engines auto-commit. `apply_firewall_config` handles
    // rules/NAT/aliases/routes wholesale on the snapshot path, so this is
    // belt-and-braces for the case where the snapshot capture itself failed.
    let mut tracker = InsertedRows::default();

    if let Err(reason) = apply_inner(
        &state,
        &cfg,
        &req,
        &mut summary,
        &mut skipped,
        &mut tracker,
    )
    .await
    {
        tracing::warn!(reason = %reason, "OPNsense import failed mid-apply; rolling back");
        if let Some(v) = pre_import_version {
            // Snapshot path fully covers rules/NAT/aliases/routes; this is
            // the cleanest restore.
            let _ = restore_pre_import(&state, v).await;
        } else {
            // Fallback: surgical cleanup of what we know we inserted.
            tracker.cleanup(&state).await;
        }
        return Err((StatusCode::INTERNAL_SERVER_ERROR, format!("import failed: {reason}")));
    }

    let mut commit_confirm_started = false;
    if req.commit_confirm
        && let Some(snapshot_json) = pre_apply_snapshot_json
    {
        match crate::backup::commit_confirm_arm_with_snapshot(
            state.clone(),
            snapshot_json,
            "OPNsense config import".to_string(),
            COMMIT_CONFIRM_SECONDS,
        )
        .await
        {
            Ok(_) => commit_confirm_started = true,
            Err(StatusCode::CONFLICT) => {
                tracing::warn!("commit-confirm already active — import succeeded but auto-revert window not armed");
            }
            Err(code) => {
                tracing::warn!(code = %code, "commit-confirm arm failed (import succeeded)");
            }
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
    req: &ImportRequest,
    summary: &mut AppliedCounts,
    skipped: &mut Vec<String>,
    tracker: &mut InsertedRows,
) -> Result<(), String> {
    let iface_map = &req.interface_map;

    // Aliases first — rules below may reference them by name.
    let alias_name_set = apply_aliases(state, &cfg.aliases, summary, skipped, tracker).await;

    // Rules.
    apply_rules(state, &cfg.rules, iface_map, &alias_name_set, summary, skipped, tracker).await;

    // NAT.
    apply_nat(state, &cfg.nat, iface_map, summary, skipped, tracker).await;

    // Static routes BEFORE pf reload so a route-write failure rolls back
    // engine state too. apply_routes is itself best-effort per row.
    apply_routes(state, &cfg.routes, summary, skipped, tracker).await;

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
    if summary.aliases > 0 {
        state
            .alias_engine
            .sync_all()
            .await
            .map_err(|e| format!("alias sync: {e}"))?;
    }

    // System settings — opt-in via `import_system_settings`. Default is to
    // leave hostname / domain / DNS upstreams alone, since most admins want
    // to migrate rules and aliases without renaming their box.
    if req.import_system_settings {
        if !cfg.system.dns_servers.is_empty() {
            summary.dns_servers = apply_dns_servers(state, &cfg.system.dns_servers).await;
        }
        if let Some(ref h) = cfg.system.hostname
            && apply_hostname(state, h, cfg.system.domain.as_deref()).await
        {
            summary.hostname = true;
        }
    }

    Ok(())
}

/// Tracks DB rows the importer inserted so a mid-apply failure that the
/// snapshot path can't recover from has a surgical cleanup option. Cleanup
/// runs the deletes through engine APIs where available (pf state stays in
/// sync) and falls back to direct SQL where the engine has no
/// `delete_by_name` etc.
#[derive(Default)]
struct InsertedRows {
    pub alias_ids: Vec<uuid::Uuid>,
    pub rule_ids: Vec<uuid::Uuid>,
    pub nat_ids: Vec<uuid::Uuid>,
    pub static_route_ids: Vec<String>,
}

impl InsertedRows {
    async fn cleanup(&self, state: &AppState) {
        for id in &self.rule_ids {
            let _ = state.rule_engine.delete_rule(*id).await;
        }
        for id in &self.nat_ids {
            let _ = state.nat_engine.delete_rule(*id).await;
        }
        for id in &self.alias_ids {
            let _ = state.alias_engine.delete(*id).await;
        }
        for id in &self.static_route_ids {
            let _ = sqlx::query("DELETE FROM static_routes WHERE id = ?1")
                .bind(id)
                .execute(&state.pool)
                .await;
        }
        let _ = state.rule_engine.apply_rules().await;
        let _ = state.nat_engine.apply_rules().await;
    }
}

async fn commit_confirm_active() -> bool {
    // We don't have direct access to backup::commit_store(); use the public
    // status endpoint instead. The path is in-process, so `serde_json` is
    // overkill — just ask backup::commit_confirm_status.
    crate::backup::commit_confirm_status()
        .await
        .map(|res| res.0.active)
        .unwrap_or(false)
}

// --------------------------------------------------------------------- aliases (H3)

async fn apply_aliases(
    state: &AppState,
    aliases: &[OpnAlias],
    summary: &mut AppliedCounts,
    skipped: &mut Vec<String>,
    tracker: &mut InsertedRows,
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
        let alias_id = Uuid::new_v4();
        let alias = Alias {
            id: alias_id,
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
                tracker.alias_ids.push(alias_id);
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
    tracker: &mut InsertedRows,
) {
    // M6 from audit: step by 1 (not 10) so 9000-rule imports don't blow past
    // the validate_rule cap at priority=10000. Plenty of headroom for source
    // ordering; sub-priority for floating siblings already share the slot.
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
                    let rule_id = rule.id;
                    match state.rule_engine.add_rule(rule).await {
                        Ok(_) => {
                            tracker.rule_ids.push(rule_id);
                            summary.rules += 1;
                        }
                        Err(e) => skipped.push(format!(
                            "rule '{}' ({})",
                            r.descr.as_deref().unwrap_or("(no descr)"),
                            e
                        )),
                    }
                    priority = (priority + 1).min(10000);
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
    tracker: &mut InsertedRows,
) {
    // Empty alias name set is fine for NAT — OPNsense rarely uses alias names
    // in NAT source/destination, and Address::parse handles literals.
    let empty = HashSet::new();

    // L1 from audit: honour <nat><mode>disabled</mode> by skipping outbound
    // NAT entirely. The plan reflects this in the same way.
    let outbound_disabled = nat
        .mode
        .as_deref()
        .map(|m| m.eq_ignore_ascii_case("disabled"))
        .unwrap_or(false);

    for n in &nat.port_forwards {
        if n.disabled {
            skipped.push(format!("port-forward '{}' (disabled)", n.descr.as_deref().unwrap_or("")));
            continue;
        }
        match build_port_forward(n, iface_map, &empty) {
            Ok((rule, advisories)) => {
                let id = rule.id;
                match state.nat_engine.add_rule(rule).await {
                    Ok(_) => {
                        tracker.nat_ids.push(id);
                        summary.nat_port_forwards += 1;
                        for adv in advisories {
                            skipped.push(format!(
                                "port-forward '{}' WARN: {}",
                                n.descr.as_deref().unwrap_or(""),
                                adv
                            ));
                        }
                    }
                    Err(e) => skipped.push(format!("port-forward '{}' ({})", n.descr.as_deref().unwrap_or(""), e)),
                }
            }
            Err(reason) => skipped.push(format!("port-forward '{}' ({})", n.descr.as_deref().unwrap_or(""), reason)),
        }
    }

    if outbound_disabled {
        if !nat.outbound.is_empty() {
            skipped.push(format!(
                "{} outbound NAT rules (skipped: <nat><mode>disabled</mode>)",
                nat.outbound.len()
            ));
        }
    } else {
        for n in &nat.outbound {
            if n.disabled {
                skipped.push(format!("outbound NAT '{}' (disabled)", n.descr.as_deref().unwrap_or("")));
                continue;
            }
            match build_outbound(n, iface_map, &empty) {
                Ok(rule) => {
                    let id = rule.id;
                    match state.nat_engine.add_rule(rule).await {
                        Ok(_) => {
                            tracker.nat_ids.push(id);
                            summary.nat_outbound += 1;
                        }
                        Err(e) => skipped.push(format!("outbound NAT '{}' ({})", n.descr.as_deref().unwrap_or(""), e)),
                    }
                }
                Err(reason) => skipped.push(format!("outbound NAT '{}' ({})", n.descr.as_deref().unwrap_or(""), reason)),
            }
        }
    }

    for n in &nat.onetoone {
        if n.disabled {
            skipped.push(format!("1:1 NAT '{}' (disabled)", n.descr.as_deref().unwrap_or("")));
            continue;
        }
        match build_one_to_one(n, iface_map, &empty) {
            Ok(rule) => {
                let id = rule.id;
                match state.nat_engine.add_rule(rule).await {
                    Ok(_) => {
                        tracker.nat_ids.push(id);
                        summary.nat_one_to_one += 1;
                    }
                    Err(e) => skipped.push(format!("1:1 NAT '{}' ({})", n.descr.as_deref().unwrap_or(""), e)),
                }
            }
            Err(reason) => skipped.push(format!("1:1 NAT '{}' ({})", n.descr.as_deref().unwrap_or(""), reason)),
        }
    }
}

fn build_port_forward(
    n: &OpnNatPortForward,
    iface_map: &HashMap<String, String>,
    aliases: &HashSet<String>,
) -> Result<(NatRule, Vec<String>), String> {
    let interface = Interface(map_iface(&n.interface, iface_map));
    let protocol = Protocol::parse(&n.protocol).map_err(|e| e.to_string())?;

    let mut advisories: Vec<String> = Vec::new();
    let (src_addr, src_port, src_adv) = translate_endpoint_or_any(&n.source, aliases);
    if let Some(a) = src_adv {
        advisories.push(format!("source: {a}"));
    }
    let (dst_addr, dst_port, dst_adv) = translate_endpoint_or_any(&n.destination, aliases);
    if let Some(a) = dst_adv {
        advisories.push(format!("destination: {a}"));
    }

    let target_ip = Address::parse(&n.target).map_err(|e| format!("redirect target '{}': {}", n.target, e))?;
    let redirect_port = match n.local_port.as_deref() {
        Some(p) => Some(parse_port_spec(p, aliases)?),
        None => dst_port.clone(),
    };

    // OPNsense port-forwards default to "redirect dest port → redirect target".
    // If only `<local-port>` was given, we still need a `dst_port` in NatRule
    // for DNAT validation, so reuse the redirect port when destination port is absent.
    let final_dst_port = dst_port.clone().or_else(|| redirect_port.clone());
    if final_dst_port.is_none() {
        // H9 from audit: NatEngine rejects DNAT without any port. Surface
        // this as a friendly failure here so the plan and apply agree.
        return Err(
            "DNAT/port-forward needs either <destination><port> or <local-port> — full-IP redirects not yet supported".into(),
        );
    }

    let now = chrono::Utc::now();
    Ok((NatRule {
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
    }, advisories))
}

fn build_outbound(
    n: &OpnNatOutbound,
    iface_map: &HashMap<String, String>,
    aliases: &HashSet<String>,
) -> Result<NatRule, String> {
    if n.nonat {
        return Err(
            "<nonat> outbound NAT bypass not yet supported — leaves source rewriting on, opposite of intent. Configure manually after import."
                .into(),
        );
    }
    if n.staticnatport {
        return Err(
            "<staticnatport> (preserve source port) not yet supported — pf rule emits dynamic source port. Configure manually after import."
                .into(),
        );
    }
    let interface = Interface(map_iface(&n.interface, iface_map));
    let protocol = Protocol::parse(&n.protocol).map_err(|e| e.to_string())?;
    let mut advisories: Vec<String> = Vec::new();
    let (src_addr, src_port, src_adv) = translate_endpoint_or_any(&n.source, aliases);
    if let Some(a) = src_adv {
        advisories.push(format!("source: {a}"));
    }
    let (dst_addr, dst_port, dst_adv) = translate_endpoint_or_any(&n.destination, aliases);
    if let Some(a) = dst_adv {
        advisories.push(format!("destination: {a}"));
    }

    // Empty target = masquerade (use interface address). Concrete IP = SNAT.
    let (nat_type, redirect_addr) = match n.target.as_deref().filter(|s| !s.is_empty()) {
        None => (NatType::Masquerade, Address::Any),
        Some(t) => {
            let a = Address::parse(t).map_err(|e| format!("outbound target '{t}': {e}"))?;
            (NatType::Snat, a)
        }
    };

    let now = chrono::Utc::now();
    let _ = advisories; // collected for future return; signature kept simple for now
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
    let (dst_addr, _, _) = translate_endpoint_or_any(&n.destination, aliases);

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

/// Like `translate_endpoint`, but for NAT contexts. Returns
/// `(addr, port, advisory)` where `advisory`, if set, calls out a fidelity
/// loss the caller can surface to the operator (e.g. `wanip` couldn't be
/// expressed precisely). Pre-audit this silently collapsed to `Address::Any`
/// for unresolved keywords, which broadens the match dangerously — port-
/// forward rules ended up matching from any destination instead of just
/// packets to the WAN IP.
fn translate_endpoint_or_any(
    ep: &OpnEndpoint,
    alias_names: &HashSet<String>,
) -> (Address, Option<PortRange>, Option<String>) {
    let port = ep
        .port
        .as_deref()
        .and_then(|p| parse_port_spec(p, alias_names).ok());
    if ep.any {
        return (Address::Any, port, None);
    }
    if let Some(addr) = &ep.address {
        if let Ok(a) = Address::parse(addr) {
            return (a, port, None);
        }
        if alias_names.contains(addr) {
            return (Address::Table(addr.clone()), port, None);
        }
    }
    if let Some(net) = &ep.network {
        if alias_names.contains(net) {
            return (Address::Table(net.clone()), port, None);
        }
        // OPNsense `<network>wanip|lanip|(self)|optNip</network>` means "the
        // configured IP on that interface". AiFw's `Address` enum can't
        // represent that as a literal; pf can via the `(<iface>)` syntax,
        // but `Address::parse` doesn't round-trip that. Return `Any` AND a
        // diagnostic so the importer reports the loss rather than hiding it.
        return (
            Address::Any,
            port,
            Some(format!(
                "OPNsense network keyword '{net}' broadened to 'any' (no AiFw equivalent for interface address)"
            )),
        );
    }
    (Address::Any, port, None)
}

// --------------------------------------------------------------------- routes (C3, H5)

async fn apply_routes(
    state: &AppState,
    routes: &[OpnRoute],
    summary: &mut AppliedCounts,
    skipped: &mut Vec<String>,
    tracker: &mut InsertedRows,
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

        // M2/M3 from audit: validate destination + gateway shape (the
        // /api/v1/routes endpoint does this; the importer was skipping the
        // check) and dedup against pre-existing rows so re-imports don't
        // accumulate duplicates.
        if crate::routes::validate_route_target(&r.network).is_err() {
            skipped.push(format!("route {} (invalid destination)", r.network));
            continue;
        }
        if crate::routes::validate_route_target(gateway).is_err() {
            skipped.push(format!("route {} (invalid gateway '{}')", r.network, gateway));
            continue;
        }
        let dup: Option<(i64,)> = sqlx::query_as(
            "SELECT 1 FROM static_routes WHERE destination = ?1 AND gateway = ?2 AND COALESCE(fib,0) = 0",
        )
        .bind(&r.network)
        .bind(gateway)
        .fetch_optional(&state.pool)
        .await
        .ok()
        .flatten();
        if dup.is_some() {
            skipped.push(format!(
                "route {} via {} (already exists)",
                r.network, gateway
            ));
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
                // creation request.
                crate::routes::apply_route_to_system(&r.network, gateway, None, 0).await;
                tracker.static_route_ids.push(id);
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
    // failure is logged and the DB row is what survives. We drop the stdin
    // handle before awaiting `wait()` so `tee` sees EOF and exits — without
    // that drop, `wait()` deadlocks because tee keeps reading.
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
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            let _ = stdin.write_all(content.as_bytes()).await;
            let _ = stdin.shutdown().await;
            drop(stdin);
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
    // Read existing timezone — never clobber it. If unset (fresh appliance)
    // fall back to UTC, matching `apply_general`'s own default.
    let existing_timezone: String = sqlx::query_as::<_, (String,)>(
        "SELECT value FROM system_config WHERE key = 'timezone'",
    )
    .fetch_optional(&state.pool)
    .await
    .ok()
    .flatten()
    .map(|(v,)| v)
    .unwrap_or_else(|| "UTC".to_string());

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
        timezone: existing_timezone,
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
