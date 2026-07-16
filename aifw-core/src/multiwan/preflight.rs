//! Pre-flight / blast-radius analysis for multi-WAN config changes.
//!
//! Consumes a proposed set of policies/gateways/instances and an observed pf
//! state table, produces a BlastRadiusReport describing which existing flows
//! would be rerouted, whether management traffic would be stranded, and a diff
//! of generated pf rules.

use aifw_common::{
    Gateway, GatewayGroup, GroupMember, PolicyRule, PolicyStatus, Result, RouteAction,
    RoutingInstance,
};
use aifw_pf::{PfBackend, PfState};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use super::policy::PolicyEngine;

/// An existing pf state (live connection) that a proposed change may reroute
#[derive(Debug, Clone, Serialize)]
pub struct AffectedFlow {
    /// Source endpoint as "addr:port"
    pub src: String,
    /// Destination endpoint as "addr:port"
    pub dst: String,
    /// Protocol of the flow (e.g. tcp, udp)
    pub protocol: String,
    /// Interface the flow currently uses, if known
    pub current_iface: Option<String>,
    /// Interface the flow would use after the change (currently not predicted)
    pub future_iface: Option<String>,
    /// Total bytes transferred so far (in + out)
    pub bytes: u64,
}

/// One safety finding from validating a proposed policy set
#[derive(Debug, Clone, Serialize)]
pub struct ValidationFinding {
    /// info | warning | error
    pub severity: String, // info | warning | error
    /// Human-readable description of the finding
    pub message: String,
}

/// Result of a pre-flight analysis: what a proposed multi-WAN change would do
#[derive(Debug, Clone, Serialize)]
pub struct BlastRadiusReport {
    /// Live flows that may be rerouted by the change (capped at 50)
    pub affected_flows: Vec<AffectedFlow>,
    /// True if the change would move management traffic off the mgmt FIB
    pub would_strand_mgmt: bool,
    /// pf rules the proposed config adds relative to the current one
    pub new_rules: Vec<String>,
    /// pf rules the proposed config removes relative to the current one
    pub removed_rules: Vec<String>,
    /// Safety findings (mgmt-strand errors, missing-mgmt warnings, etc.)
    pub validation: Vec<ValidationFinding>,
}

/// Pre-flight engine: dry-runs a proposed policy set against the current one
/// and the live pf state table without touching pf
pub struct PreflightEngine {
    pf: Arc<dyn PfBackend>,
}

impl PreflightEngine {
    /// Create the engine over a pf backend (used only to read the state table)
    pub fn new(pf: Arc<dyn PfBackend>) -> Self {
        Self { pf }
    }

    /// Compile the current and proposed policy sets, diff the resulting pf
    /// rules, sample live pf states that may be rerouted, and run mgmt-safety
    /// validation. Read-only — never modifies pf
    pub async fn preview(
        &self,
        current_policies: &[PolicyRule],
        proposed_policies: &[PolicyRule],
        instances: &[RoutingInstance],
        gateways: &[Gateway],
        groups: &[GatewayGroup],
        group_members: &HashMap<Uuid, Vec<GroupMember>>,
    ) -> Result<BlastRadiusReport> {
        let current =
            PolicyEngine::compile(current_policies, instances, gateways, groups, group_members);
        let proposed = PolicyEngine::compile(
            proposed_policies,
            instances,
            gateways,
            groups,
            group_members,
        );

        let current_set: std::collections::HashSet<&String> = current.pbr.iter().collect();
        let proposed_set: std::collections::HashSet<&String> = proposed.pbr.iter().collect();

        let new_rules: Vec<String> = proposed
            .pbr
            .iter()
            .filter(|r| !current_set.contains(r))
            .cloned()
            .collect();
        let removed_rules: Vec<String> = current
            .pbr
            .iter()
            .filter(|r| !proposed_set.contains(r))
            .cloned()
            .collect();

        let states = self.pf.get_states().await.unwrap_or_default();
        let affected_flows = derive_affected_flows(&states, &new_rules);

        let mut validation = Vec::new();
        let would_strand_mgmt = validate_mgmt_safety(proposed_policies, instances, &mut validation);

        Ok(BlastRadiusReport {
            affected_flows,
            would_strand_mgmt,
            new_rules,
            removed_rules,
            validation,
        })
    }
}

fn derive_affected_flows(states: &[PfState], new_rules: &[String]) -> Vec<AffectedFlow> {
    // Heuristic: any state whose iface doesn't appear in any new rule but
    // whose src/dst might match a new rule is potentially affected. We keep
    // this simple for now and report all states if any new rules exist.
    if new_rules.is_empty() {
        return Vec::new();
    }
    states
        .iter()
        .take(50)
        .map(|s| AffectedFlow {
            src: format!("{}:{}", s.src_addr, s.src_port),
            dst: format!("{}:{}", s.dst_addr, s.dst_port),
            protocol: s.protocol.clone(),
            current_iface: s.iface.clone(),
            future_iface: None,
            bytes: s.bytes_in + s.bytes_out,
        })
        .collect()
}

fn validate_mgmt_safety(
    proposed: &[PolicyRule],
    instances: &[RoutingInstance],
    findings: &mut Vec<ValidationFinding>,
) -> bool {
    let mgmt_instance = instances.iter().find(|i| i.mgmt_reachable);
    let Some(mgmt) = mgmt_instance else {
        findings.push(ValidationFinding {
            severity: "warning".into(),
            message: "No management-reachable instance defined".into(),
        });
        return false;
    };

    // A policy that targets a non-mgmt instance with src_addr='any' or 'any/0'
    // could move management traffic. Flag it.
    let mut strand = false;
    for p in proposed.iter().filter(|p| p.status == PolicyStatus::Active) {
        if p.action_kind == RouteAction::SetInstance
            && p.target_id != mgmt.id
            && (p.src_addr == "any" || p.src_addr == "0.0.0.0/0")
        {
            findings.push(ValidationFinding {
                severity: "error".into(),
                message: format!(
                    "Policy '{}' with src=any moves ALL traffic away from mgmt FIB",
                    p.name
                ),
            });
            strand = true;
        }
    }
    strand
}

#[cfg(test)]
mod tests {
    use super::*;
    use aifw_common::{InstanceStatus, MwIpVersion, MwProtocol, StickyMode};
    use chrono::Utc;
    use uuid::Uuid;

    fn make_inst(fib: u32, mgmt: bool) -> RoutingInstance {
        RoutingInstance {
            id: Uuid::new_v4(),
            name: format!("wan{fib}"),
            fib_number: fib,
            description: None,
            mgmt_reachable: mgmt,
            status: InstanceStatus::Active,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_policy(target: Uuid, src: &str, status: PolicyStatus) -> PolicyRule {
        PolicyRule {
            id: Uuid::new_v4(),
            priority: 100,
            name: "p".into(),
            status,
            ip_version: MwIpVersion::V4,
            iface_in: Some("em_lan".into()),
            src_addr: src.into(),
            dst_addr: "any".into(),
            src_port: None,
            dst_port: None,
            protocol: MwProtocol::Any,
            dscp_in: None,
            geoip_country: None,
            schedule_id: None,
            action_kind: RouteAction::SetInstance,
            target_id: target,
            sticky: StickyMode::None,
            fallback_target_id: None,
            description: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn policy_moving_any_to_non_mgmt_flags_strand() {
        let mgmt = make_inst(0, true);
        let wan2 = make_inst(1, false);
        let p = make_policy(wan2.id, "any", PolicyStatus::Active);
        let mut findings = Vec::new();
        let strand = validate_mgmt_safety(&[p], &[mgmt, wan2], &mut findings);
        assert!(strand);
        assert!(findings.iter().any(|f| f.severity == "error"));
    }

    #[test]
    fn specific_subnet_does_not_strand() {
        let mgmt = make_inst(0, true);
        let wan2 = make_inst(1, false);
        let p = make_policy(wan2.id, "10.0.0.0/24", PolicyStatus::Active);
        let mut findings = Vec::new();
        let strand = validate_mgmt_safety(&[p], &[mgmt, wan2], &mut findings);
        assert!(!strand);
    }

    #[test]
    fn disabled_policy_does_not_strand() {
        let mgmt = make_inst(0, true);
        let wan2 = make_inst(1, false);
        let p = make_policy(wan2.id, "any", PolicyStatus::Disabled);
        let mut findings = Vec::new();
        let strand = validate_mgmt_safety(&[p], &[mgmt, wan2], &mut findings);
        assert!(!strand);
    }

    #[test]
    fn no_mgmt_instance_reports_warning() {
        let wan1 = make_inst(1, false);
        let wan2 = make_inst(2, false);
        let mut findings = Vec::new();
        validate_mgmt_safety(&[], &[wan1, wan2], &mut findings);
        assert!(findings.iter().any(|f| f.severity == "warning"));
    }
}
