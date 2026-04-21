use aifw_common::{
    AifwError, Gateway, GatewayGroup, GatewayState, GroupMember, GroupPolicy, PolicyRule, Result,
    RoutingInstance, StickyMode,
};
use aifw_pf::PfBackend;
use chrono::Utc;
use sqlx::Row;
use sqlx::sqlite::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

use super::group::{Selection, select};

pub const PBR_ANCHOR: &str = "aifw-pbr";
pub const REPLY_ANCHOR: &str = "aifw-mwan-reply";

pub struct PolicyEngine {
    pool: SqlitePool,
    pf: Arc<dyn PfBackend>,
}

impl PolicyEngine {
    pub fn new(pool: SqlitePool, pf: Arc<dyn PfBackend>) -> Self {
        Self { pool, pf }
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS multiwan_policies (
                id TEXT PRIMARY KEY,
                priority INTEGER NOT NULL,
                name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                ip_version TEXT NOT NULL DEFAULT 'both',
                iface_in TEXT,
                src_addr TEXT NOT NULL DEFAULT 'any',
                dst_addr TEXT NOT NULL DEFAULT 'any',
                src_port TEXT,
                dst_port TEXT,
                protocol TEXT NOT NULL DEFAULT 'any',
                dscp_in INTEGER,
                geoip_country TEXT,
                schedule_id TEXT,
                action_kind TEXT NOT NULL,
                target_id TEXT NOT NULL,
                sticky TEXT NOT NULL DEFAULT 'none',
                fallback_target_id TEXT,
                description TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_mwan_policy_prio ON multiwan_policies(priority)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;
        Ok(())
    }

    pub async fn list(&self) -> Result<Vec<PolicyRule>> {
        let rows = sqlx::query("SELECT * FROM multiwan_policies ORDER BY priority ASC")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AifwError::Database(e.to_string()))?;
        Ok(rows.iter().map(row_to_policy).collect())
    }

    pub async fn get(&self, id: Uuid) -> Result<PolicyRule> {
        let row = sqlx::query("SELECT * FROM multiwan_policies WHERE id = ?1")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AifwError::Database(e.to_string()))?
            .ok_or_else(|| AifwError::NotFound(format!("policy {id} not found")))?;
        Ok(row_to_policy(&row))
    }

    pub async fn add(&self, p: PolicyRule) -> Result<PolicyRule> {
        sqlx::query(
            r#"INSERT INTO multiwan_policies
            (id, priority, name, status, ip_version, iface_in, src_addr, dst_addr,
             src_port, dst_port, protocol, dscp_in, geoip_country, schedule_id,
             action_kind, target_id, sticky, fallback_target_id, description,
             created_at, updated_at)
            VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)"#,
        )
        .bind(p.id.to_string())
        .bind(p.priority)
        .bind(&p.name)
        .bind(&p.status)
        .bind(&p.ip_version)
        .bind(p.iface_in.as_deref())
        .bind(&p.src_addr)
        .bind(&p.dst_addr)
        .bind(p.src_port.as_deref())
        .bind(p.dst_port.as_deref())
        .bind(&p.protocol)
        .bind(p.dscp_in.map(|v| v as i64))
        .bind(p.geoip_country.as_deref())
        .bind(p.schedule_id.as_deref())
        .bind(&p.action_kind)
        .bind(p.target_id.to_string())
        .bind(p.sticky.as_str())
        .bind(p.fallback_target_id.map(|u| u.to_string()))
        .bind(p.description.as_deref())
        .bind(p.created_at.to_rfc3339())
        .bind(p.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;
        Ok(p)
    }

    pub async fn update(&self, p: PolicyRule) -> Result<PolicyRule> {
        let now = Utc::now();
        let res = sqlx::query(
            r#"UPDATE multiwan_policies SET
                priority=?2, name=?3, status=?4, ip_version=?5, iface_in=?6,
                src_addr=?7, dst_addr=?8, src_port=?9, dst_port=?10, protocol=?11,
                dscp_in=?12, geoip_country=?13, schedule_id=?14,
                action_kind=?15, target_id=?16, sticky=?17, fallback_target_id=?18,
                description=?19, updated_at=?20
             WHERE id=?1"#,
        )
        .bind(p.id.to_string())
        .bind(p.priority)
        .bind(&p.name)
        .bind(&p.status)
        .bind(&p.ip_version)
        .bind(p.iface_in.as_deref())
        .bind(&p.src_addr)
        .bind(&p.dst_addr)
        .bind(p.src_port.as_deref())
        .bind(p.dst_port.as_deref())
        .bind(&p.protocol)
        .bind(p.dscp_in.map(|v| v as i64))
        .bind(p.geoip_country.as_deref())
        .bind(p.schedule_id.as_deref())
        .bind(&p.action_kind)
        .bind(p.target_id.to_string())
        .bind(p.sticky.as_str())
        .bind(p.fallback_target_id.map(|u| u.to_string()))
        .bind(p.description.as_deref())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;
        if res.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("policy {} not found", p.id)));
        }
        let mut updated = p;
        updated.updated_at = now;
        Ok(updated)
    }

    pub async fn delete(&self, id: Uuid) -> Result<()> {
        let res = sqlx::query("DELETE FROM multiwan_policies WHERE id=?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AifwError::Database(e.to_string()))?;
        if res.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("policy {id} not found")));
        }
        Ok(())
    }

    /// Compile active policies into pf rule strings. Pure function — no I/O.
    pub fn compile(
        policies: &[PolicyRule],
        instances: &[RoutingInstance],
        gateways: &[Gateway],
        groups: &[GatewayGroup],
        group_members: &HashMap<Uuid, Vec<GroupMember>>,
    ) -> CompiledPolicies {
        let mut pbr = Vec::new();
        let mut reply = Vec::new();

        let inst_by_id: HashMap<Uuid, &RoutingInstance> =
            instances.iter().map(|i| (i.id, i)).collect();
        let gw_by_id: HashMap<Uuid, &Gateway> = gateways.iter().map(|g| (g.id, g)).collect();
        let grp_by_id: HashMap<Uuid, &GatewayGroup> = groups.iter().map(|g| (g.id, g)).collect();

        for p in policies.iter().filter(|p| p.status == "active") {
            let label = format!("pbr:{}", p.id);
            match p.action_kind.as_str() {
                "set_instance" => {
                    if let Some(inst) = inst_by_id.get(&p.target_id)
                        && let Some(line) = emit_set_instance(p, inst, &label)
                    {
                        pbr.push(line);
                    }
                }
                "set_gateway" => {
                    if let Some(gw) = gw_by_id.get(&p.target_id) {
                        let (out, rep) = emit_set_gateway(p, gw, &label);
                        pbr.push(out);
                        reply.push(rep);
                    }
                }
                "set_group" => {
                    if let Some(group) = grp_by_id.get(&p.target_id) {
                        let empty = Vec::new();
                        let members = group_members.get(&group.id).unwrap_or(&empty);
                        let sel = select(group, members, gateways);
                        if let Some((out, rep)) = emit_set_group(p, group, sel, &gw_by_id, &label) {
                            pbr.push(out);
                            reply.push(rep);
                        }
                    }
                }
                _ => {}
            }
        }
        CompiledPolicies { pbr, reply }
    }

    /// Recompile and load pf rules for all anchors.
    pub async fn apply(
        &self,
        instances: &[RoutingInstance],
        gateways: &[Gateway],
        groups: &[GatewayGroup],
        group_members: &HashMap<Uuid, Vec<GroupMember>>,
    ) -> Result<()> {
        let policies = self.list().await?;
        let compiled = Self::compile(&policies, instances, gateways, groups, group_members);
        self.pf
            .load_rules(PBR_ANCHOR, &compiled.pbr)
            .await
            .map_err(|e| AifwError::Pf(e.to_string()))?;
        self.pf
            .load_rules(REPLY_ANCHOR, &compiled.reply)
            .await
            .map_err(|e| AifwError::Pf(e.to_string()))?;
        tracing::info!(
            anchor = PBR_ANCHOR,
            rules = compiled.pbr.len(),
            "pbr anchor loaded"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct CompiledPolicies {
    pub pbr: Vec<String>,
    pub reply: Vec<String>,
}

fn emit_set_instance(p: &PolicyRule, inst: &RoutingInstance, label: &str) -> Option<String> {
    let iface_in = p.iface_in.as_deref()?;
    let mut rule = format!("pass in quick on {iface_in}");
    if_some_af(&p.ip_version, &mut rule);
    if_some_proto(&p.protocol, &mut rule);
    rule.push_str(&format!(" from {} to {}", p.src_addr, p.dst_addr));
    if let Some(sp) = &p.src_port {
        rule.push_str(&format!(" port {sp}"));
    }
    if let Some(dp) = &p.dst_port {
        rule.push_str(&format!(" port {dp}"));
    }
    rule.push_str(&format!(
        " rtable {} keep state (if-bound) label \"{label}\"",
        inst.fib_number
    ));
    Some(rule)
}

fn emit_set_gateway(p: &PolicyRule, gw: &Gateway, label: &str) -> (String, String) {
    let mut out = format!("pass out quick on {}", gw.interface);
    if_some_af(&p.ip_version, &mut out);
    if_some_proto(&p.protocol, &mut out);
    out.push_str(&format!(" from {} to {}", p.src_addr, p.dst_addr));
    if let Some(sp) = &p.src_port {
        out.push_str(&format!(" port {sp}"));
    }
    if let Some(dp) = &p.dst_port {
        out.push_str(&format!(" port {dp}"));
    }
    out.push_str(&format!(
        " route-to ({} {}) keep state (if-bound) label \"{label}\"",
        gw.interface, gw.next_hop
    ));

    let mut reply = "pass in quick".to_string();
    if let Some(iface_in) = &p.iface_in {
        reply.push_str(&format!(" on {iface_in}"));
    }
    if_some_af(&p.ip_version, &mut reply);
    if_some_proto(&p.protocol, &mut reply);
    reply.push_str(&format!(" from {} to {}", p.src_addr, p.dst_addr));
    if let Some(sp) = &p.src_port {
        reply.push_str(&format!(" port {sp}"));
    }
    if let Some(dp) = &p.dst_port {
        reply.push_str(&format!(" port {dp}"));
    }
    reply.push_str(&format!(
        " reply-to ({} {}) keep state (if-bound) label \"{label}:rep\"",
        gw.interface, gw.next_hop
    ));
    (out, reply)
}

fn emit_set_group(
    p: &PolicyRule,
    group: &GatewayGroup,
    sel: Selection,
    gw_by_id: &HashMap<Uuid, &Gateway>,
    label: &str,
) -> Option<(String, String)> {
    match sel {
        Selection::None => None,
        Selection::Single(id) => {
            let gw = gw_by_id.get(&id)?;
            Some(emit_set_gateway(p, gw, label))
        }
        Selection::WeightedList(list) if list.is_empty() => None,
        Selection::WeightedList(list) => {
            let primary_iface = gw_by_id.get(&list[0].0)?.interface.clone();
            let targets: Vec<String> = list
                .iter()
                .filter_map(|(id, w)| {
                    let gw = gw_by_id.get(id)?;
                    Some(format!("({} {}) weight {}", gw.interface, gw.next_hop, w))
                })
                .collect();
            if targets.is_empty() {
                return None;
            }
            let mut out = format!("pass out quick on {primary_iface}");
            if_some_af(&p.ip_version, &mut out);
            if_some_proto(&p.protocol, &mut out);
            out.push_str(&format!(" from {} to {}", p.src_addr, p.dst_addr));
            out.push_str(" route-to { ");
            out.push_str(&targets.join(", "));
            out.push_str(" } round-robin");
            if group.sticky == StickyMode::Src {
                out.push_str(" sticky-address");
            }
            out.push_str(&format!(" keep state (if-bound) label \"{label}:grp\""));

            // Reply: use first healthy gw as return path
            let first = gw_by_id.get(&list[0].0)?;
            let mut reply = "pass in quick".to_string();
            if let Some(iface_in) = &p.iface_in {
                reply.push_str(&format!(" on {iface_in}"));
            }
            if_some_af(&p.ip_version, &mut reply);
            if_some_proto(&p.protocol, &mut reply);
            reply.push_str(&format!(" from {} to {}", p.src_addr, p.dst_addr));
            reply.push_str(&format!(
                " reply-to ({} {}) keep state (if-bound) label \"{label}:grp:rep\"",
                first.interface, first.next_hop
            ));
            let _ = group; // kept for future preempt/hysteresis fields
            let _ = GroupPolicy::Failover; // reference all variants
            let _ = GatewayState::Up;
            Some((out, reply))
        }
    }
}

fn if_some_af(v: &str, out: &mut String) {
    match v {
        "v4" => out.push_str(" inet"),
        "v6" => out.push_str(" inet6"),
        _ => {}
    }
}

fn if_some_proto(p: &str, out: &mut String) {
    if p != "any" && !p.is_empty() {
        out.push_str(&format!(" proto {p}"));
    }
}

fn row_to_policy(r: &sqlx::sqlite::SqliteRow) -> PolicyRule {
    PolicyRule {
        id: r.get::<String, _>("id").parse().unwrap_or_default(),
        priority: r.get("priority"),
        name: r.get("name"),
        status: r.get("status"),
        ip_version: r.get("ip_version"),
        iface_in: r.get("iface_in"),
        src_addr: r.get("src_addr"),
        dst_addr: r.get("dst_addr"),
        src_port: r.get("src_port"),
        dst_port: r.get("dst_port"),
        protocol: r.get("protocol"),
        dscp_in: r.get::<Option<i64>, _>("dscp_in").map(|v| v as u8),
        geoip_country: r.get("geoip_country"),
        schedule_id: r.get("schedule_id"),
        action_kind: r.get("action_kind"),
        target_id: r.get::<String, _>("target_id").parse().unwrap_or_default(),
        sticky: StickyMode::parse(&r.get::<String, _>("sticky")).unwrap_or(StickyMode::None),
        fallback_target_id: r
            .get::<Option<String>, _>("fallback_target_id")
            .and_then(|s| s.parse().ok()),
        description: r.get("description"),
        created_at: r.get::<String, _>("created_at").parse().unwrap_or_default(),
        updated_at: r.get::<String, _>("updated_at").parse().unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aifw_common::{InstanceStatus, RoutingInstance};

    fn make_inst(fib: u32) -> RoutingInstance {
        RoutingInstance {
            id: Uuid::new_v4(),
            name: format!("wan{fib}"),
            fib_number: fib,
            description: None,
            mgmt_reachable: false,
            status: InstanceStatus::Active,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_policy(action: &str, target: Uuid) -> PolicyRule {
        PolicyRule {
            id: Uuid::new_v4(),
            priority: 100,
            name: "p".into(),
            status: "active".into(),
            ip_version: "v4".into(),
            iface_in: Some("em_lan".into()),
            src_addr: "10.0.0.0/24".into(),
            dst_addr: "any".into(),
            src_port: None,
            dst_port: Some("443".into()),
            protocol: "tcp".into(),
            dscp_in: None,
            geoip_country: None,
            schedule_id: None,
            action_kind: action.into(),
            target_id: target,
            sticky: StickyMode::None,
            fallback_target_id: None,
            description: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_gw(id: Uuid, iface: &str, nh: &str) -> Gateway {
        Gateway {
            id,
            name: iface.into(),
            instance_id: Uuid::new_v4(),
            interface: iface.into(),
            next_hop: nh.into(),
            ip_version: "v4".into(),
            monitor_kind: "icmp".into(),
            monitor_target: None,
            monitor_port: None,
            monitor_expect: None,
            interval_ms: 500,
            timeout_ms: 1000,
            loss_pct_down: 20.0,
            loss_pct_up: 5.0,
            latency_ms_down: None,
            latency_ms_up: None,
            consec_fail_down: 3,
            consec_ok_up: 5,
            weight: 1,
            dampening_secs: 10,
            dscp_tag: None,
            enabled: true,
            state: GatewayState::Up,
            last_rtt_ms: None,
            last_jitter_ms: None,
            last_loss_pct: None,
            last_mos: None,
            last_probe_ts: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn compile_set_instance_emits_rtable() {
        let inst = make_inst(2);
        let p = make_policy("set_instance", inst.id);
        let c = PolicyEngine::compile(&[p], &[inst], &[], &[], &HashMap::new());
        assert_eq!(c.pbr.len(), 1);
        assert!(c.pbr[0].contains("rtable 2"));
        assert!(c.pbr[0].contains("if-bound"));
        assert_eq!(c.reply.len(), 0);
    }

    #[test]
    fn compile_set_gateway_emits_route_and_reply() {
        let gw = make_gw(Uuid::new_v4(), "em1", "203.0.113.1");
        let p = make_policy("set_gateway", gw.id);
        let c = PolicyEngine::compile(&[p], &[], &[gw.clone()], &[], &HashMap::new());
        assert_eq!(c.pbr.len(), 1);
        assert_eq!(c.reply.len(), 1);
        assert!(c.pbr[0].contains("route-to (em1 203.0.113.1)"));
        assert!(c.pbr[0].contains("if-bound"));
        assert!(c.reply[0].contains("reply-to (em1 203.0.113.1)"));
        assert!(c.reply[0].contains("if-bound"));
    }

    #[test]
    fn disabled_policies_skipped() {
        let inst = make_inst(2);
        let mut p = make_policy("set_instance", inst.id);
        p.status = "disabled".into();
        let c = PolicyEngine::compile(&[p], &[inst], &[], &[], &HashMap::new());
        assert_eq!(c.pbr.len(), 0);
    }
}
