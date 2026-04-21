use aifw_common::{
    AifwError, Gateway, GatewayGroup, GatewayState, GroupMember, GroupPolicy, Result, StickyMode,
};
use chrono::Utc;
use sqlx::Row;
use sqlx::sqlite::SqlitePool;
use uuid::Uuid;

/// Selection produced by a group given a live set of gateway states.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// A single gateway ID to pin a flow to (failover/adaptive).
    Single(Uuid),
    /// Multiple gateway IDs with weights (LB/weighted).
    WeightedList(Vec<(Uuid, u32)>),
    /// No member is healthy.
    None,
}

pub struct GroupEngine {
    pool: SqlitePool,
}

impl GroupEngine {
    pub fn new(pool: SqlitePool) -> Self {
        Self { pool }
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS multiwan_groups (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                policy TEXT NOT NULL,
                preempt INTEGER NOT NULL DEFAULT 1,
                sticky TEXT NOT NULL DEFAULT 'none',
                hysteresis_ms INTEGER NOT NULL DEFAULT 2000,
                kill_states_on_failover INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS multiwan_group_members (
                group_id TEXT NOT NULL,
                gateway_id TEXT NOT NULL,
                tier INTEGER NOT NULL DEFAULT 1,
                weight INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (group_id, gateway_id),
                FOREIGN KEY (group_id) REFERENCES multiwan_groups(id) ON DELETE CASCADE,
                FOREIGN KEY (gateway_id) REFERENCES multiwan_gateways(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;
        Ok(())
    }

    pub async fn list(&self) -> Result<Vec<GatewayGroup>> {
        let rows = sqlx::query("SELECT * FROM multiwan_groups ORDER BY name ASC")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AifwError::Database(e.to_string()))?;
        Ok(rows.iter().map(row_to_group).collect())
    }

    pub async fn get(&self, id: Uuid) -> Result<GatewayGroup> {
        let row = sqlx::query("SELECT * FROM multiwan_groups WHERE id = ?1")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AifwError::Database(e.to_string()))?
            .ok_or_else(|| AifwError::NotFound(format!("group {id} not found")))?;
        Ok(row_to_group(&row))
    }

    pub async fn add(&self, g: GatewayGroup) -> Result<GatewayGroup> {
        sqlx::query(
            r#"INSERT INTO multiwan_groups
            (id, name, policy, preempt, sticky, hysteresis_ms, kill_states_on_failover,
             created_at, updated_at)
            VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)"#,
        )
        .bind(g.id.to_string())
        .bind(&g.name)
        .bind(g.policy.as_str())
        .bind(g.preempt as i64)
        .bind(g.sticky.as_str())
        .bind(g.hysteresis_ms as i64)
        .bind(g.kill_states_on_failover as i64)
        .bind(g.created_at.to_rfc3339())
        .bind(g.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;
        Ok(g)
    }

    pub async fn update(&self, g: GatewayGroup) -> Result<GatewayGroup> {
        let now = Utc::now();
        let res = sqlx::query(
            r#"UPDATE multiwan_groups SET
                name=?2, policy=?3, preempt=?4, sticky=?5, hysteresis_ms=?6,
                kill_states_on_failover=?7, updated_at=?8
             WHERE id=?1"#,
        )
        .bind(g.id.to_string())
        .bind(&g.name)
        .bind(g.policy.as_str())
        .bind(g.preempt as i64)
        .bind(g.sticky.as_str())
        .bind(g.hysteresis_ms as i64)
        .bind(g.kill_states_on_failover as i64)
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;
        if res.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("group {} not found", g.id)));
        }
        let mut updated = g;
        updated.updated_at = now;
        Ok(updated)
    }

    pub async fn delete(&self, id: Uuid) -> Result<()> {
        let res = sqlx::query("DELETE FROM multiwan_groups WHERE id=?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AifwError::Database(e.to_string()))?;
        if res.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("group {id} not found")));
        }
        Ok(())
    }

    pub async fn list_members(&self, group_id: Uuid) -> Result<Vec<GroupMember>> {
        let rows = sqlx::query(
            "SELECT group_id, gateway_id, tier, weight FROM multiwan_group_members
             WHERE group_id = ?1 ORDER BY tier ASC, weight DESC",
        )
        .bind(group_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;
        Ok(rows
            .iter()
            .map(|r| GroupMember {
                group_id: r.get::<String, _>("group_id").parse().unwrap_or_default(),
                gateway_id: r.get::<String, _>("gateway_id").parse().unwrap_or_default(),
                tier: r.get::<i64, _>("tier") as u32,
                weight: r.get::<i64, _>("weight") as u32,
            })
            .collect())
    }

    pub async fn add_member(&self, m: GroupMember) -> Result<GroupMember> {
        sqlx::query(
            "INSERT OR REPLACE INTO multiwan_group_members (group_id, gateway_id, tier, weight)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(m.group_id.to_string())
        .bind(m.gateway_id.to_string())
        .bind(m.tier as i64)
        .bind(m.weight as i64)
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;
        Ok(m)
    }

    pub async fn remove_member(&self, group_id: Uuid, gateway_id: Uuid) -> Result<()> {
        let res =
            sqlx::query("DELETE FROM multiwan_group_members WHERE group_id=?1 AND gateway_id=?2")
                .bind(group_id.to_string())
                .bind(gateway_id.to_string())
                .execute(&self.pool)
                .await
                .map_err(|e| AifwError::Database(e.to_string()))?;
        if res.rows_affected() == 0 {
            return Err(AifwError::NotFound("member not in group".into()));
        }
        Ok(())
    }
}

/// Pure selection logic — given a group, its members, and current gateway states,
/// produce the Selection for rule emission. No I/O.
pub fn select(group: &GatewayGroup, members: &[GroupMember], gateways: &[Gateway]) -> Selection {
    use std::collections::HashMap;
    let gw_by_id: HashMap<Uuid, &Gateway> = gateways.iter().map(|g| (g.id, g)).collect();

    let healthy: Vec<(&GroupMember, &Gateway)> = members
        .iter()
        .filter_map(|m| {
            let gw = gw_by_id.get(&m.gateway_id)?;
            if gw.enabled && matches!(gw.state, GatewayState::Up | GatewayState::Warning) {
                Some((m, *gw))
            } else {
                None
            }
        })
        .collect();

    if healthy.is_empty() {
        return Selection::None;
    }

    match group.policy {
        GroupPolicy::Failover => {
            // Lowest tier wins; within tier highest weight wins.
            let min_tier = healthy.iter().map(|(m, _)| m.tier).min().unwrap();
            let best = healthy
                .iter()
                .filter(|(m, _)| m.tier == min_tier)
                .max_by_key(|(m, g)| (m.weight, prefer_up(g.state)))
                .unwrap();
            Selection::Single(best.1.id)
        }
        GroupPolicy::WeightedLb | GroupPolicy::LoadBalance => {
            let min_tier = healthy.iter().map(|(m, _)| m.tier).min().unwrap();
            let list: Vec<(Uuid, u32)> = healthy
                .iter()
                .filter(|(m, _)| m.tier == min_tier)
                .map(|(m, g)| (g.id, m.weight.max(1)))
                .collect();
            Selection::WeightedList(list)
        }
        GroupPolicy::Adaptive => {
            let min_tier = healthy.iter().map(|(m, _)| m.tier).min().unwrap();
            let list: Vec<(Uuid, u32)> = healthy
                .iter()
                .filter(|(m, _)| m.tier == min_tier)
                .map(|(m, g)| {
                    let mos = g.last_mos.unwrap_or(3.5).clamp(1.0, 4.5);
                    let factor = ((mos - 1.0) * 10.0) as u32; // 0..35
                    (g.id, m.weight.saturating_mul(factor.max(1)))
                })
                .collect();
            Selection::WeightedList(list)
        }
    }
}

fn prefer_up(s: GatewayState) -> u8 {
    match s {
        GatewayState::Up => 2,
        GatewayState::Warning => 1,
        _ => 0,
    }
}

fn row_to_group(r: &sqlx::sqlite::SqliteRow) -> GatewayGroup {
    GatewayGroup {
        id: r.get::<String, _>("id").parse().unwrap_or_default(),
        name: r.get("name"),
        policy: GroupPolicy::parse(&r.get::<String, _>("policy")).unwrap_or(GroupPolicy::Failover),
        preempt: r.get::<i64, _>("preempt") != 0,
        sticky: StickyMode::parse(&r.get::<String, _>("sticky")).unwrap_or(StickyMode::None),
        hysteresis_ms: r.get::<i64, _>("hysteresis_ms") as u32,
        kill_states_on_failover: r.get::<i64, _>("kill_states_on_failover") != 0,
        created_at: r.get::<String, _>("created_at").parse().unwrap_or_default(),
        updated_at: r.get::<String, _>("updated_at").parse().unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_gw(id: Uuid, state: GatewayState, mos: Option<f64>) -> Gateway {
        Gateway {
            id,
            name: format!("gw-{id}"),
            instance_id: Uuid::new_v4(),
            interface: "em0".into(),
            next_hop: "10.0.0.1".into(),
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
            state,
            last_rtt_ms: None,
            last_jitter_ms: None,
            last_loss_pct: None,
            last_mos: mos,
            last_probe_ts: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn make_group(policy: GroupPolicy) -> GatewayGroup {
        GatewayGroup {
            id: Uuid::new_v4(),
            name: "g".into(),
            policy,
            preempt: true,
            sticky: StickyMode::None,
            hysteresis_ms: 2000,
            kill_states_on_failover: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn failover_picks_lowest_tier_up() {
        let g = make_group(GroupPolicy::Failover);
        let gw1 = make_gw(Uuid::new_v4(), GatewayState::Up, None);
        let gw2 = make_gw(Uuid::new_v4(), GatewayState::Up, None);
        let members = vec![
            GroupMember {
                group_id: g.id,
                gateway_id: gw1.id,
                tier: 1,
                weight: 1,
            },
            GroupMember {
                group_id: g.id,
                gateway_id: gw2.id,
                tier: 2,
                weight: 1,
            },
        ];
        assert_eq!(
            select(&g, &members, &[gw1.clone(), gw2]),
            Selection::Single(gw1.id)
        );
    }

    #[test]
    fn failover_falls_back_when_tier1_down() {
        let g = make_group(GroupPolicy::Failover);
        let gw1 = make_gw(Uuid::new_v4(), GatewayState::Down, None);
        let gw2 = make_gw(Uuid::new_v4(), GatewayState::Up, None);
        let members = vec![
            GroupMember {
                group_id: g.id,
                gateway_id: gw1.id,
                tier: 1,
                weight: 1,
            },
            GroupMember {
                group_id: g.id,
                gateway_id: gw2.id,
                tier: 2,
                weight: 1,
            },
        ];
        assert_eq!(
            select(&g, &members, &[gw1, gw2.clone()]),
            Selection::Single(gw2.id)
        );
    }

    #[test]
    fn no_selection_when_all_down() {
        let g = make_group(GroupPolicy::Failover);
        let gw1 = make_gw(Uuid::new_v4(), GatewayState::Down, None);
        let members = vec![GroupMember {
            group_id: g.id,
            gateway_id: gw1.id,
            tier: 1,
            weight: 1,
        }];
        assert_eq!(select(&g, &members, &[gw1]), Selection::None);
    }

    #[test]
    fn weighted_lb_returns_list() {
        let g = make_group(GroupPolicy::WeightedLb);
        let gw1 = make_gw(Uuid::new_v4(), GatewayState::Up, None);
        let gw2 = make_gw(Uuid::new_v4(), GatewayState::Up, None);
        let members = vec![
            GroupMember {
                group_id: g.id,
                gateway_id: gw1.id,
                tier: 1,
                weight: 2,
            },
            GroupMember {
                group_id: g.id,
                gateway_id: gw2.id,
                tier: 1,
                weight: 3,
            },
        ];
        match select(&g, &members, &[gw1, gw2]) {
            Selection::WeightedList(l) => assert_eq!(l.len(), 2),
            _ => panic!("expected WeightedList"),
        }
    }

    #[test]
    fn adaptive_scales_by_mos() {
        let g = make_group(GroupPolicy::Adaptive);
        let gw1 = make_gw(Uuid::new_v4(), GatewayState::Up, Some(4.4)); // great
        let gw2 = make_gw(Uuid::new_v4(), GatewayState::Up, Some(1.5)); // poor
        let members = vec![
            GroupMember {
                group_id: g.id,
                gateway_id: gw1.id,
                tier: 1,
                weight: 1,
            },
            GroupMember {
                group_id: g.id,
                gateway_id: gw2.id,
                tier: 1,
                weight: 1,
            },
        ];
        match select(&g, &members, &[gw1.clone(), gw2.clone()]) {
            Selection::WeightedList(l) => {
                let w1 = l.iter().find(|(id, _)| *id == gw1.id).unwrap().1;
                let w2 = l.iter().find(|(id, _)| *id == gw2.id).unwrap().1;
                assert!(
                    w1 > w2,
                    "gw1 (mos 4.4) should weigh more than gw2 (mos 1.5)"
                );
            }
            _ => panic!(),
        }
    }
}
