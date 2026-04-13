use aifw_common::{AifwError, Result, RouteLeak, RoutingInstance};
use aifw_pf::PfBackend;
use chrono::Utc;
use sqlx::Row;
use sqlx::sqlite::SqlitePool;
use std::collections::HashMap;
use std::sync::Arc;
use uuid::Uuid;

pub const LEAK_ANCHOR: &str = "aifw-mwan-leak";

pub struct LeakEngine {
    pool: SqlitePool,
    pf: Arc<dyn PfBackend>,
}

impl LeakEngine {
    pub fn new(pool: SqlitePool, pf: Arc<dyn PfBackend>) -> Self {
        Self { pool, pf }
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS multiwan_leaks (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                src_instance_id TEXT NOT NULL,
                dst_instance_id TEXT NOT NULL,
                prefix TEXT NOT NULL,
                protocol TEXT NOT NULL DEFAULT 'any',
                ports TEXT,
                direction TEXT NOT NULL DEFAULT 'bidirectional',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (src_instance_id) REFERENCES multiwan_instances(id) ON DELETE CASCADE,
                FOREIGN KEY (dst_instance_id) REFERENCES multiwan_instances(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;
        Ok(())
    }

    pub async fn list(&self) -> Result<Vec<RouteLeak>> {
        let rows = sqlx::query("SELECT * FROM multiwan_leaks ORDER BY name ASC")
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AifwError::Database(e.to_string()))?;
        Ok(rows.iter().map(row_to_leak).collect())
    }

    pub async fn get(&self, id: Uuid) -> Result<RouteLeak> {
        let row = sqlx::query("SELECT * FROM multiwan_leaks WHERE id = ?1")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AifwError::Database(e.to_string()))?
            .ok_or_else(|| AifwError::NotFound(format!("leak {id} not found")))?;
        Ok(row_to_leak(&row))
    }

    pub async fn add(&self, l: RouteLeak) -> Result<RouteLeak> {
        sqlx::query(
            r#"INSERT INTO multiwan_leaks
            (id, name, src_instance_id, dst_instance_id, prefix, protocol, ports,
             direction, enabled, created_at, updated_at)
            VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"#,
        )
        .bind(l.id.to_string())
        .bind(&l.name)
        .bind(l.src_instance_id.to_string())
        .bind(l.dst_instance_id.to_string())
        .bind(&l.prefix)
        .bind(&l.protocol)
        .bind(l.ports.as_deref())
        .bind(&l.direction)
        .bind(l.enabled as i64)
        .bind(l.created_at.to_rfc3339())
        .bind(l.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;
        Ok(l)
    }

    pub async fn update(&self, l: RouteLeak) -> Result<RouteLeak> {
        let now = Utc::now();
        let res = sqlx::query(
            r#"UPDATE multiwan_leaks SET
                name=?2, src_instance_id=?3, dst_instance_id=?4, prefix=?5,
                protocol=?6, ports=?7, direction=?8, enabled=?9, updated_at=?10
             WHERE id=?1"#,
        )
        .bind(l.id.to_string())
        .bind(&l.name)
        .bind(l.src_instance_id.to_string())
        .bind(l.dst_instance_id.to_string())
        .bind(&l.prefix)
        .bind(&l.protocol)
        .bind(l.ports.as_deref())
        .bind(&l.direction)
        .bind(l.enabled as i64)
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;
        if res.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("leak {} not found", l.id)));
        }
        let mut updated = l;
        updated.updated_at = now;
        Ok(updated)
    }

    pub async fn delete(&self, id: Uuid) -> Result<()> {
        // Block deletion of mgmt-escape leaks. A mgmt-escape is identified as
        // a leak whose destination instance is mgmt_reachable — without it the
        // admin could lock themselves out.
        let leak = self.get(id).await?;
        let dst = sqlx::query("SELECT mgmt_reachable FROM multiwan_instances WHERE id = ?1")
            .bind(leak.dst_instance_id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AifwError::Database(e.to_string()))?;
        if let Some(row) = dst {
            let mgmt: i64 = row.get("mgmt_reachable");
            if mgmt != 0 {
                return Err(AifwError::Validation(
                    "cannot delete leak pointing at mgmt-reachable instance (would strand admin)"
                        .into(),
                ));
            }
        }
        let res = sqlx::query("DELETE FROM multiwan_leaks WHERE id=?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AifwError::Database(e.to_string()))?;
        if res.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("leak {id} not found")));
        }
        Ok(())
    }

    /// Compile leaks into pf rules. Pure function — no I/O.
    pub fn compile(leaks: &[RouteLeak], instances: &[RoutingInstance]) -> Vec<String> {
        let inst: HashMap<Uuid, &RoutingInstance> =
            instances.iter().map(|i| (i.id, i)).collect();
        let mut out = Vec::new();
        for l in leaks.iter().filter(|l| l.enabled) {
            let Some(dst) = inst.get(&l.dst_instance_id) else {
                continue;
            };
            let proto = if l.protocol == "any" || l.protocol.is_empty() {
                String::new()
            } else {
                format!(" proto {}", l.protocol)
            };
            let ports = l
                .ports
                .as_deref()
                .map(|p| format!(" port {p}"))
                .unwrap_or_default();
            let label = format!("leak:{}", l.id);
            out.push(format!(
                "pass quick{proto} from any to {prefix}{ports} rtable {fib} keep state (if-bound) label \"{label}\"",
                prefix = l.prefix,
                fib = dst.fib_number,
            ));
            if l.direction == "bidirectional" {
                if let Some(src) = inst.get(&l.src_instance_id) {
                    out.push(format!(
                        "pass quick{proto} from {prefix} to any{ports} rtable {fib} keep state (if-bound) label \"{label}:rev\"",
                        prefix = l.prefix,
                        fib = src.fib_number,
                    ));
                }
            }
        }
        out
    }

    pub async fn apply(&self, instances: &[RoutingInstance]) -> Result<()> {
        let leaks = self.list().await?;
        let rules = Self::compile(&leaks, instances);
        self.pf
            .load_rules(LEAK_ANCHOR, &rules)
            .await
            .map_err(|e| AifwError::Pf(e.to_string()))?;
        tracing::info!(
            anchor = LEAK_ANCHOR,
            rules = rules.len(),
            "leak anchor loaded"
        );
        Ok(())
    }

    /// Seed default mgmt-escape leak: from every instance to FIB 0 (mgmt).
    /// Idempotent — re-seeds for any instance that doesn't have a leak yet.
    pub async fn seed_mgmt_escapes(&self, instances: &[RoutingInstance]) -> Result<()> {
        let default = instances
            .iter()
            .find(|i| i.mgmt_reachable && i.fib_number == aifw_common::DEFAULT_FIB_NUMBER);
        let Some(default) = default else {
            return Ok(());
        };
        for inst in instances.iter().filter(|i| i.id != default.id) {
            let existing: Option<(String,)> = sqlx::query_as(
                "SELECT id FROM multiwan_leaks WHERE src_instance_id = ?1 AND dst_instance_id = ?2 AND prefix = 'any' AND protocol = 'any'",
            )
            .bind(inst.id.to_string())
            .bind(default.id.to_string())
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AifwError::Database(e.to_string()))?;
            if existing.is_some() {
                continue;
            }
            let now = Utc::now();
            let leak = RouteLeak {
                id: Uuid::new_v4(),
                name: format!("{}-mgmt-escape", inst.name),
                src_instance_id: inst.id,
                dst_instance_id: default.id,
                prefix: "any".into(),
                protocol: "any".into(),
                ports: None,
                direction: "bidirectional".into(),
                enabled: true,
                created_at: now,
                updated_at: now,
            };
            self.add(leak).await?;
            tracing::info!(instance = %inst.name, "seeded mgmt escape leak");
        }
        Ok(())
    }
}

fn row_to_leak(r: &sqlx::sqlite::SqliteRow) -> RouteLeak {
    RouteLeak {
        id: r.get::<String, _>("id").parse().unwrap_or_default(),
        name: r.get("name"),
        src_instance_id: r
            .get::<String, _>("src_instance_id")
            .parse()
            .unwrap_or_default(),
        dst_instance_id: r
            .get::<String, _>("dst_instance_id")
            .parse()
            .unwrap_or_default(),
        prefix: r.get("prefix"),
        protocol: r.get("protocol"),
        ports: r.get("ports"),
        direction: r.get("direction"),
        enabled: r.get::<i64, _>("enabled") != 0,
        created_at: r
            .get::<String, _>("created_at")
            .parse()
            .unwrap_or_default(),
        updated_at: r
            .get::<String, _>("updated_at")
            .parse()
            .unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aifw_common::InstanceStatus;

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

    #[test]
    fn compile_bidirectional_emits_two_rules() {
        let src = make_inst(1, false);
        let dst = make_inst(0, true);
        let now = Utc::now();
        let leak = RouteLeak {
            id: Uuid::new_v4(),
            name: "mgmt-escape".into(),
            src_instance_id: src.id,
            dst_instance_id: dst.id,
            prefix: "10.0.0.0/24".into(),
            protocol: "any".into(),
            ports: None,
            direction: "bidirectional".into(),
            enabled: true,
            created_at: now,
            updated_at: now,
        };
        let rules = LeakEngine::compile(&[leak], &[src, dst]);
        assert_eq!(rules.len(), 2);
        assert!(rules[0].contains("rtable 0"));
        assert!(rules[1].contains("rtable 1"));
        assert!(rules.iter().all(|r| r.contains("if-bound")));
    }

    #[test]
    fn disabled_leaks_skipped() {
        let src = make_inst(1, false);
        let dst = make_inst(0, true);
        let now = Utc::now();
        let leak = RouteLeak {
            id: Uuid::new_v4(),
            name: "x".into(),
            src_instance_id: src.id,
            dst_instance_id: dst.id,
            prefix: "any".into(),
            protocol: "any".into(),
            ports: None,
            direction: "bidirectional".into(),
            enabled: false,
            created_at: now,
            updated_at: now,
        };
        assert!(LeakEngine::compile(&[leak], &[src, dst]).is_empty());
    }
}
