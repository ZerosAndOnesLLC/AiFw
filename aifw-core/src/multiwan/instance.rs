use aifw_common::{
    AifwError, DEFAULT_FIB_NUMBER, DEFAULT_INSTANCE_ID, DEFAULT_INSTANCE_NAME, InstanceMember,
    InstanceStatus, Result, RoutingInstance,
};
use aifw_pf::PfBackend;
use chrono::Utc;
use sqlx::Row;
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;
use uuid::Uuid;

/// Engine for WAN routing instances. Each instance maps to a unique FreeBSD FIB.
pub struct InstanceEngine {
    pool: SqlitePool,
    pf: Arc<dyn PfBackend>,
}

impl InstanceEngine {
    pub fn new(pool: SqlitePool, pf: Arc<dyn PfBackend>) -> Self {
        Self { pool, pf }
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS multiwan_instances (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                fib_number INTEGER UNIQUE NOT NULL,
                description TEXT,
                mgmt_reachable INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'idle',
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
            CREATE TABLE IF NOT EXISTS multiwan_instance_members (
                instance_id TEXT NOT NULL,
                interface TEXT NOT NULL,
                PRIMARY KEY (instance_id, interface),
                FOREIGN KEY (instance_id) REFERENCES multiwan_instances(id) ON DELETE CASCADE
            )
            "#,
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_mwan_inst_fib ON multiwan_instances(fib_number)",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;

        let now = Utc::now().to_rfc3339();
        sqlx::query(
            r#"
            INSERT OR IGNORE INTO multiwan_instances
                (id, name, fib_number, description, mgmt_reachable, status, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, 1, 'active', ?5, ?5)
            "#,
        )
        .bind(DEFAULT_INSTANCE_ID.to_string())
        .bind(DEFAULT_INSTANCE_NAME)
        .bind(DEFAULT_FIB_NUMBER as i64)
        .bind("Default routing instance (FIB 0)")
        .bind(&now)
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;

        Ok(())
    }

    pub async fn list(&self) -> Result<Vec<RoutingInstance>> {
        let rows = sqlx::query(
            "SELECT id, name, fib_number, description, mgmt_reachable, status, created_at, updated_at
             FROM multiwan_instances ORDER BY fib_number ASC",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;

        Ok(rows.iter().map(row_to_instance).collect())
    }

    pub async fn get(&self, id: Uuid) -> Result<RoutingInstance> {
        let row = sqlx::query(
            "SELECT id, name, fib_number, description, mgmt_reachable, status, created_at, updated_at
             FROM multiwan_instances WHERE id = ?1",
        )
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?
        .ok_or_else(|| AifwError::NotFound(format!("instance {id} not found")))?;

        Ok(row_to_instance(&row))
    }

    pub async fn add(&self, mut inst: RoutingInstance) -> Result<RoutingInstance> {
        if inst.name.trim().is_empty() {
            return Err(AifwError::Validation("instance name required".into()));
        }

        let fib_count = self.pf.list_fibs().await.unwrap_or(1);
        if inst.fib_number >= fib_count {
            return Err(AifwError::Validation(format!(
                "fib {} out of range (net.fibs={})",
                inst.fib_number, fib_count
            )));
        }

        inst.created_at = Utc::now();
        inst.updated_at = inst.created_at;

        sqlx::query(
            r#"
            INSERT INTO multiwan_instances
                (id, name, fib_number, description, mgmt_reachable, status, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
        )
        .bind(inst.id.to_string())
        .bind(&inst.name)
        .bind(inst.fib_number as i64)
        .bind(inst.description.as_deref())
        .bind(inst.mgmt_reachable as i64)
        .bind(inst.status.as_str())
        .bind(inst.created_at.to_rfc3339())
        .bind(inst.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;

        tracing::info!(id = %inst.id, name = %inst.name, fib = inst.fib_number, "routing instance created");
        Ok(inst)
    }

    pub async fn update(&self, inst: RoutingInstance) -> Result<RoutingInstance> {
        let now = Utc::now();
        let result = sqlx::query(
            r#"
            UPDATE multiwan_instances
               SET name = ?2, fib_number = ?3, description = ?4, mgmt_reachable = ?5,
                   status = ?6, updated_at = ?7
             WHERE id = ?1
            "#,
        )
        .bind(inst.id.to_string())
        .bind(&inst.name)
        .bind(inst.fib_number as i64)
        .bind(inst.description.as_deref())
        .bind(inst.mgmt_reachable as i64)
        .bind(inst.status.as_str())
        .bind(now.to_rfc3339())
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!(
                "instance {} not found",
                inst.id
            )));
        }

        let mut updated = inst;
        updated.updated_at = now;
        Ok(updated)
    }

    pub async fn delete(&self, id: Uuid) -> Result<()> {
        if id == DEFAULT_INSTANCE_ID {
            return Err(AifwError::Validation(
                "cannot delete the default routing instance".into(),
            ));
        }
        let result = sqlx::query("DELETE FROM multiwan_instances WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| AifwError::Database(e.to_string()))?;
        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("instance {id} not found")));
        }
        Ok(())
    }

    pub async fn list_members(&self, instance_id: Uuid) -> Result<Vec<InstanceMember>> {
        let rows = sqlx::query(
            "SELECT instance_id, interface FROM multiwan_instance_members WHERE instance_id = ?1",
        )
        .bind(instance_id.to_string())
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;

        Ok(rows
            .iter()
            .map(|r| InstanceMember {
                instance_id: r
                    .get::<String, _>("instance_id")
                    .parse()
                    .unwrap_or_default(),
                interface: r.get("interface"),
            })
            .collect())
    }

    /// Attach an interface to an instance and pin it to the instance's FIB.
    pub async fn add_member(&self, instance_id: Uuid, interface: &str) -> Result<InstanceMember> {
        let inst = self.get(instance_id).await?;

        // Detach from any existing instance (interface can only live in one)
        sqlx::query("DELETE FROM multiwan_instance_members WHERE interface = ?1")
            .bind(interface)
            .execute(&self.pool)
            .await
            .map_err(|e| AifwError::Database(e.to_string()))?;

        sqlx::query(
            "INSERT INTO multiwan_instance_members (instance_id, interface) VALUES (?1, ?2)",
        )
        .bind(instance_id.to_string())
        .bind(interface)
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;

        self.pf
            .set_interface_fib(interface, inst.fib_number)
            .await
            .map_err(|e| AifwError::Pf(e.to_string()))?;

        tracing::info!(%instance_id, interface, fib = inst.fib_number, "instance member attached");
        Ok(InstanceMember {
            instance_id,
            interface: interface.to_string(),
        })
    }

    pub async fn remove_member(&self, instance_id: Uuid, interface: &str) -> Result<()> {
        let result = sqlx::query(
            "DELETE FROM multiwan_instance_members WHERE instance_id = ?1 AND interface = ?2",
        )
        .bind(instance_id.to_string())
        .bind(interface)
        .execute(&self.pool)
        .await
        .map_err(|e| AifwError::Database(e.to_string()))?;
        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!(
                "member {interface} not in instance {instance_id}"
            )));
        }
        // Return interface to default FIB
        let _ = self
            .pf
            .set_interface_fib(interface, DEFAULT_FIB_NUMBER)
            .await;
        Ok(())
    }

    /// Report the number of FIBs the kernel makes available.
    pub async fn available_fibs(&self) -> Result<u32> {
        self.pf
            .list_fibs()
            .await
            .map_err(|e| AifwError::Pf(e.to_string()))
    }
}

fn row_to_instance(r: &sqlx::sqlite::SqliteRow) -> RoutingInstance {
    let status_str: String = r.get("status");
    RoutingInstance {
        id: r.get::<String, _>("id").parse().unwrap_or_default(),
        name: r.get("name"),
        fib_number: r.get::<i64, _>("fib_number") as u32,
        description: r.get("description"),
        mgmt_reachable: r.get::<i64, _>("mgmt_reachable") != 0,
        status: InstanceStatus::parse(&status_str).unwrap_or(InstanceStatus::Idle),
        created_at: r.get::<String, _>("created_at").parse().unwrap_or_default(),
        updated_at: r.get::<String, _>("updated_at").parse().unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aifw_pf::PfMock;

    async fn setup() -> InstanceEngine {
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .connect(":memory:")
            .await
            .unwrap();
        let pf = Arc::new(PfMock::new());
        pf.set_fib_count(4).await;
        let engine = InstanceEngine::new(pool, pf);
        engine.migrate().await.unwrap();
        engine
    }

    #[tokio::test]
    async fn default_instance_seeded() {
        let engine = setup().await;
        let list = engine.list().await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, DEFAULT_INSTANCE_ID);
        assert_eq!(list[0].fib_number, 0);
        assert!(list[0].mgmt_reachable);
    }

    #[tokio::test]
    async fn migrate_is_idempotent() {
        let engine = setup().await;
        engine.migrate().await.unwrap();
        engine.migrate().await.unwrap();
        let list = engine.list().await.unwrap();
        assert_eq!(list.len(), 1);
    }

    #[tokio::test]
    async fn cannot_delete_default_instance() {
        let engine = setup().await;
        let err = engine.delete(DEFAULT_INSTANCE_ID).await.unwrap_err();
        assert!(matches!(err, AifwError::Validation(_)));
    }

    #[tokio::test]
    async fn fib_uniqueness_enforced() {
        let engine = setup().await;
        let inst = RoutingInstance {
            id: Uuid::new_v4(),
            name: "collides".into(),
            fib_number: 0, // collides with default
            description: None,
            mgmt_reachable: false,
            status: InstanceStatus::Idle,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let err = engine.add(inst).await.unwrap_err();
        assert!(matches!(err, AifwError::Database(_)));
    }

    #[tokio::test]
    async fn fib_out_of_range_rejected() {
        let engine = setup().await;
        let inst = RoutingInstance {
            id: Uuid::new_v4(),
            name: "too-high".into(),
            fib_number: 99,
            description: None,
            mgmt_reachable: false,
            status: InstanceStatus::Idle,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let err = engine.add(inst).await.unwrap_err();
        assert!(matches!(err, AifwError::Validation(_)));
    }

    #[tokio::test]
    async fn member_attach_pins_fib() {
        let engine = setup().await;
        let inst = engine
            .add(RoutingInstance {
                id: Uuid::new_v4(),
                name: "wan2".into(),
                fib_number: 2,
                description: None,
                mgmt_reachable: false,
                status: InstanceStatus::Idle,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            })
            .await
            .unwrap();
        engine.add_member(inst.id, "em1").await.unwrap();
        let members = engine.list_members(inst.id).await.unwrap();
        assert_eq!(members.len(), 1);
        assert_eq!(members[0].interface, "em1");
    }

    #[tokio::test]
    async fn member_delete_cascades() {
        let engine = setup().await;
        let inst = engine
            .add(RoutingInstance {
                id: Uuid::new_v4(),
                name: "wan3".into(),
                fib_number: 3,
                description: None,
                mgmt_reachable: false,
                status: InstanceStatus::Idle,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            })
            .await
            .unwrap();
        engine.add_member(inst.id, "em2").await.unwrap();
        engine.delete(inst.id).await.unwrap();
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM multiwan_instance_members WHERE instance_id = ?1",
        )
        .bind(inst.id.to_string())
        .fetch_one(&engine.pool)
        .await
        .unwrap();
        assert_eq!(count, 0);
    }
}
