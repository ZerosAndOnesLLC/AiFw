use aifw_common::{
    Address, AifwError, Interface, NatRedirect, NatRule, NatStatus, NatType, PortRange, Protocol,
    Result,
};
use aifw_pf::PfBackend;
use chrono::{DateTime, Utc};
use sqlx::sqlite::SqlitePool;
use std::sync::Arc;
use uuid::Uuid;

use crate::audit::{AuditAction, AuditLog};

pub struct NatEngine {
    pool: SqlitePool,
    pf: Arc<dyn PfBackend>,
    audit: AuditLog,
    anchor: String,
}

impl NatEngine {
    pub fn new(pool: SqlitePool, pf: Arc<dyn PfBackend>) -> Self {
        let audit = AuditLog::new(pool.clone());
        Self {
            pool,
            pf,
            audit,
            anchor: "aifw".to_string(),
        }
    }

    pub fn with_anchor(mut self, anchor: String) -> Self {
        self.anchor = anchor;
        self
    }

    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS nat_rules (
                id TEXT PRIMARY KEY,
                nat_type TEXT NOT NULL,
                interface TEXT NOT NULL,
                protocol TEXT NOT NULL,
                src_addr TEXT NOT NULL,
                src_port_start INTEGER,
                src_port_end INTEGER,
                dst_addr TEXT NOT NULL,
                dst_port_start INTEGER,
                dst_port_end INTEGER,
                redirect_addr TEXT NOT NULL,
                redirect_port_start INTEGER,
                redirect_port_end INTEGER,
                label TEXT,
                status TEXT NOT NULL DEFAULT 'active',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_nat_rules_status ON nat_rules(status);",
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn add_rule(&self, rule: NatRule) -> Result<NatRule> {
        validate_nat_rule(&rule)?;
        self.insert_rule(&rule).await?;
        let pf_syntax = rule.to_pf_rule();
        self.audit
            .log(
                AuditAction::RuleAdded,
                Some(rule.id),
                &format!("nat: {pf_syntax}"),
                "nat_engine",
            )
            .await?;
        tracing::info!(id = %rule.id, nat_type = %rule.nat_type, "NAT rule added");
        Ok(rule)
    }

    pub async fn get_rule(&self, id: Uuid) -> Result<NatRule> {
        let row = sqlx::query_as::<_, NatRuleRow>("SELECT * FROM nat_rules WHERE id = ?1")
            .bind(id.to_string())
            .fetch_optional(&self.pool)
            .await?;

        row.map(|r| r.into_nat_rule())
            .transpose()?
            .ok_or_else(|| AifwError::NotFound(format!("NAT rule {id} not found")))
    }

    pub async fn list_rules(&self) -> Result<Vec<NatRule>> {
        let rows =
            sqlx::query_as::<_, NatRuleRow>("SELECT * FROM nat_rules ORDER BY created_at ASC")
                .fetch_all(&self.pool)
                .await?;

        rows.into_iter().map(|r| r.into_nat_rule()).collect()
    }

    pub async fn list_active_rules(&self) -> Result<Vec<NatRule>> {
        let rows = sqlx::query_as::<_, NatRuleRow>(
            "SELECT * FROM nat_rules WHERE status = 'active' ORDER BY created_at ASC",
        )
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.into_nat_rule()).collect()
    }

    pub async fn update_rule(&self, rule: &NatRule) -> Result<()> {
        validate_nat_rule(rule)?;
        let result = sqlx::query(
            r#"
            UPDATE nat_rules SET nat_type = ?2, interface = ?3, protocol = ?4,
                src_addr = ?5, src_port_start = ?6, src_port_end = ?7,
                dst_addr = ?8, dst_port_start = ?9, dst_port_end = ?10,
                redirect_addr = ?11, redirect_port_start = ?12, redirect_port_end = ?13,
                label = ?14, status = ?15, updated_at = ?16
            WHERE id = ?1
            "#,
        )
        .bind(rule.id.to_string())
        .bind(rule.nat_type.to_string())
        .bind(rule.interface.0.as_str())
        .bind(rule.protocol.to_string())
        .bind(rule.src_addr.to_string())
        .bind(rule.src_port.as_ref().map(|p| p.start as i64))
        .bind(rule.src_port.as_ref().map(|p| p.end as i64))
        .bind(rule.dst_addr.to_string())
        .bind(rule.dst_port.as_ref().map(|p| p.start as i64))
        .bind(rule.dst_port.as_ref().map(|p| p.end as i64))
        .bind(rule.redirect.address.to_string())
        .bind(rule.redirect.port.as_ref().map(|p| p.start as i64))
        .bind(rule.redirect.port.as_ref().map(|p| p.end as i64))
        .bind(rule.label.as_deref())
        .bind(match rule.status {
            NatStatus::Active => "active",
            NatStatus::Disabled => "disabled",
        })
        .bind(chrono::Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("NAT rule {} not found", rule.id)));
        }

        self.audit
            .log(
                AuditAction::RuleUpdated,
                Some(rule.id),
                &format!("nat: {}", rule.to_pf_rule()),
                "nat_engine",
            )
            .await?;
        tracing::info!(id = %rule.id, "NAT rule updated");
        Ok(())
    }

    pub async fn delete_rule(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM nat_rules WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("NAT rule {id} not found")));
        }

        self.audit
            .log(
                AuditAction::RuleRemoved,
                Some(id),
                "NAT rule deleted",
                "nat_engine",
            )
            .await?;
        tracing::info!(%id, "NAT rule deleted");
        Ok(())
    }

    /// Generate pf NAT rules and load them into the anchor
    pub async fn apply_rules(&self) -> Result<()> {
        let rules = self.list_active_rules().await?;
        let pf_rules: Vec<String> = rules.iter().map(|r| r.to_pf_rule()).collect();

        tracing::info!(
            anchor = %self.anchor,
            count = pf_rules.len(),
            "applying NAT rules to pf"
        );

        self.pf
            .load_nat_rules(&self.anchor, &pf_rules)
            .await
            .map_err(|e| AifwError::Pf(e.to_string()))?;

        self.audit
            .log(
                AuditAction::RulesApplied,
                None,
                &format!("{} NAT rules applied to anchor {}", pf_rules.len(), self.anchor),
                "nat_engine",
            )
            .await?;

        Ok(())
    }

    pub async fn flush_rules(&self) -> Result<()> {
        self.pf
            .flush_nat_rules(&self.anchor)
            .await
            .map_err(|e| AifwError::Pf(e.to_string()))?;

        self.audit
            .log(
                AuditAction::RulesFlushed,
                None,
                &format!("flushed NAT rules from anchor {}", self.anchor),
                "nat_engine",
            )
            .await?;

        tracing::info!(anchor = %self.anchor, "flushed NAT rules");
        Ok(())
    }

    async fn insert_rule(&self, rule: &NatRule) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO nat_rules (id, nat_type, interface, protocol, src_addr,
                src_port_start, src_port_end, dst_addr, dst_port_start, dst_port_end,
                redirect_addr, redirect_port_start, redirect_port_end,
                label, status, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)
            "#,
        )
        .bind(rule.id.to_string())
        .bind(rule.nat_type.to_string())
        .bind(rule.interface.0.as_str())
        .bind(rule.protocol.to_string())
        .bind(rule.src_addr.to_string())
        .bind(rule.src_port.as_ref().map(|p| p.start as i64))
        .bind(rule.src_port.as_ref().map(|p| p.end as i64))
        .bind(rule.dst_addr.to_string())
        .bind(rule.dst_port.as_ref().map(|p| p.start as i64))
        .bind(rule.dst_port.as_ref().map(|p| p.end as i64))
        .bind(rule.redirect.address.to_string())
        .bind(rule.redirect.port.as_ref().map(|p| p.start as i64))
        .bind(rule.redirect.port.as_ref().map(|p| p.end as i64))
        .bind(rule.label.as_deref())
        .bind(match rule.status {
            NatStatus::Active => "active",
            NatStatus::Disabled => "disabled",
        })
        .bind(rule.created_at.to_rfc3339())
        .bind(rule.updated_at.to_rfc3339())
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

fn validate_nat_rule(rule: &NatRule) -> Result<()> {
    if rule.interface.0.is_empty() {
        return Err(AifwError::Validation(
            "NAT rule requires an interface".to_string(),
        ));
    }

    // DNAT requires a destination port or redirect port
    if rule.nat_type == NatType::Dnat
        && rule.dst_port.is_none()
        && rule.redirect.port.is_none()
    {
        return Err(AifwError::Validation(
            "DNAT/RDR rule requires a destination port or redirect port".to_string(),
        ));
    }

    // Masquerade redirect is the interface itself, no address needed
    if rule.nat_type == NatType::Masquerade && rule.redirect.address != Address::Any {
        // This is fine — we'll ignore the redirect address and use the interface
    }

    Ok(())
}

#[derive(sqlx::FromRow)]
struct NatRuleRow {
    id: String,
    nat_type: String,
    interface: String,
    protocol: String,
    src_addr: String,
    src_port_start: Option<i64>,
    src_port_end: Option<i64>,
    dst_addr: String,
    dst_port_start: Option<i64>,
    dst_port_end: Option<i64>,
    redirect_addr: String,
    redirect_port_start: Option<i64>,
    redirect_port_end: Option<i64>,
    label: Option<String>,
    status: String,
    created_at: String,
    updated_at: String,
}

impl NatRuleRow {
    fn into_nat_rule(self) -> Result<NatRule> {
        let parse_port_range = |start: Option<i64>, end: Option<i64>| -> Option<PortRange> {
            match (start, end) {
                (Some(s), Some(e)) => Some(PortRange {
                    start: s as u16,
                    end: e as u16,
                }),
                _ => None,
            }
        };

        Ok(NatRule {
            id: Uuid::parse_str(&self.id)
                .map_err(|e| AifwError::Database(format!("invalid uuid: {e}")))?,
            nat_type: NatType::parse(&self.nat_type)?,
            interface: Interface(self.interface),
            protocol: Protocol::parse(&self.protocol)?,
            src_addr: Address::parse(&self.src_addr)?,
            src_port: parse_port_range(self.src_port_start, self.src_port_end),
            dst_addr: Address::parse(&self.dst_addr)?,
            dst_port: parse_port_range(self.dst_port_start, self.dst_port_end),
            redirect: NatRedirect {
                address: Address::parse(&self.redirect_addr)?,
                port: parse_port_range(self.redirect_port_start, self.redirect_port_end),
            },
            label: self.label,
            status: match self.status.as_str() {
                "active" => NatStatus::Active,
                _ => NatStatus::Disabled,
            },
            created_at: DateTime::parse_from_rfc3339(&self.created_at)
                .map_err(|e| AifwError::Database(format!("invalid date: {e}")))?
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339(&self.updated_at)
                .map_err(|e| AifwError::Database(format!("invalid date: {e}")))?
                .with_timezone(&Utc),
        })
    }
}
