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

/// NAT engine: persists SNAT/DNAT/masquerade rules in the `nat_rules`
/// SQLite table and loads active ones as pf NAT rules into the `aifw`
/// anchor (override via [`Self::with_anchor`]). Every mutation commits its
/// audit row in the same transaction.
pub struct NatEngine {
    pool: SqlitePool,
    pf: Arc<dyn PfBackend>,
    audit: AuditLog,
    anchor: String,
}

impl NatEngine {
    /// Build a NAT engine over the shared pool and pf backend, targeting
    /// the default `aifw` anchor
    pub fn new(pool: SqlitePool, pf: Arc<dyn PfBackend>) -> Self {
        let audit = AuditLog::new(pool.clone());
        Self {
            pool,
            pf,
            audit,
            anchor: "aifw".to_string(),
        }
    }

    /// Replace the target pf anchor (builder style)
    pub fn with_anchor(mut self, anchor: String) -> Self {
        self.anchor = anchor;
        self
    }

    /// Create the `nat_rules` table and its status index if missing
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

        sqlx::query("CREATE INDEX IF NOT EXISTS idx_nat_rules_status ON nat_rules(status);")
            .execute(&self.pool)
            .await?;

        Ok(())
    }

    /// Validate and insert a NAT rule; the row and its audit entry commit
    /// in one transaction. pf is untouched until [`Self::apply_rules`].
    /// Fails validation when the interface is empty or a DNAT/RDR rule has
    /// neither a destination nor a redirect port.
    pub async fn add_rule(&self, rule: NatRule) -> Result<NatRule> {
        validate_nat_rule(&rule)?;
        self.parser_gate_with(&rule).await?;
        let pf_syntax = rule.to_pf_rule();
        // PERF-H6 (#350): mutation + audit row commit together — one fsync
        // instead of two per NAT rule change.
        let mut tx = self.pool.begin().await?;
        Self::insert_rule_on(&mut *tx, &rule).await?;
        AuditLog::log_on(
            &mut *tx,
            AuditAction::RuleAdded,
            Some(rule.id),
            &format!("nat: {pf_syntax}"),
            "nat_engine",
        )
        .await?;
        tx.commit().await?;
        tracing::info!(id = %rule.id, nat_type = %rule.nat_type, "NAT rule added");
        Ok(rule)
    }

    /// Fetch a NAT rule by id. Fails with `NotFound` if it doesn't exist
    pub async fn get_rule(&self, id: Uuid) -> Result<NatRule> {
        let row = sqlx::query_as::<_, NatRuleRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {NAT_RULE_COLUMNS} FROM nat_rules WHERE id = ?1"
        )))
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?;

        row.map(|r| r.into_nat_rule())
            .transpose()?
            .ok_or_else(|| AifwError::NotFound(format!("NAT rule {id} not found")))
    }

    /// All NAT rules, oldest first
    pub async fn list_rules(&self) -> Result<Vec<NatRule>> {
        let rows = sqlx::query_as::<_, NatRuleRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {NAT_RULE_COLUMNS} FROM nat_rules ORDER BY created_at ASC"
        )))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.into_nat_rule()).collect()
    }

    /// NAT rules with status `active`, oldest first
    pub async fn list_active_rules(&self) -> Result<Vec<NatRule>> {
        let rows = sqlx::query_as::<_, NatRuleRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {NAT_RULE_COLUMNS} FROM nat_rules WHERE status = 'active' ORDER BY created_at ASC"
        )))
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter().map(|r| r.into_nat_rule()).collect()
    }

    /// Validate and update a NAT rule; the update and its audit entry
    /// commit in one transaction. Fails with `NotFound` for an unknown id.
    /// pf is untouched until [`Self::apply_rules`].
    pub async fn update_rule(&self, rule: &NatRule) -> Result<()> {
        validate_nat_rule(rule)?;
        self.parser_gate_with(rule).await?;
        let mut tx = self.pool.begin().await?;
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
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!(
                "NAT rule {} not found",
                rule.id
            )));
        }

        AuditLog::log_on(
            &mut *tx,
            AuditAction::RuleUpdated,
            Some(rule.id),
            &format!("nat: {}", rule.to_pf_rule()),
            "nat_engine",
        )
        .await?;
        tx.commit().await?;
        tracing::info!(id = %rule.id, "NAT rule updated");
        Ok(())
    }

    /// Delete a NAT rule; the delete and its audit entry commit in one
    /// transaction. Fails with `NotFound` for an unknown id
    pub async fn delete_rule(&self, id: Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await?;
        let result = sqlx::query("DELETE FROM nat_rules WHERE id = ?1")
            .bind(id.to_string())
            .execute(&mut *tx)
            .await?;

        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("NAT rule {id} not found")));
        }

        AuditLog::log_on(
            &mut *tx,
            AuditAction::RuleRemoved,
            Some(id),
            "NAT rule deleted",
            "nat_engine",
        )
        .await?;
        tx.commit().await?;
        tracing::info!(%id, "NAT rule deleted");
        Ok(())
    }

    /// Generate pf NAT rules and load them into the anchor
    pub async fn apply_rules(&self) -> Result<()> {
        let rules = self.list_active_rules().await?;
        let pf_rules = self.render_ruleset(&rules);

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
                &format!(
                    "{} NAT rules applied to anchor {}",
                    pf_rules.len(),
                    self.anchor
                ),
                "nat_engine",
            )
            .await?;

        Ok(())
    }

    /// Real-parser gate (#531): dry-run the full prospective active ruleset
    /// (current active rules with `candidate` inserted/substituted) through
    /// `pfctl -n` before persisting, so rules only real pf can judge (af-to
    /// family constraints, prefix extraction limits) never land in the DB
    /// unloadable. No-op on the mock backend (dev/tests).
    async fn parser_gate_with(&self, candidate: &NatRule) -> Result<()> {
        let mut prospective: Vec<NatRule> = self
            .list_active_rules()
            .await?
            .into_iter()
            .filter(|r| r.id != candidate.id)
            .collect();
        if candidate.status == NatStatus::Active {
            prospective.push(candidate.clone());
        }
        let rendered = self.render_ruleset(&prospective);
        self.pf
            .validate_rules(&self.anchor, &rendered)
            .await
            .map_err(|e| AifwError::Validation(format!("pf rejected NAT ruleset: {e}")))
    }

    /// Render the full pf ruleset for a set of NAT rules, translation-class
    /// lines first (traditional pf.conf section order). Cross-family
    /// (af-to) rules render as filter-class `pass` lines and pf evaluates
    /// the two classes independently, so cross-class order has no effect —
    /// this ordering just keeps the loaded file conventional.
    fn render_ruleset(&self, rules: &[NatRule]) -> Vec<String> {
        let (translation, filter): (Vec<String>, Vec<String>) = rules
            .iter()
            .flat_map(|r| r.to_pf_rules())
            .partition(|l| is_translation_class(l));
        translation.into_iter().chain(filter).collect()
    }

    /// Verify the pf anchor holds the NAT ruleset [`Self::apply_rules`]
    /// would render right now (#535 post-apply verification). Exact
    /// per-class comparison on backends that echo loaded rules; per-class
    /// emptiness invariant on real pfctl (see `RuleEngine::verify_applied`).
    /// Cross-family (af-to) rules are filter-class and surface via
    /// `get_rules`, not `get_nat_rules`.
    pub async fn verify_applied(&self) -> Result<()> {
        let rules = self.list_active_rules().await?;
        let (expected_nat, expected_filter): (Vec<String>, Vec<String>) = rules
            .iter()
            .flat_map(|r| r.to_pf_rules())
            .partition(|l| is_translation_class(l));
        let actual_nat = self
            .pf
            .get_nat_rules(&self.anchor)
            .await
            .map_err(|e| AifwError::Pf(e.to_string()))?;
        let actual_filter = self
            .pf
            .get_rules(&self.anchor)
            .await
            .map_err(|e| AifwError::Pf(e.to_string()))?;
        let mismatch = if self.pf.echoes_exact_rules() {
            actual_nat != expected_nat || actual_filter != expected_filter
        } else {
            actual_nat.is_empty() != expected_nat.is_empty()
                || actual_filter.is_empty() != expected_filter.is_empty()
        };
        if mismatch {
            return Err(AifwError::Pf(format!(
                "anchor {} holds {} nat-class / {} filter-class rules but {} / {} were expected — pf does not match the database",
                self.anchor,
                actual_nat.len(),
                actual_filter.len(),
                expected_nat.len(),
                expected_filter.len()
            )));
        }
        Ok(())
    }

    /// Flush all NAT rules from the pf anchor and record an audit entry.
    /// Fails if the pf backend rejects the flush
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

    /// Executor-generic insert. Public so the transactional restore path
    /// (#158/#535) can batch NAT rows with every other section.
    pub async fn insert_rule_on<'e, E>(exec: E, rule: &NatRule) -> Result<()>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
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
        .execute(exec)
        .await?;

        Ok(())
    }
}

/// True for pf translation-class rule text (`nat`/`rdr`/`binat`), false for
/// filter-class lines (the af-to `pass` rules cross-family NAT renders to).
fn is_translation_class(rule: &str) -> bool {
    ["nat ", "rdr ", "binat "]
        .iter()
        .any(|p| rule.starts_with(p))
}

/// Validate a NAT rule before persisting: interface required, DNAT/RDR
/// needs a destination or redirect port. Public so the backup restore path
/// can pre-validate a whole config with the same checks `add_rule` applies.
pub fn validate_nat_rule(rule: &NatRule) -> Result<()> {
    if rule.interface.0.is_empty() {
        return Err(AifwError::Validation(
            "NAT rule requires an interface".to_string(),
        ));
    }

    // DNAT requires a destination port or redirect port
    if rule.nat_type == NatType::Dnat && rule.dst_port.is_none() && rule.redirect.port.is_none() {
        return Err(AifwError::Validation(
            "DNAT/RDR rule requires a destination port or redirect port".to_string(),
        ));
    }

    // Masquerade redirect is the interface itself, no address needed
    if rule.nat_type == NatType::Masquerade && rule.redirect.address != Address::Any {
        // This is fine — we'll ignore the redirect address and use the interface
    }

    // Cross-family (af-to) rules: pf requires the matched side and the
    // translation source to be in opposite, concrete families (#531).
    match rule.nat_type {
        NatType::Nat64 => validate_af_to(rule, true)?,
        NatType::Nat46 => validate_af_to(rule, false)?,
        _ => {}
    }

    Ok(())
}

/// Family/prefix checks for pf `af-to` rules. `inet6_match` is true for
/// NAT64 (rule matches IPv6, translates to IPv4) and false for NAT46.
fn validate_af_to(rule: &NatRule, inet6_match: bool) -> Result<()> {
    let (kind, matched, translated) = if inet6_match {
        ("nat64", "IPv6", "IPv4")
    } else {
        ("nat46", "IPv4", "IPv6")
    };

    // pf tables can mix families — af-to needs concrete same-family matches.
    if matches!(rule.src_addr, Address::Table(_)) || matches!(rule.dst_addr, Address::Table(_)) {
        return Err(AifwError::Validation(format!(
            "{kind} rules cannot use pf tables for source/destination — the matched family must be concrete"
        )));
    }

    // Source must be `any` or in the matched family.
    if rule.src_addr.is_ipv6() == Some(!inet6_match) {
        return Err(AifwError::Validation(format!(
            "{kind} source address must be {matched} (the rule matches {matched} traffic)"
        )));
    }

    if inet6_match {
        // NAT64 destination is the translation prefix: an IPv6 network with
        // a /96 prefix so the IPv4 destination embeds in the low 32 bits
        // (RFC 6052). pf's af-to extraction supports /96 exactly.
        match rule.dst_addr {
            Address::Network(std::net::IpAddr::V6(_), 96) => {}
            _ => {
                return Err(AifwError::Validation(
                    "nat64 destination must be an IPv6 /96 translation prefix (e.g. 64:ff9b::/96)"
                        .to_string(),
                ));
            }
        }
    } else {
        // NAT46 destination is the concrete IPv4 host/network being reached.
        match rule.dst_addr.is_ipv6() {
            Some(false) => {}
            _ => {
                return Err(AifwError::Validation(
                    "nat46 destination must be a concrete IPv4 address or network".to_string(),
                ));
            }
        }
    }

    // Translation source: a single concrete host in the translated family
    // (pf: `af-to inet|inet6 from <addr>` — the new source of the packet).
    match (&rule.redirect.address, rule.redirect.address.is_ipv6()) {
        (Address::Single(_), Some(v6)) if v6 != inet6_match => {}
        _ => {
            return Err(AifwError::Validation(format!(
                "{kind} translation source (redirect) must be a single {translated} address the firewall owns"
            )));
        }
    }

    // af-to has no port-rewrite syntax.
    if rule.redirect.port.is_some() {
        return Err(AifwError::Validation(format!(
            "{kind} rules do not support a redirect port — af-to translates addresses, not ports"
        )));
    }

    Ok(())
}

/// Explicit column list for `NatRuleRow` selects, in schema order. Replaces
/// `SELECT *` which triggers a sqlx-sqlite column-count panic and blocks
/// column pruning (#348).
const NAT_RULE_COLUMNS: &str = "id, nat_type, interface, protocol, src_addr, \
    src_port_start, src_port_end, dst_addr, dst_port_start, dst_port_end, \
    redirect_addr, redirect_port_start, redirect_port_end, label, status, \
    created_at, updated_at";

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
