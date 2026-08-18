use aifw_common::{
    AifwError, CountryCode, GeoIpAction, GeoIpLookupResult, GeoIpRule, GeoIpRuleStatus, Result,
};
use aifw_pf::PfBackend;
use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use ip_network::{IpNetwork, Ipv4Network, Ipv6Network};
use ip_network_table::IpNetworkTable;
use sqlx::sqlite::SqlitePool;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use uuid::Uuid;

/// In-memory geo-IP index built once at load time.
///
/// `lookup_table` is a treebitmap (longest-prefix match trie) keyed by the
/// network → country code. A 70k-CIDR US block takes ~tens of MB of memory
/// and resolves to O(W) per lookup where W is the address bit width
/// (32 for v4, 128 for v6). The legacy code did an O(N×M) linear scan of
/// every country's CIDR list on each lookup.
struct GeoIpIndex {
    /// Treebitmap for longest-prefix match. Value is the country code.
    lookup_table: IpNetworkTable<String>,
    /// Per-country CIDR list — preserved for pfctl table population
    /// (get_country_cidrs / apply_rules).
    by_country: HashMap<String, Vec<(IpAddr, u8)>>,
}

impl GeoIpIndex {
    fn empty() -> Self {
        Self {
            lookup_table: IpNetworkTable::new(),
            by_country: HashMap::new(),
        }
    }
}

/// Country-based blocking engine. Rules live in the `geoip_rules` /
/// `geoip_config` SQLite tables; country CIDR sets populate pf tables under
/// the `aifw-geoip` anchor. IP-to-country lookups hit a lock-free in-memory
/// longest-prefix-match index that reloads swap in atomically.
pub struct GeoIpEngine {
    pool: SqlitePool,
    pf: Arc<dyn PfBackend>,
    anchor: String,
    /// Atomic snapshot of the geo-IP index. Lookups acquire an Arc with no
    /// lock; reloads build a fresh index off-thread and swap.
    index: Arc<ArcSwap<GeoIpIndex>>,
}

impl GeoIpEngine {
    /// Build a geo-IP engine over the shared pool and pf backend, targeting
    /// the `aifw-geoip` anchor. The in-memory index starts empty until
    /// [`Self::load_database`] runs.
    pub fn new(pool: SqlitePool, pf: Arc<dyn PfBackend>) -> Self {
        Self {
            pool,
            pf,
            anchor: aifw_common::anchors::GEOIP.to_string(),
            index: Arc::new(ArcSwap::from_pointee(GeoIpIndex::empty())),
        }
    }

    /// Create the `geoip_rules` and `geoip_config` tables if missing
    pub async fn migrate(&self) -> Result<()> {
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS geoip_rules (
                id TEXT PRIMARY KEY,
                country TEXT NOT NULL,
                action TEXT NOT NULL,
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
            r#"
            CREATE TABLE IF NOT EXISTS geoip_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // --- Rule CRUD ---

    /// Insert a per-country block/allow rule row. pf tables aren't touched
    /// until the geo-IP rules are next applied
    pub async fn add(&self, rule: GeoIpRule) -> Result<GeoIpRule> {
        Self::insert_rule_on(&self.pool, &rule).await?;
        tracing::info!(id = %rule.id, country = %rule.country, action = %rule.action, "geo-ip rule added");
        Ok(rule)
    }

    /// Executor-generic insert. Public so the transactional restore path
    /// (#158/#535) can batch geo-IP rows with every other section.
    pub async fn insert_rule_on<'e, E>(exec: E, rule: &GeoIpRule) -> Result<()>
    where
        E: sqlx::Executor<'e, Database = sqlx::Sqlite>,
    {
        sqlx::query(
            r#"
            INSERT INTO geoip_rules (id, country, action, label, status, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            "#,
        )
        .bind(rule.id.to_string())
        .bind(&rule.country.0)
        .bind(rule.action.to_string())
        .bind(rule.label.as_deref())
        .bind(match rule.status {
            GeoIpRuleStatus::Active => "active",
            GeoIpRuleStatus::Disabled => "disabled",
        })
        .bind(rule.created_at.to_rfc3339())
        .bind(rule.updated_at.to_rfc3339())
        .execute(exec)
        .await?;
        Ok(())
    }

    /// All geo-IP rules ordered by country code
    pub async fn list(&self) -> Result<Vec<GeoIpRule>> {
        let rows = sqlx::query_as::<_, GeoIpRuleRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {GEOIP_RULE_COLUMNS} FROM geoip_rules ORDER BY country ASC"
        )))
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(|r| r.into_rule()).collect()
    }

    /// Fetch a geo-IP rule by id. Fails with `NotFound` if it doesn't exist
    pub async fn get(&self, id: Uuid) -> Result<GeoIpRule> {
        let row = sqlx::query_as::<_, GeoIpRuleRow>(sqlx::AssertSqlSafe(format!(
            "SELECT {GEOIP_RULE_COLUMNS} FROM geoip_rules WHERE id = ?1"
        )))
        .bind(id.to_string())
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| AifwError::NotFound(format!("geo-ip rule {id} not found")))?;
        row.into_rule()
    }

    /// Update a geo-IP rule row. Fails with `NotFound` for an unknown id
    pub async fn update(&self, rule: &GeoIpRule) -> Result<()> {
        let result = sqlx::query(
            r#"UPDATE geoip_rules SET country = ?2, action = ?3, label = ?4, status = ?5, updated_at = ?6 WHERE id = ?1"#,
        )
        .bind(rule.id.to_string())
        .bind(&rule.country.0)
        .bind(rule.action.to_string())
        .bind(rule.label.as_deref())
        .bind(match rule.status {
            GeoIpRuleStatus::Active => "active",
            GeoIpRuleStatus::Disabled => "disabled",
        })
        .bind(chrono::Utc::now().to_rfc3339())
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!(
                "geo-ip rule {} not found",
                rule.id
            )));
        }
        tracing::info!(id = %rule.id, "geo-ip rule updated");
        Ok(())
    }

    /// Delete a geo-IP rule row. Fails with `NotFound` for an unknown id
    pub async fn delete(&self, id: Uuid) -> Result<()> {
        let result = sqlx::query("DELETE FROM geoip_rules WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("geo-ip rule {id} not found")));
        }
        tracing::info!(%id, "geo-ip rule deleted");
        Ok(())
    }

    // --- Database loading ---

    /// Load a GeoLite2 database from CSV files into the in-memory index.
    /// `blocks_csv` is the content of GeoLite2-Country-Blocks-IPv4.csv (or IPv6)
    /// `locations_csv` is the content of GeoLite2-Country-Locations-en.csv
    pub async fn load_database(&self, blocks_csv: &str, locations_csv: &str) -> Result<usize> {
        let locations = aifw_common::geoip::parse_geolite2_locations_csv(locations_csv);
        let blocks = aifw_common::geoip::parse_geolite2_blocks_csv(blocks_csv);

        let mut country_cidrs: HashMap<String, Vec<(IpAddr, u8)>> = HashMap::new();

        for (ip, prefix, geoname_id) in &blocks {
            if let Some(country) = locations.get(geoname_id) {
                country_cidrs
                    .entry(country.clone())
                    .or_default()
                    .push((*ip, *prefix));
            }
        }

        let total_entries: usize = country_cidrs.values().map(|v| v.len()).sum();

        // Aggregate CIDRs per country
        for cidrs in country_cidrs.values_mut() {
            *cidrs = aifw_common::geoip::aggregate_cidrs(std::mem::take(cidrs));
        }

        let aggregated: usize = country_cidrs.values().map(|v| v.len()).sum();

        tracing::info!(
            countries = country_cidrs.len(),
            total_entries,
            aggregated,
            "loaded geo-ip database"
        );

        // Build the lookup trie once. Cost is paid here (load time), not on
        // every per-packet / per-policy lookup.
        let mut lookup_table: IpNetworkTable<String> = IpNetworkTable::new();
        for (country, cidrs) in &country_cidrs {
            for &(addr, prefix) in cidrs {
                if let Some(net) = build_ip_network(addr, prefix) {
                    lookup_table.insert(net, country.clone());
                }
            }
        }

        self.index.store(Arc::new(GeoIpIndex {
            lookup_table,
            by_country: country_cidrs,
        }));
        Ok(aggregated)
    }

    /// Lookup which country an IP belongs to. O(W) longest-prefix match.
    pub async fn lookup(&self, ip: IpAddr) -> GeoIpLookupResult {
        let index = self.index.load();
        if let Some((net, country)) = index.lookup_table.longest_match(ip) {
            let (network_ip, prefix) = match net {
                IpNetwork::V4(n) => (IpAddr::V4(n.network_address()), n.netmask()),
                IpNetwork::V6(n) => (IpAddr::V6(n.network_address()), n.netmask()),
            };
            return GeoIpLookupResult {
                ip,
                country: Some(CountryCode(country.clone())),
                network: Some(format!("{network_ip}/{prefix}")),
            };
        }
        GeoIpLookupResult {
            ip,
            country: None,
            network: None,
        }
    }

    /// Get all CIDRs for a specific country
    pub async fn get_country_cidrs(&self, country: &str) -> Vec<(IpAddr, u8)> {
        let index = self.index.load();
        index
            .by_country
            .get(&country.to_uppercase())
            .cloned()
            .unwrap_or_default()
    }

    // --- Apply to pf ---

    /// Apply geo-ip rules: create pf tables per country and populate them
    pub async fn apply_rules(&self) -> Result<()> {
        let rules = self.list().await?;
        let active: Vec<_> = rules
            .iter()
            .filter(|r| r.status == GeoIpRuleStatus::Active)
            .collect();

        let mut pf_lines = Vec::new();

        for rule in &active {
            // Table definition
            pf_lines.push(rule.to_pf_table());
            // Block/allow rule
            pf_lines.push(rule.to_pf_rule());

            // Bulk-populate the table in a single pfctl invocation. The
            // previous per-CIDR add_table_entry was ~70k forks for a 'US'
            // rule. replace_table_entries pipes the whole list via stdin.
            let cidrs = self.get_country_cidrs(&rule.country.0).await;
            self.pf
                .replace_table_entries(&rule.table_name(), &cidrs)
                .await
                .map_err(|e| AifwError::Pf(e.to_string()))?;
        }

        tracing::info!(count = active.len(), "applying geo-ip rules to pf");

        self.pf
            .load_rules(&self.anchor, &pf_lines)
            .await
            .map_err(|e| AifwError::Pf(e.to_string()))?;

        Ok(())
    }

    /// Verify the pf anchor holds the geo-IP lines [`Self::apply_rules`]
    /// would render right now (#535 post-apply verification). Table
    /// *contents* aren't compared — only the table definitions and
    /// block/allow rules. Exact comparison on backends that echo loaded
    /// rules; emptiness invariant on real pfctl, which re-renders rules and
    /// omits table definitions from `-sr` (see `RuleEngine::verify_applied`).
    pub async fn verify_applied(&self) -> Result<()> {
        let rules = self.list().await?;
        let expected: Vec<String> = rules
            .iter()
            .filter(|r| r.status == GeoIpRuleStatus::Active)
            .flat_map(|r| [r.to_pf_table(), r.to_pf_rule()])
            .collect();
        let actual = self
            .pf
            .get_rules(&self.anchor)
            .await
            .map_err(|e| AifwError::Pf(e.to_string()))?;
        let mismatch = if self.pf.echoes_exact_rules() {
            actual != expected
        } else {
            actual.is_empty() != expected.is_empty()
        };
        if mismatch {
            return Err(AifwError::Pf(format!(
                "anchor {} holds {} geo-ip lines but {} were expected — pf does not match the database",
                self.anchor,
                actual.len(),
                expected.len()
            )));
        }
        Ok(())
    }

    /// Get database statistics
    pub async fn db_stats(&self) -> (usize, usize) {
        let index = self.index.load();
        let countries = index.by_country.len();
        let total: usize = index.by_country.values().map(|v| v.len()).sum();
        (countries, total)
    }
}

/// Build an `IpNetwork` from an (address, prefix) pair, returning `None` if
/// the prefix is out of range for the address family.
fn build_ip_network(addr: IpAddr, prefix: u8) -> Option<IpNetwork> {
    match addr {
        IpAddr::V4(v4) => Ipv4Network::new(v4, prefix).ok().map(IpNetwork::V4),
        IpAddr::V6(v6) => Ipv6Network::new(v6, prefix).ok().map(IpNetwork::V6),
    }
}

// --- Row types ---

/// Explicit column list for `GeoIpRuleRow` selects, in schema order. Replaces
/// `SELECT *` which triggers a sqlx-sqlite column-count panic and blocks
/// column pruning (#348).
const GEOIP_RULE_COLUMNS: &str = "id, country, action, label, status, created_at, updated_at";

#[derive(sqlx::FromRow)]
struct GeoIpRuleRow {
    id: String,
    country: String,
    action: String,
    label: Option<String>,
    status: String,
    created_at: String,
    updated_at: String,
}

impl GeoIpRuleRow {
    fn into_rule(self) -> Result<GeoIpRule> {
        Ok(GeoIpRule {
            id: Uuid::parse_str(&self.id)
                .map_err(|e| AifwError::Database(format!("invalid uuid: {e}")))?,
            country: CountryCode(self.country),
            action: GeoIpAction::parse(&self.action)?,
            label: self.label,
            status: match self.status.as_str() {
                "active" => GeoIpRuleStatus::Active,
                _ => GeoIpRuleStatus::Disabled,
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
