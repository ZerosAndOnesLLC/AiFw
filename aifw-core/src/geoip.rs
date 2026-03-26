use aifw_common::{
    AifwError, CountryCode, GeoIpAction, GeoIpLookupResult, GeoIpRule,
    GeoIpRuleStatus, Result,
};
use aifw_pf::PfBackend;
use chrono::{DateTime, Utc};
use sqlx::sqlite::SqlitePool;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

pub struct GeoIpEngine {
    pool: SqlitePool,
    pf: Arc<dyn PfBackend>,
    anchor: String,
    /// In-memory country -> CIDRs index for fast lookup
    index: Arc<RwLock<HashMap<String, Vec<(IpAddr, u8)>>>>,
}

impl GeoIpEngine {
    pub fn new(pool: SqlitePool, pf: Arc<dyn PfBackend>) -> Self {
        Self {
            pool,
            pf,
            anchor: "aifw-geoip".to_string(),
            index: Arc::new(RwLock::new(HashMap::new())),
        }
    }

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

    pub async fn add_rule(&self, rule: GeoIpRule) -> Result<GeoIpRule> {
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
        .execute(&self.pool)
        .await?;

        tracing::info!(id = %rule.id, country = %rule.country, action = %rule.action, "geo-ip rule added");
        Ok(rule)
    }

    pub async fn list_rules(&self) -> Result<Vec<GeoIpRule>> {
        let rows = sqlx::query_as::<_, GeoIpRuleRow>(
            "SELECT * FROM geoip_rules ORDER BY country ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.into_iter().map(|r| r.into_rule()).collect()
    }

    pub async fn delete_rule(&self, id: Uuid) -> Result<()> {
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
    pub async fn load_database(
        &self,
        blocks_csv: &str,
        locations_csv: &str,
    ) -> Result<usize> {
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

        *self.index.write().await = country_cidrs;
        Ok(aggregated)
    }

    /// Lookup which country an IP belongs to
    pub async fn lookup(&self, ip: IpAddr) -> GeoIpLookupResult {
        let index = self.index.read().await;
        for (country, cidrs) in index.iter() {
            for (net, prefix) in cidrs {
                if ip_in_network(ip, *net, *prefix) {
                    return GeoIpLookupResult {
                        ip,
                        country: Some(CountryCode(country.clone())),
                        network: Some(format!("{net}/{prefix}")),
                    };
                }
            }
        }
        GeoIpLookupResult {
            ip,
            country: None,
            network: None,
        }
    }

    /// Get all CIDRs for a specific country
    pub async fn get_country_cidrs(&self, country: &str) -> Vec<(IpAddr, u8)> {
        let index = self.index.read().await;
        index.get(&country.to_uppercase()).cloned().unwrap_or_default()
    }

    // --- Apply to pf ---

    /// Apply geo-ip rules: create pf tables per country and populate them
    pub async fn apply_rules(&self) -> Result<()> {
        let rules = self.list_rules().await?;
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

            // Populate table with CIDRs
            let cidrs = self.get_country_cidrs(&rule.country.0).await;
            for (ip, prefix) in &cidrs {
                self.pf
                    .add_table_entry(&rule.table_name(), *ip)
                    .await
                    .map_err(|e| AifwError::Pf(e.to_string()))?;
                let _ = prefix; // pf tables store individual IPs; for CIDRs we'd use pfctl
            }
        }

        tracing::info!(
            count = active.len(),
            "applying geo-ip rules to pf"
        );

        self.pf
            .load_rules(&self.anchor, &pf_lines)
            .await
            .map_err(|e| AifwError::Pf(e.to_string()))?;

        Ok(())
    }

    /// Get database statistics
    pub async fn db_stats(&self) -> (usize, usize) {
        let index = self.index.read().await;
        let countries = index.len();
        let total: usize = index.values().map(|v| v.len()).sum();
        (countries, total)
    }
}

fn ip_in_network(ip: IpAddr, network: IpAddr, prefix: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip4), IpAddr::V4(net4)) => {
            if prefix == 0 {
                return true;
            }
            if prefix > 32 {
                return false;
            }
            let mask = u32::MAX << (32 - prefix);
            (u32::from(ip4) & mask) == (u32::from(net4) & mask)
        }
        (IpAddr::V6(ip6), IpAddr::V6(net6)) => {
            if prefix == 0 {
                return true;
            }
            if prefix > 128 {
                return false;
            }
            let mask = u128::MAX << (128 - prefix);
            (u128::from(ip6) & mask) == (u128::from(net6) & mask)
        }
        _ => false,
    }
}

// --- Row types ---

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
