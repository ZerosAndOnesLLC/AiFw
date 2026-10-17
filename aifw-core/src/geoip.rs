use aifw_common::{
    AifwError, CountryCode, GeoIpAction, GeoIpLookupResult, GeoIpRule, GeoIpRuleStatus, Result,
};
use aifw_pf::PfBackend;
use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use ip_network::{IpNetwork, Ipv4Network, Ipv6Network};
use ip_network_table::IpNetworkTable;
use serde::Serialize;
use sqlx::sqlite::SqlitePool;
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use uuid::Uuid;

/// GeoLite2 Country CSV file names, as MaxMind ships them.
pub const BLOCKS_V4_FILE: &str = "GeoLite2-Country-Blocks-IPv4.csv";
/// IPv6 blocks file name.
pub const BLOCKS_V6_FILE: &str = "GeoLite2-Country-Blocks-IPv6.csv";
/// Locations (geoname → country) file name.
pub const LOCATIONS_FILE: &str = "GeoLite2-Country-Locations-en.csv";
/// Largest archive / CSV upload accepted (the real GeoLite2 Country zip is ~6 MB).
pub const MAX_ARCHIVE_BYTES: usize = 64 * 1024 * 1024;
/// Default refresh cadence: weekly, like pfBlockerNG / OPNsense GeoIP updates.
pub const DEFAULT_UPDATE_INTERVAL_HOURS: u32 = 168;
/// After a failed refresh, wait this long before trying again.
const RETRY_AFTER_FAILURE_HOURS: i64 = 6;

// geoip_config keys
const CFG_DB_PATH: &str = "db_path";
const CFG_LICENSE_KEY: &str = "license_key";
const CFG_INTERVAL: &str = "update_interval_hours";
const CFG_SOURCE: &str = "db_source";
const CFG_UPDATED_AT: &str = "db_updated_at";
const CFG_LAST_ATTEMPT: &str = "last_refresh_attempt";
const CFG_LAST_ERROR: &str = "last_error";

/// State of the GeoLite2 database behind the engine, for the UI / CLI.
#[derive(Debug, Clone, Serialize)]
pub struct GeoIpDbStatus {
    /// An index is loaded in memory
    pub loaded: bool,
    /// Countries in the index
    pub countries: usize,
    /// Aggregated CIDRs in the index
    pub cidrs: usize,
    /// Directory holding the CSV files
    pub db_path: String,
    /// Where the current files came from: `maxmind` (download) or `upload`
    pub source: Option<String>,
    /// When the current files were written
    pub updated_at: Option<DateTime<Utc>>,
    /// When a download was last attempted
    pub last_refresh_attempt: Option<DateTime<Utc>>,
    /// Why the last download failed, if it did
    pub last_error: Option<String>,
    /// Scheduled refresh cadence; 0 disables
    pub update_interval_hours: u32,
    /// When the scheduler will next download (needs a license key)
    pub next_refresh: Option<DateTime<Utc>>,
    /// A MaxMind license key is stored (value never returned)
    pub has_license_key: bool,
}

/// A rule plus the size of the country's CIDR set in the loaded index.
#[derive(Debug, Clone, Serialize)]
pub struct GeoIpRuleView {
    /// The stored rule
    #[serde(flatten)]
    pub rule: GeoIpRule,
    /// pf table the rule reads
    pub table: String,
    /// CIDRs the loaded database holds for this country (0 = nothing to
    /// block until the database is loaded or the code is unknown)
    pub cidr_count: usize,
}

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

    /// The database pool behind the engine.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
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
        Self::validate(&rule)?;
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

    /// Field checks every write path shares (#194): the country code must
    /// be a real ISO 3166-1 alpha-2 code and the label must be pf-safe.
    pub fn validate(rule: &GeoIpRule) -> Result<()> {
        // Re-run the shape check even for values built from the type — a
        // deserialised snapshot can carry anything.
        CountryCode::new(&rule.country.0)?;
        if let Some(label) = rule.label.as_deref() {
            crate::validation::validate_label(label)?;
        }
        Ok(())
    }

    /// Update a geo-IP rule row. Fails with `NotFound` for an unknown id
    pub async fn update(&self, rule: &GeoIpRule) -> Result<()> {
        Self::validate(rule)?;
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

    /// Delete a geo-IP rule row. Fails with `NotFound` for an unknown id.
    /// The country's pf table is emptied unless another rule still uses it.
    pub async fn delete(&self, id: Uuid) -> Result<()> {
        let rule = self.get(id).await?;
        let result = sqlx::query("DELETE FROM geoip_rules WHERE id = ?1")
            .bind(id.to_string())
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(AifwError::NotFound(format!("geo-ip rule {id} not found")));
        }
        tracing::info!(%id, "geo-ip rule deleted");
        let still_used = self
            .list()
            .await?
            .iter()
            .any(|r| r.country == rule.country && r.status == GeoIpRuleStatus::Active);
        if !still_used && let Err(e) = self.pf.flush_table(&rule.table_name()).await {
            tracing::warn!(table = %rule.table_name(), error = %e, "geo-ip table flush failed");
        }
        Ok(())
    }

    // --- Configuration ---

    async fn config_get(&self, key: &str) -> Result<Option<String>> {
        let row: Option<(String,)> =
            sqlx::query_as("SELECT value FROM geoip_config WHERE key = ?1")
                .bind(key)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(v,)| v))
    }

    async fn config_set(&self, key: &str, value: Option<&str>) -> Result<()> {
        match value {
            Some(v) => {
                sqlx::query(
                    "INSERT INTO geoip_config (key, value) VALUES (?1, ?2) \
                     ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                )
                .bind(key)
                .bind(v)
                .execute(&self.pool)
                .await?;
            }
            None => {
                sqlx::query("DELETE FROM geoip_config WHERE key = ?1")
                    .bind(key)
                    .execute(&self.pool)
                    .await?;
            }
        }
        Ok(())
    }

    async fn config_time(&self, key: &str) -> Result<Option<DateTime<Utc>>> {
        Ok(self
            .config_get(key)
            .await?
            .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
            .map(|t| t.with_timezone(&Utc)))
    }

    /// Directory the GeoLite2 CSV files live in: `db_path` from
    /// `geoip_config`, else `<db dir>/geoip` next to the secrets key
    /// (`/var/db/aifw/geoip` on an appliance, a scratch dir in dev).
    pub async fn db_dir(&self) -> PathBuf {
        match self.config_get(CFG_DB_PATH).await {
            Ok(Some(p)) if !p.is_empty() => PathBuf::from(p),
            _ => crate::secrets::key_path()
                .parent()
                .map(|d| d.join("geoip"))
                .unwrap_or_else(|| PathBuf::from("/var/db/aifw/geoip")),
        }
    }

    /// Override the database directory (tests, unusual layouts).
    pub async fn set_db_dir(&self, dir: &Path) -> Result<()> {
        self.config_set(CFG_DB_PATH, Some(&dir.display().to_string()))
            .await
    }

    /// The stored MaxMind license key (plaintext), if any.
    pub async fn license_key(&self) -> Result<Option<String>> {
        let stored = self.config_get(CFG_LICENSE_KEY).await?;
        Ok(crate::secrets::open_opt(stored)
            .map_err(crate::secrets::to_common)?
            .filter(|k| !k.is_empty()))
    }

    /// Store (sealed) or clear the MaxMind license key.
    pub async fn set_license_key(&self, key: Option<&str>) -> Result<()> {
        let key = key.map(str::trim).filter(|k| !k.is_empty());
        if let Some(k) = key
            && (k.len() > 128 || !k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'))
        {
            return Err(AifwError::Validation(
                "license key must be alphanumeric (MaxMind keys are 40 characters)".into(),
            ));
        }
        let sealed = match key {
            Some(k) => Some(crate::secrets::seal(k).map_err(crate::secrets::to_common)?),
            None => None,
        };
        self.config_set(CFG_LICENSE_KEY, sealed.as_deref()).await
    }

    /// Scheduled refresh cadence in hours (0 = off).
    pub async fn update_interval_hours(&self) -> Result<u32> {
        Ok(self
            .config_get(CFG_INTERVAL)
            .await?
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_UPDATE_INTERVAL_HOURS))
    }

    /// Set the scheduled refresh cadence (0 disables, max 90 days).
    pub async fn set_update_interval_hours(&self, hours: u32) -> Result<()> {
        if hours > 24 * 90 {
            return Err(AifwError::Validation(
                "update interval must be at most 2160 hours (90 days)".into(),
            ));
        }
        self.config_set(CFG_INTERVAL, Some(&hours.to_string()))
            .await
    }

    /// Record the outcome of a download attempt (`Ok` = files replaced).
    pub async fn record_refresh(&self, result: std::result::Result<(), String>) -> Result<()> {
        self.config_set(CFG_LAST_ATTEMPT, Some(&Utc::now().to_rfc3339()))
            .await?;
        self.config_set(CFG_LAST_ERROR, result.as_ref().err().map(String::as_str))
            .await
    }

    /// When the scheduler should next download: `None` when disabled or
    /// without a key. A failed attempt is retried after a few hours rather
    /// than hammering MaxMind.
    pub async fn next_refresh(&self) -> Result<Option<DateTime<Utc>>> {
        let hours = self.update_interval_hours().await?;
        if hours == 0 || self.license_key().await?.is_none() {
            return Ok(None);
        }
        let updated = self.config_time(CFG_UPDATED_AT).await?;
        let attempt = self.config_time(CFG_LAST_ATTEMPT).await?;
        let failed = self.config_get(CFG_LAST_ERROR).await?.is_some();
        let mut due = match updated {
            Some(t) => t + chrono::Duration::hours(i64::from(hours)),
            None => Utc::now(),
        };
        if failed && let Some(a) = attempt {
            due = due.max(a + chrono::Duration::hours(RETRY_AFTER_FAILURE_HOURS));
        }
        Ok(Some(due))
    }

    /// Whether the scheduler should download now.
    pub async fn refresh_due(&self) -> Result<bool> {
        Ok(self
            .next_refresh()
            .await?
            .is_some_and(|due| due <= Utc::now()))
    }

    /// MaxMind download URL for the GeoLite2 Country CSV edition. Carries
    /// the key, so never log it.
    pub fn maxmind_url(license_key: &str) -> String {
        format!(
            "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key={license_key}&suffix=zip"
        )
    }

    /// Database status for the UI / CLI.
    pub async fn status(&self) -> Result<GeoIpDbStatus> {
        let (countries, cidrs) = self.db_stats().await;
        Ok(GeoIpDbStatus {
            loaded: countries > 0,
            countries,
            cidrs,
            db_path: self.db_dir().await.display().to_string(),
            source: self.config_get(CFG_SOURCE).await?,
            updated_at: self.config_time(CFG_UPDATED_AT).await?,
            last_refresh_attempt: self.config_time(CFG_LAST_ATTEMPT).await?,
            last_error: self.config_get(CFG_LAST_ERROR).await?,
            update_interval_hours: self.update_interval_hours().await?,
            next_refresh: self.next_refresh().await?,
            has_license_key: self.license_key().await?.is_some(),
        })
    }

    // --- Database loading ---

    /// Load a GeoLite2 database from CSV contents into the in-memory index.
    /// `blocks_csv` is GeoLite2-Country-Blocks-IPv4.csv (or IPv6), and
    /// `locations_csv` is GeoLite2-Country-Locations-en.csv. Returns the
    /// aggregated CIDR count.
    pub async fn load_database(&self, blocks_csv: &str, locations_csv: &str) -> Result<usize> {
        self.load_csv_parts(&[blocks_csv], locations_csv).await
    }

    /// Parse any number of blocks files (v4 and v6) plus the locations
    /// file into an index, off the async threads. Nothing is installed.
    async fn build_csv_parts(blocks: &[&str], locations_csv: &str) -> Result<GeoIpIndex> {
        let blocks: Vec<String> = blocks.iter().map(|b| b.to_string()).collect();
        let locations_csv = locations_csv.to_string();
        tokio::task::spawn_blocking(move || build_index(&blocks, &locations_csv))
            .await
            .map_err(|e| AifwError::Other(format!("geo-ip index build task failed: {e}")))
    }

    /// Build and install an index; returns the aggregated CIDR count.
    async fn load_csv_parts(&self, blocks: &[&str], locations_csv: &str) -> Result<usize> {
        let built = Self::build_csv_parts(blocks, locations_csv).await?;
        Ok(self.install_index(built))
    }

    fn install_index(&self, built: GeoIpIndex) -> usize {
        let aggregated: usize = built.by_country.values().map(|v| v.len()).sum();
        tracing::info!(
            countries = built.by_country.len(),
            aggregated,
            "loaded geo-ip database"
        );
        self.index.store(Arc::new(built));
        aggregated
    }

    /// Load the CSV files from the database directory, if present. `Ok(None)`
    /// when there is nothing to load yet (fresh install).
    pub async fn load_from_dir(&self) -> Result<Option<usize>> {
        let dir = self.db_dir().await;
        let read = |name: &str| {
            let p = dir.join(name);
            async move {
                match tokio::fs::read_to_string(&p).await {
                    Ok(s) => Ok(Some(s)),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(e) => Err(AifwError::Other(format!("{}: {e}", p.display()))),
                }
            }
        };
        let (v4, v6, loc) = tokio::try_join!(
            read(BLOCKS_V4_FILE),
            read(BLOCKS_V6_FILE),
            read(LOCATIONS_FILE)
        )?;
        let Some(loc) = loc else {
            return Ok(None);
        };
        let blocks: Vec<&str> = [v4.as_deref(), v6.as_deref()]
            .into_iter()
            .flatten()
            .collect();
        if blocks.is_empty() {
            return Ok(None);
        }
        Ok(Some(self.load_csv_parts(&blocks, &loc).await?))
    }

    /// Install a GeoLite2 Country CSV release from a MaxMind zip archive:
    /// the three CSVs are written into the database directory and the
    /// index reloaded. `source` is recorded for the status view.
    pub async fn import_archive(&self, archive: Vec<u8>, source: &str) -> Result<usize> {
        if archive.len() > MAX_ARCHIVE_BYTES {
            return Err(AifwError::Validation(format!(
                "archive larger than {} MB",
                MAX_ARCHIVE_BYTES / (1024 * 1024)
            )));
        }
        let files = tokio::task::spawn_blocking(move || extract_geolite2_zip(&archive))
            .await
            .map_err(|e| AifwError::Other(format!("archive extraction task failed: {e}")))??;
        self.import_csv_files(files, source).await
    }

    /// Install CSV files given directly (name → contents). The locations
    /// file and at least one blocks file are required; other names are
    /// refused.
    pub async fn import_csv_files(
        &self,
        files: HashMap<String, String>,
        source: &str,
    ) -> Result<usize> {
        let allowed = [BLOCKS_V4_FILE, BLOCKS_V6_FILE, LOCATIONS_FILE];
        if let Some(bad) = files.keys().find(|k| !allowed.contains(&k.as_str())) {
            return Err(AifwError::Validation(format!(
                "unexpected file '{bad}'; expected {}",
                allowed.join(", ")
            )));
        }
        if !files.contains_key(LOCATIONS_FILE)
            || !(files.contains_key(BLOCKS_V4_FILE) || files.contains_key(BLOCKS_V6_FILE))
        {
            return Err(AifwError::Validation(format!(
                "a GeoLite2 Country CSV release needs {LOCATIONS_FILE} and at least one of {BLOCKS_V4_FILE} / {BLOCKS_V6_FILE}"
            )));
        }
        // Validate before touching disk or the live index: a release that
        // parses to nothing must not replace a working one.
        let blocks: Vec<&str> = [BLOCKS_V4_FILE, BLOCKS_V6_FILE]
            .iter()
            .filter_map(|n| files.get(*n).map(String::as_str))
            .collect();
        let built = Self::build_csv_parts(&blocks, &files[LOCATIONS_FILE]).await?;
        if built.by_country.is_empty() {
            return Err(AifwError::Validation(
                "the files parsed to zero networks; is this a GeoLite2 *Country* CSV release?"
                    .into(),
            ));
        }
        let dir = self.db_dir().await;
        tokio::fs::create_dir_all(&dir)
            .await
            .map_err(|e| AifwError::Other(format!("{}: {e}", dir.display())))?;
        for name in allowed {
            let target = dir.join(name);
            match files.get(name) {
                Some(content) => {
                    let tmp = dir.join(format!(".{name}.tmp"));
                    tokio::fs::write(&tmp, content)
                        .await
                        .map_err(|e| AifwError::Other(format!("{}: {e}", tmp.display())))?;
                    tokio::fs::rename(&tmp, &target)
                        .await
                        .map_err(|e| AifwError::Other(format!("{}: {e}", target.display())))?;
                }
                None => {
                    if let Err(e) = tokio::fs::remove_file(&target).await
                        && e.kind() != std::io::ErrorKind::NotFound
                    {
                        tracing::warn!(path = %target.display(), error = %e, "geo-ip: stale file not removed");
                    }
                }
            }
        }
        let count = self.install_index(built);
        self.config_set(CFG_SOURCE, Some(source)).await?;
        self.config_set(CFG_UPDATED_AT, Some(&Utc::now().to_rfc3339()))
            .await?;
        self.config_set(CFG_LAST_ERROR, None).await?;
        tracing::info!(%source, cidrs = count, dir = %dir.display(), "geo-ip database installed");
        Ok(count)
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

    /// Rules with the size of each country's CIDR set in the loaded index.
    pub async fn list_views(&self) -> Result<Vec<GeoIpRuleView>> {
        let index = self.index.load();
        Ok(self
            .list()
            .await?
            .into_iter()
            .map(|rule| GeoIpRuleView {
                table: rule.table_name(),
                cidr_count: index.by_country.get(&rule.country.0).map_or(0, Vec::len),
                rule,
            })
            .collect())
    }

    /// Cheap change marker for the rules table, so a background loop can
    /// re-apply when the CLI or a restore wrote rules behind the API's back.
    pub async fn rules_fingerprint(&self) -> Result<String> {
        let row: (i64, Option<String>) =
            sqlx::query_as("SELECT COUNT(*), MAX(updated_at) FROM geoip_rules")
                .fetch_one(&self.pool)
                .await?;
        Ok(format!("{}:{}", row.0, row.1.unwrap_or_default()))
    }

    // --- Apply to pf ---

    /// Apply geo-ip rules: fill one root pf table per active country and
    /// load the block/allow rules into the anchor. Tables of disabled
    /// rules are emptied. The anchor never defines the tables itself (#704).
    pub async fn apply_rules(&self) -> Result<()> {
        let rules = self.list().await?;
        let mut pf_lines = Vec::new();
        let mut filled: Vec<String> = Vec::new();

        for rule in rules.iter().filter(|r| r.status == GeoIpRuleStatus::Active) {
            let table = rule.table_name();
            if !filled.contains(&table) {
                // Bulk-populate the root table in a single pfctl invocation.
                // An unknown country or an unloaded database yields an
                // empty table; the rule still loads and matches nothing.
                let cidrs = self.get_country_cidrs(&rule.country.0).await;
                self.pf
                    .replace_table_entries(&table, &cidrs)
                    .await
                    .map_err(|e| AifwError::Pf(e.to_string()))?;
                filled.push(table);
            }
            pf_lines.push(rule.to_pf_rule());
        }
        for rule in rules.iter().filter(|r| r.status != GeoIpRuleStatus::Active) {
            let table = rule.table_name();
            if !filled.contains(&table)
                && let Err(e) = self.pf.flush_table(&table).await
            {
                tracing::debug!(%table, error = %e, "geo-ip: disabled rule table flush");
            }
        }

        tracing::info!(count = pf_lines.len(), "applying geo-ip rules to pf");

        if pf_lines.is_empty() {
            self.pf
                .flush_rules(&self.anchor)
                .await
                .map_err(|e| AifwError::Pf(e.to_string()))?;
        } else {
            self.pf
                .load_rules(&self.anchor, &pf_lines)
                .await
                .map_err(|e| AifwError::Pf(e.to_string()))?;
        }

        Ok(())
    }

    /// Verify the pf anchor holds the geo-IP rules [`Self::apply_rules`]
    /// would render right now (#535 post-apply verification). Table
    /// *contents* aren't compared. Exact comparison on backends that echo
    /// loaded rules; emptiness invariant on real pfctl, which re-renders
    /// rules (see `RuleEngine::verify_applied`).
    pub async fn verify_applied(&self) -> Result<()> {
        let rules = self.list().await?;
        let expected: Vec<String> = rules
            .iter()
            .filter(|r| r.status == GeoIpRuleStatus::Active)
            .map(GeoIpRule::to_pf_rule)
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

/// Parse blocks + locations CSVs into an index (blocking: hundreds of
/// thousands of lines for the real release).
fn build_index(blocks: &[String], locations_csv: &str) -> GeoIpIndex {
    let locations = aifw_common::geoip::parse_geolite2_locations_csv(locations_csv);
    let mut country_cidrs: HashMap<String, Vec<(IpAddr, u8)>> = HashMap::new();
    for csv in blocks {
        for (ip, prefix, geoname_id) in aifw_common::geoip::parse_geolite2_blocks_csv(csv) {
            if let Some(country) = locations.get(&geoname_id) {
                country_cidrs
                    .entry(country.clone())
                    .or_default()
                    .push((ip, prefix));
            }
        }
    }
    for cidrs in country_cidrs.values_mut() {
        *cidrs = aifw_common::geoip::aggregate_cidrs(std::mem::take(cidrs));
    }
    let mut lookup_table: IpNetworkTable<String> = IpNetworkTable::new();
    for (country, cidrs) in &country_cidrs {
        for &(addr, prefix) in cidrs {
            if let Some(net) = build_ip_network(addr, prefix) {
                lookup_table.insert(net, country.clone());
            }
        }
    }
    GeoIpIndex {
        lookup_table,
        by_country: country_cidrs,
    }
}

/// Pull the three Country CSVs out of a MaxMind zip (they sit under a
/// `GeoLite2-Country-CSV_YYYYMMDD/` directory). Other entries are ignored;
/// each CSV is capped at the archive limit.
pub fn extract_geolite2_zip(bytes: &[u8]) -> Result<HashMap<String, String>> {
    use std::io::Read;
    let cursor = std::io::Cursor::new(bytes);
    let mut zip = zip::ZipArchive::new(cursor)
        .map_err(|e| AifwError::Validation(format!("not a zip archive: {e}")))?;
    let wanted = [BLOCKS_V4_FILE, BLOCKS_V6_FILE, LOCATIONS_FILE];
    let mut out = HashMap::new();
    for i in 0..zip.len() {
        let entry = zip
            .by_index(i)
            .map_err(|e| AifwError::Validation(format!("corrupt zip entry: {e}")))?;
        let raw = entry
            .name()
            .map_err(|e| AifwError::Validation(format!("corrupt zip entry name: {e}")))?
            .to_string();
        let Some(name) = Path::new(&raw)
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
        else {
            continue;
        };
        if !wanted.contains(&name.as_str()) || entry.is_dir() {
            continue;
        }
        if entry.size() > MAX_ARCHIVE_BYTES as u64 {
            return Err(AifwError::Validation(format!("{name} is too large")));
        }
        let mut content = String::new();
        entry
            .take(MAX_ARCHIVE_BYTES as u64 + 1)
            .read_to_string(&mut content)
            .map_err(|e| AifwError::Validation(format!("{name}: {e}")))?;
        if content.len() > MAX_ARCHIVE_BYTES {
            return Err(AifwError::Validation(format!("{name} is too large")));
        }
        out.insert(name, content);
    }
    if out.is_empty() {
        return Err(AifwError::Validation(
            "archive holds no GeoLite2 Country CSV files".into(),
        ));
    }
    Ok(out)
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
