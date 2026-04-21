use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use uuid::Uuid;

/// ISO 3166-1 alpha-2 country code
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct CountryCode(pub String);

impl CountryCode {
    pub fn new(code: &str) -> crate::Result<Self> {
        let code = code.trim().to_uppercase();
        if code.len() != 2 || !code.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(crate::AifwError::Validation(format!(
                "invalid country code: {code} (must be 2 letter ISO 3166-1 alpha-2)"
            )));
        }
        Ok(CountryCode(code))
    }
}

impl std::fmt::Display for CountryCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Action for geo-IP rules
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GeoIpAction {
    Allow,
    Block,
}

impl std::fmt::Display for GeoIpAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GeoIpAction::Allow => write!(f, "allow"),
            GeoIpAction::Block => write!(f, "block"),
        }
    }
}

impl GeoIpAction {
    pub fn parse(s: &str) -> crate::Result<Self> {
        match s.to_lowercase().as_str() {
            "allow" | "pass" => Ok(GeoIpAction::Allow),
            "block" | "deny" => Ok(GeoIpAction::Block),
            _ => Err(crate::AifwError::Validation(format!(
                "unknown geo-ip action: {s}"
            ))),
        }
    }
}

/// A geo-IP filtering rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpRule {
    pub id: Uuid,
    pub country: CountryCode,
    pub action: GeoIpAction,
    pub label: Option<String>,
    pub status: GeoIpRuleStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum GeoIpRuleStatus {
    Active,
    Disabled,
}

impl GeoIpRule {
    pub fn new(country: CountryCode, action: GeoIpAction) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            country,
            action,
            label: None,
            status: GeoIpRuleStatus::Active,
            created_at: now,
            updated_at: now,
        }
    }

    /// Generate pf table name for this country
    pub fn table_name(&self) -> String {
        format!("geoip_{}", self.country.0.to_lowercase())
    }

    /// Generate pf table definition
    pub fn to_pf_table(&self) -> String {
        format!("table <{}> persist", self.table_name())
    }

    /// Generate pf rule for this country
    pub fn to_pf_rule(&self) -> String {
        let action = match self.action {
            GeoIpAction::Allow => "pass",
            GeoIpAction::Block => "block drop",
        };
        let default_label = format!("geoip-{}-{}", self.action, self.country);
        let label = self.label.as_deref().unwrap_or(&default_label);
        format!(
            "{action} in quick from <{}> label \"{label}\"",
            self.table_name()
        )
    }
}

/// A CIDR network entry from the GeoLite2 database
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GeoIpEntry {
    pub network: IpAddr,
    pub prefix: u8,
    pub country: CountryCode,
}

impl std::fmt::Display for GeoIpEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}

/// Geo-IP database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpDbConfig {
    /// Path to the GeoLite2 CSV directory
    pub db_path: String,
    /// Auto-update interval in hours (0 = disabled)
    pub update_interval_hours: u32,
    /// License key for MaxMind downloads (optional)
    pub license_key: Option<String>,
    /// Last update timestamp
    pub last_updated: Option<DateTime<Utc>>,
}

impl Default for GeoIpDbConfig {
    fn default() -> Self {
        Self {
            db_path: "/var/db/aifw/geoip".to_string(),
            update_interval_hours: 168, // weekly
            license_key: None,
            last_updated: None,
        }
    }
}

/// Lookup result for a single IP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoIpLookupResult {
    pub ip: IpAddr,
    pub country: Option<CountryCode>,
    pub network: Option<String>,
}

// ============================================================
// CIDR aggregation
// ============================================================

/// Aggregate a list of CIDR networks to reduce the number of pf table entries.
/// Adjacent and overlapping networks with the same prefix are merged.
pub fn aggregate_cidrs(mut entries: Vec<(IpAddr, u8)>) -> Vec<(IpAddr, u8)> {
    if entries.len() <= 1 {
        return entries;
    }

    // Sort by IP then prefix
    entries.sort_by(|a, b| {
        let cmp = ip_to_u128(a.0).cmp(&ip_to_u128(b.0));
        if cmp == std::cmp::Ordering::Equal {
            a.1.cmp(&b.1)
        } else {
            cmp
        }
    });

    // Remove entries that are already covered by a broader prefix
    let mut result: Vec<(IpAddr, u8)> = Vec::new();
    for entry in &entries {
        if let Some(last) = result.last()
            && is_subnet_of(entry.0, entry.1, last.0, last.1)
        {
            continue; // already covered
        }
        result.push(*entry);
    }

    // Try to merge adjacent same-prefix networks
    let mut changed = true;
    while changed {
        changed = false;
        let mut merged = Vec::new();
        let mut i = 0;
        while i < result.len() {
            if i + 1 < result.len() && result[i].1 == result[i + 1].1 && result[i].1 > 0 {
                let prefix = result[i].1;
                let a_val = ip_to_u128(result[i].0);
                let b_val = ip_to_u128(result[i + 1].0);
                let parent_mask = !((1u128 << (128 - prefix + 1)) - 1);
                if (a_val & parent_mask) == (b_val & parent_mask) {
                    // Can merge into parent
                    merged.push((
                        u128_to_ip(a_val & parent_mask, result[i].0.is_ipv4()),
                        prefix - 1,
                    ));
                    i += 2;
                    changed = true;
                    continue;
                }
            }
            merged.push(result[i]);
            i += 1;
        }
        result = merged;
    }

    result
}

/// Check if (child_ip/child_prefix) is a subnet of (parent_ip/parent_prefix)
fn is_subnet_of(child_ip: IpAddr, child_prefix: u8, parent_ip: IpAddr, parent_prefix: u8) -> bool {
    if child_prefix < parent_prefix {
        return false;
    }
    let mask = if parent_prefix == 0 {
        0u128
    } else {
        !((1u128 << (128 - parent_prefix)) - 1)
    };
    let child_val = ip_to_u128(child_ip);
    let parent_val = ip_to_u128(parent_ip);
    (child_val & mask) == (parent_val & mask)
}

fn ip_to_u128(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // Map IPv4 to the upper bits for consistent sorting
            ((octets[0] as u128) << 120)
                | ((octets[1] as u128) << 112)
                | ((octets[2] as u128) << 104)
                | ((octets[3] as u128) << 96)
        }
        IpAddr::V6(v6) => u128::from(v6),
    }
}

fn u128_to_ip(val: u128, is_v4: bool) -> IpAddr {
    if is_v4 {
        let a = ((val >> 120) & 0xFF) as u8;
        let b = ((val >> 112) & 0xFF) as u8;
        let c = ((val >> 104) & 0xFF) as u8;
        let d = ((val >> 96) & 0xFF) as u8;
        IpAddr::V4(std::net::Ipv4Addr::new(a, b, c, d))
    } else {
        IpAddr::V6(std::net::Ipv6Addr::from(val))
    }
}

/// Parse a GeoLite2 Country CSV blocks file.
/// Expected format: network,geoname_id,registered_country_geoname_id,...
/// Returns (network_ip, prefix, geoname_id)
pub fn parse_geolite2_blocks_csv(content: &str) -> Vec<(IpAddr, u8, u32)> {
    let mut results = Vec::new();
    for line in content.lines().skip(1) {
        // skip header
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 2 {
            continue;
        }
        let network_str = fields[0].trim();
        let geoname_str = fields[1].trim();

        if geoname_str.is_empty() {
            continue;
        }

        let geoname_id: u32 = match geoname_str.parse() {
            Ok(v) => v,
            Err(_) => continue,
        };

        if let Some((ip_str, prefix_str)) = network_str.split_once('/') {
            let ip: IpAddr = match ip_str.parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            let prefix: u8 = match prefix_str.parse() {
                Ok(v) => v,
                Err(_) => continue,
            };
            results.push((ip, prefix, geoname_id));
        }
    }
    results
}

/// Parse a GeoLite2 Country CSV locations file.
/// Expected format: geoname_id,locale_code,continent_code,...,country_iso_code,...
/// Returns (geoname_id, country_code)
pub fn parse_geolite2_locations_csv(content: &str) -> std::collections::HashMap<u32, String> {
    let mut map = std::collections::HashMap::new();
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split(',').collect();
        if fields.len() < 5 {
            continue;
        }
        let geoname_id: u32 = match fields[0].trim().parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let country_code = fields[4].trim().to_string();
        if country_code.len() == 2 {
            map.insert(geoname_id, country_code);
        }
    }
    map
}
