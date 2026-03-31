use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// A named alias grouping IPs, networks, ports, or URLs for use in firewall rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alias {
    pub id: Uuid,
    pub name: String,
    pub alias_type: AliasType,
    pub entries: Vec<String>,
    pub description: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Type of entries an alias contains.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AliasType {
    /// Individual IP addresses.
    Host,
    /// CIDR networks.
    Network,
    /// Port numbers and ranges.
    Port,
    /// URL that returns a list of IPs (auto-updated).
    UrlTable,
}

impl AliasType {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "host" => Some(Self::Host),
            "network" => Some(Self::Network),
            "port" => Some(Self::Port),
            "url_table" | "urltable" | "url" => Some(Self::UrlTable),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Network => "network",
            Self::Port => "port",
            Self::UrlTable => "url_table",
        }
    }
}

impl std::fmt::Display for AliasType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
