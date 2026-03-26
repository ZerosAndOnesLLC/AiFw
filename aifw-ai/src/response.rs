use aifw_pf::PfBackend;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::types::{Threat, ThreatType};

/// Response action to take when a threat is detected
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ResponseAction {
    /// Log the threat but take no action
    Alert,
    /// Add source IP to a rate-limit table
    RateLimit,
    /// Block the source IP temporarily
    TempBlock,
    /// Block the source IP permanently
    PermBlock,
}

impl std::fmt::Display for ResponseAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResponseAction::Alert => write!(f, "alert"),
            ResponseAction::RateLimit => write!(f, "rate_limit"),
            ResponseAction::TempBlock => write!(f, "temp_block"),
            ResponseAction::PermBlock => write!(f, "perm_block"),
        }
    }
}

/// Configuration for auto-response behavior
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseConfig {
    /// Minimum score to trigger any response
    pub alert_threshold: f64,
    /// Score threshold for rate limiting
    pub rate_limit_threshold: f64,
    /// Score threshold for temporary block
    pub temp_block_threshold: f64,
    /// Score threshold for permanent block
    pub perm_block_threshold: f64,
    /// Duration of temporary blocks in seconds
    pub temp_block_duration_secs: u64,
    /// pf table for blocked IPs
    pub block_table: String,
    /// pf table for rate-limited IPs
    pub ratelimit_table: String,
    /// Per-threat-type overrides
    pub overrides: HashMap<ThreatType, f64>,
}

impl Default for ResponseConfig {
    fn default() -> Self {
        Self {
            alert_threshold: 0.3,
            rate_limit_threshold: 0.5,
            temp_block_threshold: 0.7,
            perm_block_threshold: 0.95,
            temp_block_duration_secs: 3600,
            block_table: "ai_blocked".to_string(),
            ratelimit_table: "ai_ratelimit".to_string(),
            overrides: HashMap::new(),
        }
    }
}

/// A temporary block with expiry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TempBlock {
    pub ip: IpAddr,
    pub threat_id: Uuid,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub reason: String,
}

/// Auto-response engine — evaluates threats and takes action
pub struct AutoResponder {
    pf: Arc<dyn PfBackend>,
    config: ResponseConfig,
    temp_blocks: Arc<RwLock<Vec<TempBlock>>>,
    /// History of all responses taken
    history: Arc<RwLock<Vec<ResponseRecord>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseRecord {
    pub threat_id: Uuid,
    pub threat_type: ThreatType,
    pub source_ip: IpAddr,
    pub score: f64,
    pub action: ResponseAction,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

impl AutoResponder {
    pub fn new(pf: Arc<dyn PfBackend>, config: ResponseConfig) -> Self {
        Self {
            pf,
            config,
            temp_blocks: Arc::new(RwLock::new(Vec::new())),
            history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// Determine the appropriate response action for a threat score
    pub fn determine_action(&self, threat: &Threat) -> ResponseAction {
        let threshold = self
            .config
            .overrides
            .get(&threat.threat_type)
            .copied()
            .unwrap_or(self.config.alert_threshold);

        let score = threat.score.value();

        if score >= self.config.perm_block_threshold {
            ResponseAction::PermBlock
        } else if score >= self.config.temp_block_threshold {
            ResponseAction::TempBlock
        } else if score >= self.config.rate_limit_threshold {
            ResponseAction::RateLimit
        } else if score >= threshold {
            ResponseAction::Alert
        } else {
            ResponseAction::Alert
        }
    }

    /// Process a detected threat and execute the response
    pub async fn respond(&self, threat: &Threat) -> ResponseAction {
        let action = self.determine_action(threat);

        match &action {
            ResponseAction::Alert => {
                tracing::warn!(
                    threat_type = %threat.threat_type,
                    score = %threat.score,
                    source = %threat.source_ip,
                    "threat detected (alert only)"
                );
            }
            ResponseAction::RateLimit => {
                tracing::warn!(
                    threat_type = %threat.threat_type,
                    score = %threat.score,
                    source = %threat.source_ip,
                    "rate limiting threat source"
                );
                let _ = self
                    .pf
                    .add_table_entry(&self.config.ratelimit_table, threat.source_ip)
                    .await;
            }
            ResponseAction::TempBlock => {
                let expires = Utc::now()
                    + Duration::seconds(self.config.temp_block_duration_secs as i64);

                tracing::warn!(
                    threat_type = %threat.threat_type,
                    score = %threat.score,
                    source = %threat.source_ip,
                    expires = %expires,
                    "temporarily blocking threat source"
                );

                let _ = self
                    .pf
                    .add_table_entry(&self.config.block_table, threat.source_ip)
                    .await;

                self.temp_blocks.write().await.push(TempBlock {
                    ip: threat.source_ip,
                    threat_id: threat.id,
                    expires_at: expires,
                    reason: threat.description.clone(),
                });
            }
            ResponseAction::PermBlock => {
                tracing::error!(
                    threat_type = %threat.threat_type,
                    score = %threat.score,
                    source = %threat.source_ip,
                    "permanently blocking threat source"
                );
                let _ = self
                    .pf
                    .add_table_entry(&self.config.block_table, threat.source_ip)
                    .await;
            }
        }

        // Record the response
        self.history.write().await.push(ResponseRecord {
            threat_id: threat.id,
            threat_type: threat.threat_type,
            source_ip: threat.source_ip,
            score: threat.score.value(),
            action: action.clone(),
            timestamp: Utc::now(),
        });

        action
    }

    /// Remove expired temporary blocks
    pub async fn expire_temp_blocks(&self) -> usize {
        let now = Utc::now();
        let mut blocks = self.temp_blocks.write().await;
        let before = blocks.len();

        let mut expired_ips = Vec::new();
        blocks.retain(|b| {
            if b.expires_at <= now {
                expired_ips.push(b.ip);
                false
            } else {
                true
            }
        });

        for ip in &expired_ips {
            let _ = self
                .pf
                .remove_table_entry(&self.config.block_table, *ip)
                .await;
            tracing::info!(%ip, "expired temporary block removed");
        }

        before - blocks.len()
    }

    /// Get all active temporary blocks
    pub async fn active_temp_blocks(&self) -> Vec<TempBlock> {
        self.temp_blocks.read().await.clone()
    }

    /// Get response history
    pub async fn history(&self) -> Vec<ResponseRecord> {
        self.history.read().await.clone()
    }

    pub fn config(&self) -> &ResponseConfig {
        &self.config
    }
}
