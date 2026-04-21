use aifw_common::ids::IdsAlert;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::RwLock;

use super::AlertOutput;

/// Estimated bytes per alert in memory (struct + strings + overhead).
///
/// IdsAlert has several Strings (signature_msg, protocol, classification),
/// Option<String>s (flow_id, payload_excerpt, analyst_notes), and an
/// Option<HashMap<String,String>> for metadata. Realistic average once a rule
/// source with metadata is loaded is ~1200 bytes, not 512. Under-estimating
/// meant the buffer was consuming 2–3× its configured limit before eviction.
const ALERT_ESTIMATED_BYTES: usize = 1200;

/// In-memory ring buffer for IDS alerts with configurable limits.
/// Replaces SQLite storage to avoid disk I/O on flash-based systems.
pub struct AlertBuffer {
    alerts: RwLock<VecDeque<IdsAlert>>,
    max_bytes: AtomicUsize,
    max_age_secs: AtomicUsize,
}

impl AlertBuffer {
    /// Create a new alert buffer.
    /// `max_mb` — maximum memory usage in megabytes (default 64).
    /// `max_age_secs` — maximum alert age in seconds (default 86400 = 24h).
    pub fn new(max_mb: usize, max_age_secs: usize) -> Self {
        Self {
            alerts: RwLock::new(VecDeque::new()),
            max_bytes: AtomicUsize::new(max_mb * 1024 * 1024),
            max_age_secs: AtomicUsize::new(max_age_secs),
        }
    }

    /// Update the max memory limit (in MB).
    pub fn set_max_mb(&self, mb: usize) {
        self.max_bytes.store(mb * 1024 * 1024, Ordering::Relaxed);
    }

    /// Update the max age limit (in seconds).
    pub fn set_max_age_secs(&self, secs: usize) {
        self.max_age_secs.store(secs, Ordering::Relaxed);
    }

    /// Get current limits.
    pub fn limits(&self) -> (usize, usize) {
        let max_bytes = self.max_bytes.load(Ordering::Relaxed);
        let max_age = self.max_age_secs.load(Ordering::Relaxed);
        (max_bytes / (1024 * 1024), max_age)
    }

    /// Add an alert, evicting oldest if limits exceeded.
    pub async fn push(&self, alert: IdsAlert) {
        let mut buf = self.alerts.write().await;
        buf.push_back(alert);

        let max_entries = self.max_bytes.load(Ordering::Relaxed) / ALERT_ESTIMATED_BYTES;
        while buf.len() > max_entries {
            buf.pop_front();
        }

        // Evict by age
        let max_age = self.max_age_secs.load(Ordering::Relaxed) as i64;
        if max_age > 0 {
            let cutoff = chrono::Utc::now() - chrono::Duration::seconds(max_age);
            while let Some(front) = buf.front() {
                if front.timestamp < cutoff {
                    buf.pop_front();
                } else {
                    break;
                }
            }
        }
    }

    /// Query alerts with optional filters, pagination, ordered newest-first.
    pub async fn query(
        &self,
        severity: Option<u8>,
        src_ip: Option<&str>,
        signature_id: Option<u32>,
        acknowledged: Option<bool>,
        classification: Option<&str>,
        limit: usize,
        offset: usize,
    ) -> Vec<IdsAlert> {
        let buf = self.alerts.read().await;
        let iter = buf.iter().rev().filter(|a| {
            if let Some(sev) = severity
                && a.severity.0 != sev
            {
                return false;
            }
            if let Some(ip) = src_ip
                && a.src_ip.to_string() != ip
            {
                return false;
            }
            if let Some(sid) = signature_id
                && a.signature_id != Some(sid)
            {
                return false;
            }
            if let Some(ack) = acknowledged
                && a.acknowledged != ack
            {
                return false;
            }
            if let Some(cls) = classification {
                if cls == "reviewed" {
                    if a.classification == "unreviewed" {
                        return false;
                    }
                } else if a.classification != cls {
                    return false;
                }
            }
            true
        });

        iter.skip(offset).take(limit).cloned().collect()
    }

    /// Get a single alert by ID.
    pub async fn get(&self, id: uuid::Uuid) -> Option<IdsAlert> {
        let buf = self.alerts.read().await;
        buf.iter().find(|a| a.id == id).cloned()
    }

    /// Classify an alert.
    pub async fn classify(
        &self,
        id: uuid::Uuid,
        classification: &str,
        notes: Option<&str>,
    ) -> bool {
        let mut buf = self.alerts.write().await;
        if let Some(alert) = buf.iter_mut().find(|a| a.id == id) {
            alert.classification = classification.to_string();
            if let Some(n) = notes {
                alert.analyst_notes = Some(n.to_string());
            }
            alert.acknowledged = true;
            true
        } else {
            false
        }
    }

    /// Classify all alerts with a given signature_id.
    pub async fn classify_by_signature(
        &self,
        sig_id: u32,
        classification: &str,
        notes: &str,
    ) -> usize {
        let mut buf = self.alerts.write().await;
        let mut count = 0;
        for alert in buf.iter_mut() {
            if alert.signature_id == Some(sig_id) && alert.classification == "unreviewed" {
                alert.classification = classification.to_string();
                alert.analyst_notes = Some(notes.to_string());
                alert.acknowledged = true;
                count += 1;
            }
        }
        count
    }

    /// Acknowledge an alert.
    pub async fn acknowledge(&self, id: uuid::Uuid) -> bool {
        let mut buf = self.alerts.write().await;
        if let Some(alert) = buf.iter_mut().find(|a| a.id == id) {
            alert.acknowledged = true;
            true
        } else {
            false
        }
    }

    /// Count alerts by severity.
    pub async fn count_by_severity(&self) -> std::collections::HashMap<u8, usize> {
        let buf = self.alerts.read().await;
        let mut counts = std::collections::HashMap::new();
        for a in buf.iter() {
            *counts.entry(a.severity.0).or_insert(0) += 1;
        }
        counts
    }

    /// Get usage statistics.
    pub async fn stats(&self) -> AlertBufferStats {
        let buf = self.alerts.read().await;
        let count = buf.len();
        let estimated_bytes = count * ALERT_ESTIMATED_BYTES;
        let max_bytes = self.max_bytes.load(Ordering::Relaxed);
        let oldest = buf.front().map(|a| a.timestamp);
        let newest = buf.back().map(|a| a.timestamp);
        let by_class = {
            let mut m = std::collections::HashMap::<String, usize>::new();
            for a in buf.iter() {
                *m.entry(a.classification.clone()).or_insert(0) += 1;
            }
            let mut v: Vec<(String, usize)> = m.into_iter().collect();
            v.sort_by(|a, b| b.1.cmp(&a.1));
            v
        };
        AlertBufferStats {
            count,
            estimated_mb: estimated_bytes as f64 / (1024.0 * 1024.0),
            max_mb: max_bytes as f64 / (1024.0 * 1024.0),
            usage_pct: if max_bytes > 0 {
                (estimated_bytes as f64 / max_bytes as f64 * 100.0).min(100.0)
            } else {
                0.0
            },
            oldest,
            newest,
            max_age_secs: self.max_age_secs.load(Ordering::Relaxed),
            by_classification: by_class,
        }
    }

    /// Trim buffer to current limits (call after changing settings).
    pub async fn trim(&self) {
        let mut buf = self.alerts.write().await;
        let max_entries = self.max_bytes.load(Ordering::Relaxed) / ALERT_ESTIMATED_BYTES;
        while buf.len() > max_entries {
            buf.pop_front();
        }
    }
}

/// Wrapper to use AlertBuffer as an AlertOutput in the pipeline.
pub struct MemoryOutput {
    buffer: Arc<AlertBuffer>,
}

impl MemoryOutput {
    pub fn new(buffer: Arc<AlertBuffer>) -> Self {
        Self { buffer }
    }
}

#[async_trait::async_trait]
impl AlertOutput for MemoryOutput {
    async fn emit(&self, alert: &IdsAlert) -> crate::Result<()> {
        self.buffer.push(alert.clone()).await;
        Ok(())
    }

    async fn flush(&self) -> crate::Result<()> {
        Ok(())
    }

    fn name(&self) -> &str {
        "memory"
    }
}

impl std::fmt::Debug for AlertBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (max_mb, max_age) = self.limits();
        f.debug_struct("AlertBuffer")
            .field("max_mb", &max_mb)
            .field("max_age_secs", &max_age)
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct AlertBufferStats {
    pub count: usize,
    pub estimated_mb: f64,
    pub max_mb: f64,
    pub usage_pct: f64,
    pub oldest: Option<chrono::DateTime<chrono::Utc>>,
    pub newest: Option<chrono::DateTime<chrono::Utc>>,
    pub max_age_secs: usize,
    pub by_classification: Vec<(String, usize)>,
}

impl AlertBufferStats {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "count": self.count,
            "estimated_mb": (self.estimated_mb * 10.0).round() / 10.0,
            "max_mb": self.max_mb,
            "usage_pct": (self.usage_pct * 10.0).round() / 10.0,
            "oldest": self.oldest.map(|t| t.to_rfc3339()),
            "newest": self.newest.map(|t| t.to_rfc3339()),
            "max_age_secs": self.max_age_secs,
            "by_classification": self.by_classification.iter()
                .map(|(k, v)| serde_json::json!({"classification": k, "count": v}))
                .collect::<Vec<_>>(),
        })
    }
}
