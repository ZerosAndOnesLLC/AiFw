use std::path::PathBuf;
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;

use aifw_common::ids::IdsAlert;

use super::AlertOutput;
use crate::Result;

/// EVE JSON file output — Suricata-compatible one-JSON-per-line format.
///
/// All file I/O is async via tokio::fs so emitting an alert never blocks
/// the runtime worker. Previously the std::sync::Mutex was held across
/// blocking writes; under disk pressure that stalled the whole alert
/// pipeline.
pub struct EveOutput {
    path: PathBuf,
    file: Mutex<Option<File>>,
    max_size: u64,
}

impl EveOutput {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            file: Mutex::new(None),
            max_size: 100 * 1024 * 1024, // 100MB default
        }
    }

    pub fn with_max_size(mut self, bytes: u64) -> Self {
        self.max_size = bytes;
        self
    }

    /// Open the file lazily on first write. Caller holds the lock.
    async fn ensure_open<'a>(
        &'a self,
        guard: &mut tokio::sync::MutexGuard<'a, Option<File>>,
    ) -> Result<()> {
        if guard.is_none() {
            if let Some(parent) = self.path.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .await?;
            **guard = Some(f);
        }
        Ok(())
    }

    /// Rotate the on-disk file when it exceeds `max_size`. Releases the
    /// open handle so the next emit reopens the fresh file.
    async fn check_rotation(&self) -> Result<()> {
        if let Ok(metadata) = tokio::fs::metadata(&self.path).await {
            if metadata.len() >= self.max_size {
                let rotated = self.path.with_extension("json.1");
                let _ = tokio::fs::remove_file(&rotated).await;
                let _ = tokio::fs::rename(&self.path, &rotated).await;
                let mut guard = self.file.lock().await;
                *guard = None;
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl AlertOutput for EveOutput {
    async fn emit(&self, alert: &IdsAlert) -> Result<()> {
        self.check_rotation().await?;

        let eve = serde_json::json!({
            "timestamp": alert.timestamp.to_rfc3339(),
            "event_type": "alert",
            "src_ip": alert.src_ip.to_string(),
            "src_port": alert.src_port,
            "dest_ip": alert.dst_ip.to_string(),
            "dest_port": alert.dst_port,
            "proto": alert.protocol,
            "alert": {
                "action": alert.action.to_string(),
                "gid": 1,
                "signature_id": alert.signature_id,
                "rev": 1,
                "signature": alert.signature_msg,
                "category": alert.rule_source.to_string(),
                "severity": alert.severity.0,
            },
            "flow_id": alert.flow_id,
            "app_proto": alert.protocol,
        });

        let mut line = serde_json::to_vec(&eve).unwrap_or_default();
        line.push(b'\n');

        let mut guard = self.file.lock().await;
        self.ensure_open(&mut guard).await?;
        if let Some(ref mut file) = *guard {
            file.write_all(&line).await?;
        }
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        let mut guard = self.file.lock().await;
        if let Some(ref mut file) = *guard {
            file.flush().await?;
        }
        Ok(())
    }

    fn name(&self) -> &str {
        "eve"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aifw_common::ids::{IdsAction, IdsSeverity, RuleSource};

    #[tokio::test]
    async fn test_eve_output() {
        let dir = std::env::temp_dir().join("aifw-ids-test-eve");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("eve.json");
        let _ = std::fs::remove_file(&path);

        let output = EveOutput::new(path.clone());

        let alert = IdsAlert {
            id: uuid::Uuid::new_v4(),
            timestamp: chrono::Utc::now(),
            signature_id: Some(1234),
            signature_msg: "test alert".into(),
            severity: IdsSeverity(2),
            src_ip: "10.0.0.1".parse().unwrap(),
            src_port: Some(12345),
            dst_ip: "192.168.1.1".parse().unwrap(),
            dst_port: Some(80),
            protocol: "TCP".into(),
            action: IdsAction::Alert,
            rule_source: RuleSource::EtOpen,
            flow_id: None,
            payload_excerpt: None,
            metadata: None,
            acknowledged: false,
            classification: "unreviewed".to_string(),
            analyst_notes: None,
        };

        output.emit(&alert).await.unwrap();
        output.flush().await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("\"signature_id\":1234"));
    }
}
