use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use aifw_common::ids::IdsAlert;

use super::AlertOutput;
use crate::Result;

/// EVE JSON file output — Suricata-compatible one-JSON-per-line format.
pub struct EveOutput {
    path: PathBuf,
    file: Mutex<Option<std::fs::File>>,
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

    fn get_file(&self) -> Result<std::sync::MutexGuard<'_, Option<std::fs::File>>> {
        let mut guard = self.file.lock().unwrap();
        if guard.is_none() {
            if let Some(parent) = self.path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            *guard = Some(file);
        }
        Ok(guard)
    }

    fn check_rotation(&self) -> Result<()> {
        if let Ok(metadata) = std::fs::metadata(&self.path)
            && metadata.len() >= self.max_size {
                // Rotate: rename current file to .1, delete old .1 if exists
                let rotated = self.path.with_extension("json.1");
                let _ = std::fs::remove_file(&rotated);
                let _ = std::fs::rename(&self.path, &rotated);

                // Reset the file handle
                let mut guard = self.file.lock().unwrap();
                *guard = None;
            }
        Ok(())
    }
}

#[async_trait::async_trait]
impl AlertOutput for EveOutput {
    async fn emit(&self, alert: &IdsAlert) -> Result<()> {
        self.check_rotation()?;

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

        let line = serde_json::to_string(&eve).unwrap_or_default();

        let mut guard = self.get_file()?;
        if let Some(ref mut file) = *guard {
            writeln!(file, "{line}")?;
        }

        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        let mut guard = self.file.lock().unwrap();
        if let Some(ref mut file) = *guard {
            file.flush()?;
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

        let alert = IdsAlert::new(
            "EVE test alert".into(),
            IdsSeverity::HIGH,
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            "tcp",
            IdsAction::Alert,
            RuleSource::EtOpen,
        );

        output.emit(&alert).await.unwrap();
        output.flush().await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("EVE test alert"));
        assert!(contents.contains("\"event_type\":\"alert\""));

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }
}
