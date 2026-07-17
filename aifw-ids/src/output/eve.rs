use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::fs::{File, OpenOptions};
use tokio::io::{AsyncWriteExt, BufWriter};
use tokio::sync::Mutex;

use aifw_common::ids::IdsAlert;

use super::AlertOutput;
use crate::Result;

/// Write buffer size. EVE lines are ~500 bytes, so this batches ~100
/// alerts per write syscall during bursts (PERF-L1).
const WRITE_BUF_CAPACITY: usize = 64 * 1024;

/// How often the background flusher drains buffered lines to disk. Bounds
/// how long a SIEM tailing the file can lag behind a burst.
const FLUSH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(1);

/// EVE JSON file output — Suricata-compatible one-JSON-per-line format.
///
/// All file I/O is async via tokio::fs so emitting an alert never blocks
/// the runtime worker. Previously the std::sync::Mutex was held across
/// blocking writes; under disk pressure that stalled the whole alert
/// pipeline.
///
/// PERF-L1: writes go through a 64 KiB `BufWriter`, so a high alert rate
/// costs one syscall per buffer instead of one per line. A background task
/// flushes dirty buffers every second, bounding how long lines can sit in
/// memory (the pipeline only calls `flush()` on engine stop).
pub struct EveOutput {
    path: PathBuf,
    file: Arc<Mutex<Option<BufWriter<File>>>>,
    /// Set after a buffered write; cleared by whichever flush runs first.
    dirty: Arc<AtomicBool>,
    /// Guard so the periodic flusher is spawned exactly once, lazily on
    /// first emit (`new()` has no runtime guarantee).
    flusher_started: AtomicBool,
    max_size: u64,
}

impl EveOutput {
    /// Create an EVE sink writing to `path`, with a 100 MB default rotation
    /// size. The file is opened lazily on first emit.
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            file: Arc::new(Mutex::new(None)),
            dirty: Arc::new(AtomicBool::new(false)),
            flusher_started: AtomicBool::new(false),
            max_size: 100 * 1024 * 1024, // 100MB default
        }
    }

    /// Builder: set the file size in bytes at which rotation kicks in
    pub fn with_max_size(mut self, bytes: u64) -> Self {
        self.max_size = bytes;
        self
    }

    /// Open the file lazily on first write. Caller holds the lock.
    async fn ensure_open<'a>(
        &'a self,
        guard: &mut tokio::sync::MutexGuard<'a, Option<BufWriter<File>>>,
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
            **guard = Some(BufWriter::with_capacity(WRITE_BUF_CAPACITY, f));
        }
        Ok(())
    }

    /// Spawn the once-per-second background flusher on first use.
    fn ensure_flusher(&self) {
        if self.flusher_started.swap(true, Ordering::SeqCst) {
            return;
        }
        let file = self.file.clone();
        let dirty = self.dirty.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(FLUSH_INTERVAL);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tick.tick().await;
                if !dirty.swap(false, Ordering::AcqRel) {
                    continue;
                }
                let mut guard = file.lock().await;
                if let Some(ref mut w) = *guard
                    && let Err(e) = w.flush().await
                {
                    tracing::warn!(error = %e, "eve output: periodic flush failed");
                }
            }
        });
    }

    /// Rotate the on-disk file when it exceeds `max_size`. Releases the
    /// open handle so the next emit reopens the fresh file.
    async fn check_rotation(&self) -> Result<()> {
        if let Ok(metadata) = tokio::fs::metadata(&self.path).await
            && metadata.len() >= self.max_size
        {
            let mut guard = self.file.lock().await;
            // Drain buffered lines into the file about to be rotated so
            // they aren't lost when the handle is dropped.
            if let Some(ref mut w) = *guard
                && let Err(e) = w.flush().await
            {
                tracing::warn!(error = %e, "eve output: pre-rotation flush failed");
            }
            let rotated = self.path.with_extension("json.1");
            let _ = tokio::fs::remove_file(&rotated).await;
            let _ = tokio::fs::rename(&self.path, &rotated).await;
            *guard = None;
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

        // PERF-L2: propagate instead of `unwrap_or_default()` — an empty
        // line in the EVE file chokes downstream SIEMs, and the pipeline
        // logs emit errors per output.
        let mut line = serde_json::to_vec(&eve)?;
        line.push(b'\n');

        self.ensure_flusher();
        let mut guard = self.file.lock().await;
        self.ensure_open(&mut guard).await?;
        if let Some(ref mut file) = *guard {
            file.write_all(&line).await?;
            self.dirty.store(true, Ordering::Release);
        }
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        let mut guard = self.file.lock().await;
        if let Some(ref mut file) = *guard {
            file.flush().await?;
            self.dirty.store(false, Ordering::Release);
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
            classification: aifw_common::ids::AlertClassification::Unreviewed,
            analyst_notes: None,
        };

        output.emit(&alert).await.unwrap();
        output.flush().await.unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(contents.contains("\"signature_id\":1234"));
    }
}
