pub mod eve;
pub mod sqlite;
pub mod syslog;

use aifw_common::ids::IdsAlert;
use sqlx::SqlitePool;
use tracing::error;

use crate::Result;

/// Trait for alert output backends.
#[async_trait::async_trait]
pub trait AlertOutput: Send + Sync {
    /// Emit a single alert.
    async fn emit(&self, alert: &IdsAlert) -> Result<()>;
    /// Flush any buffered alerts.
    async fn flush(&self) -> Result<()>;
    /// Output name (for logging).
    fn name(&self) -> &str;
}

/// Fan-out alert pipeline that sends alerts to all configured outputs.
pub struct AlertPipeline {
    outputs: Vec<Box<dyn AlertOutput>>,
}

impl AlertPipeline {
    /// Create a new pipeline with SQLite output enabled by default.
    pub fn new(pool: SqlitePool) -> Self {
        let outputs: Vec<Box<dyn AlertOutput>> = vec![
            Box::new(sqlite::SqliteOutput::new(pool)),
        ];
        Self { outputs }
    }

    /// Create a pipeline with custom outputs.
    pub fn with_outputs(outputs: Vec<Box<dyn AlertOutput>>) -> Self {
        Self { outputs }
    }

    /// Add an output to the pipeline.
    pub fn add_output(&mut self, output: Box<dyn AlertOutput>) {
        self.outputs.push(output);
    }

    /// Emit an alert to all outputs.
    pub async fn emit(&self, alert: &IdsAlert) -> Result<()> {
        for output in &self.outputs {
            if let Err(e) = output.emit(alert).await {
                error!(output = output.name(), "alert output error: {e}");
            }
        }
        Ok(())
    }

    /// Flush all outputs.
    pub async fn flush(&self) -> Result<()> {
        for output in &self.outputs {
            if let Err(e) = output.flush().await {
                error!(output = output.name(), "flush error: {e}");
            }
        }
        Ok(())
    }
}

impl std::fmt::Debug for AlertPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AlertPipeline")
            .field("outputs", &self.outputs.len())
            .finish()
    }
}
