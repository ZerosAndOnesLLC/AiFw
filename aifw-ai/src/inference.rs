use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Trait for ML inference backends (ONNX, etc.)
#[async_trait]
pub trait InferenceBackend: Send + Sync {
    /// Run inference on a feature vector, return anomaly score (0.0-1.0)
    async fn predict(&self, features: &[f64]) -> Result<f64, String>;

    /// Load or reload a model from the given path
    async fn load_model(&mut self, path: &str) -> Result<(), String>;

    /// Get model info
    fn model_info(&self) -> ModelInfo;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub name: String,
    pub version: String,
    pub input_size: usize,
    pub loaded: bool,
}

/// Stub inference backend for development on non-FreeBSD / without ONNX
pub struct StubInference {
    info: ModelInfo,
}

impl StubInference {
    pub fn new() -> Self {
        Self {
            info: ModelInfo {
                name: "stub-model".to_string(),
                version: "0.0.0".to_string(),
                input_size: 13,
                loaded: false,
            },
        }
    }
}

impl Default for StubInference {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl InferenceBackend for StubInference {
    async fn predict(&self, features: &[f64]) -> Result<f64, String> {
        // Simple heuristic-based "prediction" for development:
        // High connection rate + high unique ports = likely scan
        // High SYN count + low established = likely DDoS
        if features.len() < self.info.input_size {
            return Err("feature vector too short".to_string());
        }

        let conn_count = features[0];
        let unique_ports = features[2];
        let syn_count = features[6];
        let failed_ratio = features[7];
        let conn_rate = features[8];

        let mut score: f64 = 0.0;

        // High connection rate is suspicious
        if conn_rate > 10.0 {
            score += 0.3;
        }
        // Many unique ports suggests scanning
        if unique_ports > 20.0 {
            score += 0.2;
        }
        // High SYN with many failed connections
        if syn_count > 10.0 && failed_ratio > 0.7 {
            score += 0.3;
        }
        // Raw volume
        if conn_count > 100.0 {
            score += 0.1;
        }

        Ok(score.min(1.0))
    }

    async fn load_model(&mut self, path: &str) -> Result<(), String> {
        tracing::info!(path, "stub: model load (no-op)");
        self.info.loaded = true;
        self.info.name = path.to_string();
        Ok(())
    }

    fn model_info(&self) -> ModelInfo {
        self.info.clone()
    }
}
