use thiserror::Error;

/// Errors produced by the aifw-ai inference / threat-detection engine.
#[derive(Debug, Error)]
pub enum AiError {
    /// Prediction failed (e.g. feature vector shorter than the model's input size)
    #[error("inference error: {0}")]
    Inference(String),

    /// Model file could not be loaded or parsed
    #[error("model load error: {0}")]
    ModelLoad(String),

    /// Any other AI-engine failure, carried as a plain message
    #[error("{0}")]
    Other(String),
}

/// Crate-local result alias.
pub type Result<T> = std::result::Result<T, AiError>;

impl From<AiError> for aifw_common::AifwError {
    fn from(e: AiError) -> Self {
        aifw_common::AifwError::Other(e.to_string())
    }
}
