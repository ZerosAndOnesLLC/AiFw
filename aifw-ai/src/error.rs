use thiserror::Error;

/// Errors produced by the aifw-ai inference / threat-detection engine.
#[derive(Debug, Error)]
pub enum AiError {
    #[error("inference error: {0}")]
    Inference(String),

    #[error("model load error: {0}")]
    ModelLoad(String),

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
