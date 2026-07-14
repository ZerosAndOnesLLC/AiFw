use thiserror::Error;

/// Errors produced by the metrics storage backends.
#[derive(Debug, Error)]
pub enum MetricsError {
    #[error("metric not found: {0}")]
    NotFound(String),

    #[error("{0}")]
    Backend(String),
}

/// Crate-local result alias.
pub type Result<T> = std::result::Result<T, MetricsError>;

impl From<MetricsError> for aifw_common::AifwError {
    fn from(e: MetricsError) -> Self {
        aifw_common::AifwError::Other(e.to_string())
    }
}
