use thiserror::Error;

/// Errors produced by the metrics storage backends.
#[derive(Debug, Error)]
pub enum MetricsError {
    /// No series registered under the given metric name
    #[error("metric not found: {0}")]
    NotFound(String),

    /// Storage-backend failure, carried as a plain message
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
