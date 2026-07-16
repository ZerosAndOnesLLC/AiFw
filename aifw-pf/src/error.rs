use thiserror::Error;

/// Errors returned by [`crate::PfBackend`] operations (both the FreeBSD
/// pfctl backend and the mock)
#[derive(Debug, Error)]
pub enum PfError {
    /// Could not open `/dev/pf` or spawn the pfctl subprocess
    #[error("failed to open /dev/pf: {0}")]
    DeviceOpen(String),

    /// A pf ioctl call failed
    #[error("ioctl error: {0}")]
    Ioctl(String),

    /// Rule load/parse failure (e.g. pfctl reported a syntax error)
    #[error("rule error: {0}")]
    Rule(String),

    /// pf table operation failed (add/remove/replace/flush entries)
    #[error("table error: {0}")]
    Table(String),

    /// Anchor operation failed (e.g. the anchor doesn't exist)
    #[error("anchor error: {0}")]
    Anchor(String),

    /// Underlying I/O error (converted from [`std::io::Error`])
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Catch-all for errors that don't fit a more specific variant
    #[error("{0}")]
    Other(String),
}

impl From<PfError> for aifw_common::AifwError {
    fn from(e: PfError) -> Self {
        aifw_common::AifwError::Pf(e.to_string())
    }
}
