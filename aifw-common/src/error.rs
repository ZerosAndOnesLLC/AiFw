use thiserror::Error;

/// Convenience alias: `Result` with [`AifwError`] as the error type
pub type Result<T> = std::result::Result<T, AifwError>;

/// Cross-crate error type shared by AiFw components. Used as the fallback
/// where a crate doesn't define its own error enum (error policy #188).
#[derive(Debug, Error)]
pub enum AifwError {
    /// A pf operation failed (pfctl invocation, ioctl, anchor manipulation)
    #[error("pf error: {0}")]
    Pf(String),

    /// A firewall rule could not be built, parsed, or applied
    #[error("rule error: {0}")]
    Rule(String),

    /// A SQLite operation failed (also produced by the `From<sqlx::Error>` impl)
    #[error("database error: {0}")]
    Database(String),

    /// Invalid or missing configuration
    #[error("config error: {0}")]
    Config(String),

    /// User-supplied input failed validation
    #[error("validation error: {0}")]
    Validation(String),

    /// A requested entity does not exist
    #[error("not found: {0}")]
    NotFound(String),

    /// An underlying I/O operation failed
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Catch-all for errors that fit no other variant
    #[error("{0}")]
    Other(String),
}

impl From<sqlx::Error> for AifwError {
    fn from(e: sqlx::Error) -> Self {
        AifwError::Database(e.to_string())
    }
}
