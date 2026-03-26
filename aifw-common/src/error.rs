use thiserror::Error;

pub type Result<T> = std::result::Result<T, AifwError>;

#[derive(Debug, Error)]
pub enum AifwError {
    #[error("pf error: {0}")]
    Pf(String),

    #[error("rule error: {0}")]
    Rule(String),

    #[error("database error: {0}")]
    Database(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

impl From<sqlx::Error> for AifwError {
    fn from(e: sqlx::Error) -> Self {
        AifwError::Database(e.to_string())
    }
}
