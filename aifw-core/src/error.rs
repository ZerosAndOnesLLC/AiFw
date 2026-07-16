//! Per-crate error type for `aifw-core` (QUAL-C4).
//!
//! Until now, engines in this crate returned the cross-crate
//! `aifw_common::Result` / `aifw_common::AifwError` because there was no
//! crate-local enum. That works but collapses every domain failure into a
//! single shared variant set — callers can't pattern-match on
//! "couldn't reach pf" vs "DB returned no row" without parsing the
//! `AifwError::Other(String)` payload.
//!
//! `CoreError` is the new per-crate enum. Each engine can migrate from
//! `aifw_common::Result<T>` to `aifw_core::Result<T>` one at a time;
//! `From<sqlx::Error>`, `From<aifw_common::AifwError>`, and
//! `From<aifw_pf::PfError>` mean the conversion is mostly mechanical.
//!
//! Library crates per CLAUDE.md (#188) MUST use a crate-local error enum;
//! `aifw_common::AifwError` stays around as the cross-crate fallback for
//! types that need to flow through more than one crate (e.g. the public
//! API of `aifw-common::geoip` helpers).

use thiserror::Error;

/// Crate-local result alias over [`CoreError`]
pub type Result<T> = std::result::Result<T, CoreError>;

/// Error type for `aifw-core` engines. Converts from `sqlx::Error`,
/// `aifw_pf::PfError`, and `aifw_common::AifwError` so migration from the
/// shared error type is mechanical.
#[derive(Debug, Error)]
pub enum CoreError {
    /// SQLite query or connection failure
    #[error("database error: {0}")]
    Database(String),

    /// pf backend (pfctl/ioctl) failure
    #[error("pf backend error: {0}")]
    Pf(String),

    /// Input rejected by validation before touching the DB or pf
    #[error("validation error: {0}")]
    Validation(String),

    /// Requested row or entity does not exist
    #[error("not found: {0}")]
    NotFound(String),

    /// Bad or missing configuration
    #[error("config error: {0}")]
    Config(String),

    /// Underlying I/O failure
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// Anything that doesn't fit the other variants
    #[error("{0}")]
    Other(String),
}

impl From<sqlx::Error> for CoreError {
    fn from(e: sqlx::Error) -> Self {
        CoreError::Database(e.to_string())
    }
}

impl From<aifw_pf::PfError> for CoreError {
    fn from(e: aifw_pf::PfError) -> Self {
        CoreError::Pf(e.to_string())
    }
}

impl From<aifw_common::AifwError> for CoreError {
    fn from(e: aifw_common::AifwError) -> Self {
        match e {
            aifw_common::AifwError::Pf(s) => CoreError::Pf(s),
            aifw_common::AifwError::Rule(s) => CoreError::Validation(s),
            aifw_common::AifwError::Database(s) => CoreError::Database(s),
            aifw_common::AifwError::Config(s) => CoreError::Config(s),
            aifw_common::AifwError::Validation(s) => CoreError::Validation(s),
            aifw_common::AifwError::NotFound(s) => CoreError::NotFound(s),
            aifw_common::AifwError::Io(e) => CoreError::Io(e),
            aifw_common::AifwError::Other(s) => CoreError::Other(s),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_sqlx_maps_to_database() {
        let e: CoreError = sqlx::Error::RowNotFound.into();
        assert!(matches!(e, CoreError::Database(_)));
    }

    #[test]
    fn from_aifw_common_validation_maps_to_validation() {
        let src = aifw_common::AifwError::Validation("bad".into());
        let dst: CoreError = src.into();
        assert!(matches!(dst, CoreError::Validation(s) if s == "bad"));
    }
}
