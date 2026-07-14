use thiserror::Error;

/// Errors produced by the connection-tracking / pflog subsystem.
#[derive(Debug, Error)]
pub enum ConntrackError {
    #[error("pf error: {0}")]
    Pf(String),

    #[error("{0}")]
    Other(String),
}

/// Crate-local result alias.
pub type Result<T> = std::result::Result<T, ConntrackError>;

impl From<aifw_pf::PfError> for ConntrackError {
    fn from(e: aifw_pf::PfError) -> Self {
        ConntrackError::Pf(e.to_string())
    }
}

impl From<ConntrackError> for aifw_common::AifwError {
    fn from(e: ConntrackError) -> Self {
        match e {
            ConntrackError::Pf(s) => aifw_common::AifwError::Pf(s),
            ConntrackError::Other(s) => aifw_common::AifwError::Other(s),
        }
    }
}
