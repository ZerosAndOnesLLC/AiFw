use thiserror::Error;

#[derive(Debug, Error)]
pub enum PfError {
    #[error("failed to open /dev/pf: {0}")]
    DeviceOpen(String),

    #[error("ioctl error: {0}")]
    Ioctl(String),

    #[error("rule error: {0}")]
    Rule(String),

    #[error("table error: {0}")]
    Table(String),

    #[error("anchor error: {0}")]
    Anchor(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

impl From<PfError> for aifw_common::AifwError {
    fn from(e: PfError) -> Self {
        aifw_common::AifwError::Pf(e.to_string())
    }
}
