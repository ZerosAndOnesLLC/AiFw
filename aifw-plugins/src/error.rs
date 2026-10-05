use thiserror::Error;

/// Errors produced by the plugin subsystem and returned by plugin authors
/// from [`crate::plugin::Plugin`] lifecycle hooks.
#[derive(Debug, Error)]
pub enum PluginError {
    /// General plugin failure (also what bare `String`/`&str` errors convert into)
    #[error("{0}")]
    Plugin(String),

    /// pf table or rule operation failed or was denied (non-`plugin_` table)
    #[error("pf error: {0}")]
    Table(String),

    /// Unknown plugin, action, or setting
    #[error("not found: {0}")]
    NotFound(String),

    /// Settings or action arguments failed validation
    #[error("{0}")]
    Validation(String),

    /// The plugin's `init` failed or timed out
    #[error("init failed: {0}")]
    Init(String),

    /// Persistence (plugin_config / plugin_kv) failed
    #[error("store error: {0}")]
    Store(String),

    /// A plugin call exceeded its time budget
    #[error("timed out: {0}")]
    Timeout(String),
}

/// Crate-local result alias.
pub type Result<T> = std::result::Result<T, PluginError>;

// Ergonomic conversions so plugin authors can return `Err("msg".into())`.
impl From<String> for PluginError {
    fn from(s: String) -> Self {
        PluginError::Plugin(s)
    }
}

impl From<&str> for PluginError {
    fn from(s: &str) -> Self {
        PluginError::Plugin(s.to_string())
    }
}

impl From<sqlx::Error> for PluginError {
    fn from(e: sqlx::Error) -> Self {
        PluginError::Store(e.to_string())
    }
}

impl From<aifw_core::CoreError> for PluginError {
    fn from(e: aifw_core::CoreError) -> Self {
        PluginError::Store(e.to_string())
    }
}

impl From<PluginError> for aifw_common::AifwError {
    fn from(e: PluginError) -> Self {
        match e {
            PluginError::NotFound(m) => aifw_common::AifwError::NotFound(m),
            PluginError::Validation(m) => aifw_common::AifwError::Validation(m),
            other => aifw_common::AifwError::Other(other.to_string()),
        }
    }
}
