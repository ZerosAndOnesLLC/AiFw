use thiserror::Error;

/// Errors produced by the plugin subsystem and returned by plugin authors
/// from [`crate::plugin::Plugin`] lifecycle hooks.
#[derive(Debug, Error)]
pub enum PluginError {
    /// General plugin failure (also what bare `String`/`&str` errors convert into)
    #[error("plugin error: {0}")]
    Plugin(String),

    /// pf table operation failed or was denied (non-`plugin_` prefixed table)
    #[error("pf table error: {0}")]
    Table(String),

    /// Catch-all for errors that don't fit a more specific variant
    #[error("{0}")]
    Other(String),
}

/// Crate-local result alias.
pub type Result<T> = std::result::Result<T, PluginError>;

// Ergonomic conversions so plugin authors can keep returning `Err("msg".into())`
// and existing `.map_err(|e| e.to_string())?` chains still convert via `?`.
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

impl From<PluginError> for aifw_common::AifwError {
    fn from(e: PluginError) -> Self {
        aifw_common::AifwError::Other(e.to_string())
    }
}
