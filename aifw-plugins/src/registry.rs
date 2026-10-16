//! The list of built-in plugins. Adding a plugin to AiFw means writing a
//! type that implements [`crate::Plugin`] and adding one line here — the
//! API, CLI, config restore and UI all discover plugins through this list.

use std::sync::Arc;

use crate::plugin::Plugin;

/// Every built-in plugin, in display order.
pub fn builtins() -> Vec<Arc<dyn Plugin>> {
    vec![
        Arc::new(crate::builtin::ThreatFeeds),
        Arc::new(crate::builtin::Notifier),
    ]
}

/// The built-in plugin `name`, if one exists. Used by paths that need a
/// plugin's schema without a running manager (CLI, config restore).
pub fn find(name: &str) -> Option<Arc<dyn Plugin>> {
    builtins().into_iter().find(|p| p.info().name == name)
}
