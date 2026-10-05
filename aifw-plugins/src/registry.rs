//! The list of built-in plugins. Adding a plugin to AiFw means writing a
//! type that implements [`crate::Plugin`] and adding one line here — the
//! API, CLI, config restore and UI all discover plugins through this list.

use std::sync::Arc;

use crate::plugin::Plugin;

/// Builds a fresh, un-initialized plugin instance.
pub type Factory = Arc<dyn Fn() -> Box<dyn Plugin> + Send + Sync>;

/// Constructors of every built-in plugin, in display order.
const BUILTINS: &[fn() -> Box<dyn Plugin>] = &[crate::builtin::ThreatFeeds::boxed];

/// Factories for every built-in plugin.
pub fn factories() -> Vec<Factory> {
    BUILTINS
        .iter()
        .map(|f| {
            let f = *f;
            Arc::new(f) as Factory
        })
        .collect()
}

/// A fresh instance of the built-in plugin `name`, if one exists. Used by
/// paths that need a plugin's schema without a running manager (CLI,
/// config restore).
pub fn instantiate(name: &str) -> Option<Box<dyn Plugin>> {
    BUILTINS.iter().map(|f| f()).find(|p| p.info().name == name)
}
