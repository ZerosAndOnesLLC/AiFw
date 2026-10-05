//! **Threat Intel Feeds** — keeps a pf table filled with addresses from
//! public IP blocklists (Spamhaus DROP, abuse.ch Feodo, DShield, …) and
//! drops traffic to or from them.
//!
//! This is the reference plugin for `docs/plugins.md`: it shows typed
//! settings, a `Timer` hook that schedules background work with
//! `ctx.spawn`, persistent state in the plugin KV store, pf table and rule
//! management through the sandboxed context, a live `status`, and
//! operator actions.

mod feeds;
mod parse;
mod plugin;
mod sanitize;

pub use feeds::{CATALOG, Feed, Format};
pub use plugin::ThreatFeeds;
