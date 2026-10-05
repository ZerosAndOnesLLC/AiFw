//! Plugins that ship with AiFw. Each is listed in [`crate::registry`].

pub mod notifier;
pub mod threat_feeds;

pub use notifier::Notifier;
pub use threat_feeds::ThreatFeeds;
