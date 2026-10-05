//! Plugins that ship with AiFw. Each is listed in [`crate::registry`].

pub mod threat_feeds;

pub use threat_feeds::ThreatFeeds;
