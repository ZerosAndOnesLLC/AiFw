/// Blocklist plugin — blocks connections from known-bad IPs at PreRule
pub mod ip_reputation;
/// Logging plugin — captures hook events into an in-memory buffer
pub mod logging;
/// Webhook plugin — queues notifications for security-relevant events
pub mod webhook;

pub use ip_reputation::IpReputationPlugin;
pub use logging::LoggingPlugin;
pub use webhook::WebhookPlugin;
