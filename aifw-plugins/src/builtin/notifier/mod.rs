//! **Notifier** — pushes IDS alerts, gateway and VPN outages, and selected
//! configuration changes to ntfy, Discord, Slack, Telegram or a signed
//! JSON webhook. Shows the event-driven plugin pattern: hooks are
//! classified quickly in `on_hook` and handed to a background delivery
//! task (`ctx.spawn`) that dedupes, rate-limits and retries.

mod channels;
mod limiter;
mod message;
mod plugin;

pub use plugin::Notifier;
