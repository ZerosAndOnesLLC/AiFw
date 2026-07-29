//! Remote syslog forwarding.
//!
//! One shared subsystem used by aifw-api, aifw-daemon, and aifw-ids-bin:
//!
//! - [`config`] — the `syslog_config` singleton row (server target, transport,
//!   format, per-category toggles) with `migrate`/`load`/`save`.
//! - [`format`] — RFC 3164 (BSD) and RFC 5424 message rendering.
//!
//! Forwarding is opt-in per category ([`Category`]): pf packet logs, IDS
//! alerts, and application (tracing) logs.

mod config;
mod format;

pub use config::{
    Category, SyslogConfig, SyslogFormat, Transport, facility_from_name, facility_name, load,
    migrate, save, save_on,
};
pub use format::{SyslogRecord, format_message, priority};
