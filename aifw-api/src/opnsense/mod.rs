//! OPNsense / pfSense `config.xml` import.
//!
//! Two HTTP entry points — `preview_opnsense` and `import_opnsense` — sit on
//! top of a typed parser (`parser`) and an engine-routed applier (`importer`).
//! The parser uses `quick-xml` so source/destination port disambiguation,
//! self-closing tags, and CDATA all behave correctly. The applier writes
//! through `RuleEngine`, `NatEngine`, `AliasEngine`, and the static-route +
//! DNS HTTP paths so imported state actually reaches pf and the kernel.
//!
//! The whole apply step runs inside a SQLite transaction with a pre-import
//! config snapshot, and is wrapped in commit-confirm so a bad import
//! auto-reverts if the admin loses access before they can confirm.

mod importer;
mod parser;
mod types;

#[cfg(test)]
mod tests;

pub use importer::{import_opnsense, preview_opnsense};
