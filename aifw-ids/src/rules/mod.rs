//! Rule model and storage, split by concern (#477). This module root
//! declares the submodules (including the existing per-format parsers
//! `sigma`, `suricata`, `yara`, and the `manager`) and re-exports the
//! rule types so `rules::CompiledRule`, `rules::RuleDatabase`, etc. keep
//! resolving.

pub mod database;
/// Ruleset download, SQLite storage, and compilation management
pub mod manager;
pub mod ruleset;
/// Sigma rule model — parsed detection conditions and value modifiers
pub mod sigma;
/// Suricata rule-format parser (action proto addrs ports + options)
pub mod suricata;
pub mod types;
/// YARA rule-format parser (native, no libyara dependency)
pub mod yara;

pub use database::*;
pub use ruleset::*;
pub use types::*;
