//! Rule model and storage, split by concern (#477). This module root
//! declares the submodules (including the existing per-format parsers
//! `sigma`, `suricata`, `yara`, and the `manager`) and re-exports the
//! rule types so `rules::CompiledRule`, `rules::RuleDatabase`, etc. keep
//! resolving.

pub mod database;
pub mod manager;
pub mod ruleset;
pub mod sigma;
pub mod suricata;
pub mod types;
pub mod yara;

pub use database::*;
pub use ruleset::*;
pub use types::*;
