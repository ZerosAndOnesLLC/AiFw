//! Detection engine, split by concern (#477). This module root declares
//! the submodules (including the existing `multi_pattern` and `threshold`
//! helpers) and re-exports the engine surface so `detect::DetectionEngine`
//! keeps resolving.

pub mod engine;
pub mod matching;
/// Aho-Corasick multi-pattern matching helpers used by the prefilter
pub mod multi_pattern;
/// Per-rule, per-IP threshold and rate-limit tracking
pub mod threshold;

pub use engine::*;
