//! Detection engine, split by concern (#477). This module root declares
//! the submodules (including the existing `multi_pattern` and `threshold`
//! helpers) and re-exports the engine surface so `detect::DetectionEngine`
//! keeps resolving.

pub mod engine;
pub mod matching;
pub mod multi_pattern;
pub mod threshold;

pub use engine::*;
