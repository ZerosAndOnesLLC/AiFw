#![warn(missing_docs)]
//! # aifw-ai
//!
//! **WIP** — AI/ML threat-detection engine. This crate is a work in progress;
//! see the crate README for current status and caveats.

/// Heuristic threat detectors (port scan, DDoS, brute force, C2, DNS tunnel)
pub mod detectors;
/// Crate error type (`AiError`) and result alias
pub mod error;
/// Per-source-IP traffic feature extraction from pf states
pub mod features;
/// ML inference backend trait and the development stub implementation
pub mod inference;
/// Auto-response engine: alert / rate-limit / block actions via pf tables
pub mod response;
/// Core threat types: `Threat`, `ThreatType`, `ThreatScore`, evidence
pub mod types;

#[cfg(test)]
mod tests;

pub use error::{AiError, Result};
pub use features::TrafficFeatures;
pub use inference::InferenceBackend;
pub use response::{AutoResponder, ResponseAction, ResponseConfig};
pub use types::{Threat, ThreatScore, ThreatType};
