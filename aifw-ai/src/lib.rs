#![warn(missing_docs)]
//! # aifw-ai
//!
//! **Prototype, not wired in.** Heuristic behavioural detectors (port
//! scan, DDoS, brute force, C2 beacon, DNS tunnel), a feature extractor,
//! an inference-backend trait with a development stub, and an auto-response
//! model. No AiFw binary depends on this crate: nothing on the appliance
//! runs these detectors and there is no setting that enables them (#171).
//! It is excluded from the workspace's `default-members` — build it with
//! `cargo build -p aifw-ai` or `--workspace`. The AI feature that ships is
//! the LLM-assisted alert triage in `aifw-api::ai_analysis`.

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
