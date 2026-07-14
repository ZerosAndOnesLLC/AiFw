//! # aifw-ai
//!
//! **WIP** — AI/ML threat-detection engine. This crate is a work in progress;
//! see the crate README for current status and caveats.

pub mod detectors;
pub mod features;
pub mod inference;
pub mod response;
pub mod types;

#[cfg(test)]
mod tests;

pub use features::TrafficFeatures;
pub use inference::InferenceBackend;
pub use response::{AutoResponder, ResponseAction, ResponseConfig};
pub use types::{Threat, ThreatScore, ThreatType};
