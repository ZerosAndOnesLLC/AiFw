//! The `aifw` command-line client.
//!
//! A library so the API's integration tests can drive real commands
//! against an in-process server (`aifw_cli::run` with buffered stdio).

pub mod app;
pub mod cli;
pub mod commands;

pub use app::run;
pub use cli::{Env, Io};
