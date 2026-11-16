//! CLI plumbing shared by every command: flags, config/credentials,
//! connection resolution, output, prompts and exit codes.

pub mod body;
pub mod config;
pub mod connect;
pub mod ctx;
pub mod exit;
pub mod fanout;
pub mod global;
pub mod io;
pub mod onbox;
pub mod output;
pub mod parse;
pub mod prompt;

pub use ctx::{Ctx, Env};
pub use io::Io;
pub use output::{Format, col, wide};
