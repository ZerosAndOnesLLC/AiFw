//! `aifw local …` — break-glass operations that work without the API by
//! touching the database / pf directly. Only this module may do that.

mod cli_key;
mod cmd;
mod common;
mod config;
mod init;
mod ratelimit;
mod system;
mod updates;

pub use cli_key::{CLI_KEY_NAME, CLI_USERNAME, provision_cli_key};
pub use cmd::{LocalCmd, LocalUpdateCmd, run};
pub use config::config_export;
pub use init::init;
pub use ratelimit::{ratelimit_add, ratelimit_list, ratelimit_remove};
pub use system::*;
pub use updates::*;
