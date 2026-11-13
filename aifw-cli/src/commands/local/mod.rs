//! `aifw local …` — break-glass operations that work without the API by
//! touching the database / pf directly. Only this module may do that.

mod cli_key;
mod cmd;

pub use cli_key::{CLI_KEY_NAME, CLI_USERNAME, provision_cli_key};
pub use cmd::{LocalCmd, run};
