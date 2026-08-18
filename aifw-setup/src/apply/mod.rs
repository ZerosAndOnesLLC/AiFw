//! Setup apply phase, split by concern (#191). `mod.rs` only declares
//! the modules and re-exports the entry points `main.rs` uses.

mod database;
mod pf_conf;
mod rcd;
mod root_password;
mod run;
mod sudoers;
mod system;

pub use pf_conf::generate_pf_conf;
pub use root_password::set_root_password_noninteractive;
pub use run::apply;
pub use sudoers::sudoers_content;
