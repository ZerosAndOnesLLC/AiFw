//! Authentication and RBAC, one submodule per concern.
//!
//! This module root holds no implementation (#477): it declares the
//! submodules and re-exports their public surface so existing flat
//! `auth::<name>` paths (e.g. `auth::get_user_by_id`, `auth::AuthUser`,
//! `auth::migrate`) keep resolving throughout the crate.

pub mod api_keys;
pub mod config;
pub mod cookies;
pub mod jwt_key;
pub mod middleware;
pub mod migrate;
pub mod oauth;
pub mod password;
pub mod revocation;
pub mod tokens;
pub mod totp;
pub mod totp_store;
pub mod types;
pub mod users;
pub mod ws_ticket;

pub use api_keys::*;
pub use config::AuthSettings;
pub use middleware::*;
pub use migrate::*;
pub use password::{hash_password, verify_password};
pub use revocation::*;
pub use tokens::{Claims, TokenPair, verify_access_token};
pub use totp_store::*;
pub use types::*;
pub use users::*;
