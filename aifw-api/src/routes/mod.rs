//! `/api/v1` route handlers, one submodule per resource namespace.
//!
//! This module root deliberately holds no handler code (#477): it declares
//! the submodules, re-exports their public surface so existing
//! `routes::<handler>` paths in `main.rs` keep resolving, and carries the
//! small shared glue (status-code helpers, the import prelude) that every
//! submodule reaches through its `use super::*;` wildcard.

use axum::{
    Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::sse::{Event, KeepAlive, Sse},
};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use uuid::Uuid;

use crate::AppState;
use aifw_common::{
    Action, Address, Direction, Interface, IpsecSa, NatRedirect, NatRule, NatStatus, NatType,
    PortRange, Protocol, Rule, RuleMatch, RuleStatus, StateTracking, WgPeer, WgTunnel,
};

pub mod ai;
pub mod auth;
pub mod config_io;
pub mod dns;
pub mod geoip;
pub mod interfaces;
pub mod nat;
pub mod rbac;
pub mod response;
pub mod rules;
pub mod schedules;
pub mod settings;
pub mod static_routes;
pub mod status;
pub mod users;
pub mod vpn;

pub use ai::*;
pub use auth::*;
pub use config_io::*;
pub use dns::*;
pub use geoip::*;
pub use interfaces::*;
pub use nat::*;
pub use rbac::*;
pub use response::*;
pub use rules::*;
pub use schedules::*;
pub use settings::*;
pub use static_routes::*;
pub use status::*;
pub use users::*;
pub use vpn::*;

// Crate-internal helpers (validate_route_target, apply_route_to_system,
// remove_route_from_system) are re-exported with their original
// `pub(crate)` visibility so `backup`, `main`, and the opnsense
// importer keep their `routes::<name>` paths working.
pub(crate) use static_routes::{apply_route_to_system, validate_route_target};

pub(super) fn port_range(start: Option<u16>, end: Option<u16>) -> Option<PortRange> {
    match (start, end) {
        (Some(s), Some(e)) => Some(PortRange { start: s, end: e }),
        (Some(s), None) => Some(PortRange { start: s, end: s }),
        _ => None,
    }
}

pub(super) fn bad_request() -> StatusCode {
    StatusCode::BAD_REQUEST
}

pub(super) fn internal() -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}
