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
pub mod shaper;
pub mod static_routes;
pub mod status;
pub mod users;
pub mod vpn;

// Explicit re-export lists (#462): renaming an item inside a submodule is a
// visible change here instead of silently reshaping `routes::*`.
pub use ai::{get_ai_settings, list_ai_models, test_ai_provider, update_ai_settings};
pub use auth::{
    create_api_key, create_oauth_provider, delete_oauth_provider, get_auth_settings,
    get_oauth_settings, list_oauth_providers, login, logout, oauth_authorize, oauth_callback,
    oauth_login_options, oauth_totp, put_oauth_settings, refresh_token, register, totp_disable,
    totp_login, totp_setup, totp_verify, update_auth_settings,
};
pub use config_io::{export_config, export_config_with_passphrase, import_config};
pub use dns::{get_dns, update_dns};
pub use geoip::{
    create_geoip_rule, delete_geoip_rule, geoip_lookup, list_geoip_rules, update_geoip_rule,
};
pub use interfaces::{get_interface_stats, get_system_routes, list_interfaces};
pub use nat::{
    create_nat_rule, delete_nat_rule, get_nat_pf_output, list_nat_rules, reorder_nat_rules,
    update_nat_rule,
};
pub use rbac::{
    create_role, delete_role, get_current_user, list_permissions, list_roles, update_role,
};
pub use response::{ApiResponse, MessageResponse};
pub use rules::{
    create_rule, delete_rule, get_rule, list_rules, list_system_rules, reorder_rules,
    toggle_block_logging, update_rule,
};
pub use schedules::{create_schedule, delete_schedule, list_schedules, update_schedule};
pub use settings::{
    HISTORY_SECONDS_HARD_MAX, get_dashboard_history_settings, get_generic_settings,
    get_ids_alert_settings, get_tls_settings, get_valkey_settings,
    update_dashboard_history_settings, update_generic_settings, update_ids_alert_settings,
    update_tls_settings, update_valkey_settings,
};
pub use shaper::{
    apply_shaper, create_shaper_queue, delete_shaper_queue, list_shaper_queues, shaper_status,
    update_shaper_queue,
};
pub use static_routes::{
    SystemRoute, apply_all_routes, create_static_route, delete_static_route, list_static_routes,
    update_static_route,
};
pub use status::{
    about_info, get_pending, get_pf_tuning, issue_ws_ticket, list_blocked_traffic,
    list_connections, list_logs, metrics, pending_stream, put_pf_tuning, reload, status,
};
pub use users::{
    create_user, delete_user_handler, get_user, list_user_audit, list_users, update_user,
};
pub use vpn::{
    create_ipsec_sa_gone, create_ipsec_tunnel, create_wg_peer, create_wg_tunnel, delete_ipsec_sa,
    delete_ipsec_tunnel, delete_wg_peer, delete_wg_tunnel, get_ipsec_tunnel, get_peer_config,
    ipsec_status_all, ipsec_tunnel_status, list_ipsec_sas, list_ipsec_tunnels, list_wg_peers,
    list_wg_tunnels, next_wg_peer_ip, start_ipsec_tunnel, start_wg_tunnel, stop_ipsec_tunnel,
    stop_wg_tunnel, update_ipsec_tunnel, update_wg_peer, update_wg_tunnel, wg_tunnel_status,
};

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

/// Map an engine error to a status (#194): engines own validation, so a
/// `Validation` error is the caller's fault (400), `NotFound` is 404, and
/// anything else is a server-side failure — logged, 500. Handlers no longer
/// pre-validate what the engine's `add`/`update` re-checks anyway.
pub(crate) fn engine_error(e: aifw_common::AifwError) -> StatusCode {
    match e {
        aifw_common::AifwError::Validation(msg) => {
            tracing::debug!(error = %msg, "request rejected by engine validation");
            StatusCode::BAD_REQUEST
        }
        aifw_common::AifwError::NotFound(_) => StatusCode::NOT_FOUND,
        other => {
            tracing::error!(error = %other, "engine call failed");
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }
}

pub(super) fn internal() -> StatusCode {
    StatusCode::INTERNAL_SERVER_ERROR
}
