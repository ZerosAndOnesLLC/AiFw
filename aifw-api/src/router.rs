//! Permission-scoped route-group factories for the API (#372).
//!
//! `build_router` in `main.rs` was a single ~1150-line function. Each
//! permission group is now a `Router::new()` factory here, merged by
//! `build_router`. Two groups (`dashboard_view`, `dns_read`) stay inline
//! in `build_router` because they layer the WS/SSE `origin_guard` closure
//! onto individual stream routes.
//!
//! Every factory returns `Router<AppState>`; state is applied once by
//! `build_router` via `.with_state(state)`.

use aifw_common::Permission;
use axum::Router;
use axum::routing::{delete, get, post, put};

use crate::AppState;
use crate::perm_check;
use crate::{
    acme, ai_analysis, aliases, backup, backup_s3, ca, cluster, dhcp, dns_blocklists, dns_resolver,
    ids, iface, multiwan, opnsense, plugins, reverse_proxy, routes, system, time_service, updates,
};
use axum::middleware;

pub(crate) fn public_routes() -> Router<AppState> {
    Router::new()
        .route("/api/v1/auth/login", post(routes::login))
        .route("/api/v1/auth/totp/login", post(routes::totp_login))
        .route("/api/v1/auth/refresh", post(routes::refresh_token))
        .route(
            "/api/v1/auth/oauth/{provider}/authorize",
            get(routes::oauth_authorize),
        )
        .route(
            "/api/v1/auth/oauth/{provider}/callback",
            get(routes::oauth_callback),
        )
        .route("/api/v1/auth/register", post(routes::register))
}

pub(crate) fn self_service() -> Router<AppState> {
    Router::new()
        .route("/api/v1/auth/logout", post(routes::logout))
        .route("/api/v1/auth/totp/setup", post(routes::totp_setup))
        .route("/api/v1/auth/totp/verify", post(routes::totp_verify))
        .route("/api/v1/auth/totp/disable", post(routes::totp_disable))
        .route("/api/v1/auth/me", get(routes::get_current_user))
        .route("/api/v1/auth/ws-ticket", post(routes::issue_ws_ticket))
}

pub(crate) fn rules_read() -> Router<AppState> {
    Router::new()
        .route("/api/v1/rules", get(routes::list_rules))
        .route("/api/v1/rules/{id}", get(routes::get_rule))
        .route("/api/v1/rules/system", get(routes::list_system_rules))
        .route("/api/v1/schedules", get(routes::list_schedules))
        .layer(middleware::from_fn(perm_check!(Permission::RulesRead)))
}

pub(crate) fn rules_write() -> Router<AppState> {
    Router::new()
        .route("/api/v1/rules", post(routes::create_rule))
        .route(
            "/api/v1/rules/{id}",
            put(routes::update_rule).delete(routes::delete_rule),
        )
        .route("/api/v1/rules/reorder", put(routes::reorder_rules))
        .route(
            "/api/v1/rules/block-logging",
            post(routes::toggle_block_logging),
        )
        .route("/api/v1/reload", post(routes::reload))
        .route("/api/v1/schedules", post(routes::create_schedule))
        .route(
            "/api/v1/schedules/{id}",
            put(routes::update_schedule).delete(routes::delete_schedule),
        )
        .layer(middleware::from_fn(perm_check!(Permission::RulesWrite)))
}

pub(crate) fn nat_read() -> Router<AppState> {
    Router::new()
        .route("/api/v1/nat", get(routes::list_nat_rules))
        .route("/api/v1/nat/pf-output", get(routes::get_nat_pf_output))
        .layer(middleware::from_fn(perm_check!(Permission::NatRead)))
}

pub(crate) fn nat_write() -> Router<AppState> {
    Router::new()
        .route("/api/v1/nat", post(routes::create_nat_rule))
        .route(
            "/api/v1/nat/{id}",
            put(routes::update_nat_rule).delete(routes::delete_nat_rule),
        )
        .route("/api/v1/nat/reorder", put(routes::reorder_nat_rules))
        .layer(middleware::from_fn(perm_check!(Permission::NatWrite)))
}

pub(crate) fn vpn_read() -> Router<AppState> {
    Router::new()
        .route("/api/v1/vpn/wg", get(routes::list_wg_tunnels))
        .route("/api/v1/vpn/wg/{id}/peers", get(routes::list_wg_peers))
        .route(
            "/api/v1/vpn/wg/{id}/peers/next-ip",
            get(routes::next_wg_peer_ip),
        )
        .route(
            "/api/v1/vpn/wg/{tid}/peers/{pid}/config",
            get(routes::get_peer_config),
        )
        .route("/api/v1/vpn/wg/{id}/status", get(routes::wg_tunnel_status))
        .route("/api/v1/vpn/ipsec", get(routes::list_ipsec_sas))
        .route("/api/v1/vpn/ipsec/status", get(routes::ipsec_status_all))
        .route("/api/v1/vpn/ipsec/tunnels", get(routes::list_ipsec_tunnels))
        .route(
            "/api/v1/vpn/ipsec/tunnels/{id}",
            get(routes::get_ipsec_tunnel),
        )
        .route(
            "/api/v1/vpn/ipsec/tunnels/{id}/status",
            get(routes::ipsec_tunnel_status),
        )
        .layer(middleware::from_fn(perm_check!(Permission::VpnRead)))
}

pub(crate) fn vpn_write() -> Router<AppState> {
    Router::new()
        .route("/api/v1/vpn/wg", post(routes::create_wg_tunnel))
        .route(
            "/api/v1/vpn/wg/{id}",
            put(routes::update_wg_tunnel).delete(routes::delete_wg_tunnel),
        )
        .route("/api/v1/vpn/wg/{id}/start", post(routes::start_wg_tunnel))
        .route("/api/v1/vpn/wg/{id}/stop", post(routes::stop_wg_tunnel))
        .route("/api/v1/vpn/wg/{id}/peers", post(routes::create_wg_peer))
        .route(
            "/api/v1/vpn/wg/{tid}/peers/{pid}",
            put(routes::update_wg_peer).delete(routes::delete_wg_peer),
        )
        // Legacy SA records (#530): creation is gone, deletion still
        // allowed so operators can clean the read-only leftovers up.
        .route("/api/v1/vpn/ipsec", post(routes::create_ipsec_sa_gone))
        .route("/api/v1/vpn/ipsec/{id}", delete(routes::delete_ipsec_sa))
        .route(
            "/api/v1/vpn/ipsec/tunnels",
            post(routes::create_ipsec_tunnel),
        )
        .route(
            "/api/v1/vpn/ipsec/tunnels/{id}",
            put(routes::update_ipsec_tunnel).delete(routes::delete_ipsec_tunnel),
        )
        .route(
            "/api/v1/vpn/ipsec/tunnels/{id}/start",
            post(routes::start_ipsec_tunnel),
        )
        .route(
            "/api/v1/vpn/ipsec/tunnels/{id}/stop",
            post(routes::stop_ipsec_tunnel),
        )
        .layer(middleware::from_fn(perm_check!(Permission::VpnWrite)))
}

pub(crate) fn geoip_read() -> Router<AppState> {
    Router::new()
        .route("/api/v1/geoip", get(routes::list_geoip_rules))
        .route("/api/v1/geoip/lookup/{ip}", get(routes::geoip_lookup))
        .layer(middleware::from_fn(perm_check!(Permission::GeoipRead)))
}

pub(crate) fn geoip_write() -> Router<AppState> {
    Router::new()
        .route("/api/v1/geoip", post(routes::create_geoip_rule))
        .route(
            "/api/v1/geoip/{id}",
            put(routes::update_geoip_rule).delete(routes::delete_geoip_rule),
        )
        .layer(middleware::from_fn(perm_check!(Permission::GeoipWrite)))
}

pub(crate) fn ids_read() -> Router<AppState> {
    Router::new()
        .route("/api/v1/ids/config", get(ids::get_config))
        .route("/api/v1/ids/alerts", get(ids::list_alerts))
        .route("/api/v1/ids/alerts/{id}", get(ids::get_alert))
        .route("/api/v1/ids/rulesets", get(ids::list_rulesets))
        .route("/api/v1/ids/rules", get(ids::list_rules))
        .route("/api/v1/ids/rules/{id}", get(ids::get_rule))
        .route("/api/v1/ids/rules/search", get(ids::search_rules))
        .route("/api/v1/ids/suppressions", get(ids::list_suppressions))
        .route("/api/v1/ids/stats", get(ids::get_stats))
        .route(
            "/api/v1/ids/alerts/buffer-stats",
            get(ids::alert_buffer_stats),
        )
        .route("/api/v1/ai/audit-log", get(ai_analysis::get_audit_log))
        .layer(middleware::from_fn(perm_check!(Permission::IdsRead)))
}

pub(crate) fn ids_write() -> Router<AppState> {
    Router::new()
        .route("/api/v1/ids/config", put(ids::update_config))
        .route("/api/v1/ids/alerts", delete(ids::purge_alerts))
        .route(
            "/api/v1/ids/alerts/{id}/acknowledge",
            put(ids::acknowledge_alert),
        )
        .route("/api/v1/ids/alerts/{id}/classify", put(ids::classify_alert))
        .route("/api/v1/ids/rulesets", post(ids::create_ruleset))
        .route(
            "/api/v1/ids/rulesets/{id}",
            put(ids::update_ruleset).delete(ids::delete_ruleset),
        )
        .route("/api/v1/ids/rules/{id}", put(ids::update_rule))
        .route("/api/v1/ids/suppressions", post(ids::create_suppression))
        .route(
            "/api/v1/ids/suppressions/{id}",
            delete(ids::delete_suppression),
        )
        .route("/api/v1/ids/reload", post(ids::reload))
        .route("/api/v1/ai/analyze", post(ai_analysis::trigger_analysis))
        .layer(middleware::from_fn(perm_check!(Permission::IdsWrite)))
}

pub(crate) fn dns_write() -> Router<AppState> {
    Router::new()
        .route("/api/v1/dns", put(routes::update_dns))
        .route(
            "/api/v1/dns/resolver/config",
            put(dns_resolver::update_config_handler),
        )
        .route(
            "/api/v1/dns/resolver/hosts",
            post(dns_resolver::create_host),
        )
        .route(
            "/api/v1/dns/resolver/hosts/{id}",
            put(dns_resolver::update_host).delete(dns_resolver::delete_host),
        )
        .route(
            "/api/v1/dns/resolver/domains",
            post(dns_resolver::create_domain),
        )
        .route(
            "/api/v1/dns/resolver/domains/{id}",
            put(dns_resolver::update_domain).delete(dns_resolver::delete_domain),
        )
        .route("/api/v1/dns/resolver/acls", post(dns_resolver::create_acl))
        .route(
            "/api/v1/dns/resolver/acls/{id}",
            delete(dns_resolver::delete_acl),
        )
        .route(
            "/api/v1/dns/resolver/apply",
            post(dns_resolver::apply_resolver),
        )
        .route(
            "/api/v1/dns/resolver/start",
            post(dns_resolver::resolver_start),
        )
        .route(
            "/api/v1/dns/resolver/stop",
            post(dns_resolver::resolver_stop),
        )
        .route(
            "/api/v1/dns/resolver/restart",
            post(dns_resolver::resolver_restart),
        )
        .route(
            "/api/v1/dns/blocklists",
            post(dns_blocklists::create_source),
        )
        .route(
            "/api/v1/dns/blocklists/{id}",
            put(dns_blocklists::update_source).delete(dns_blocklists::delete_source),
        )
        .route(
            "/api/v1/dns/blocklists/{id}/refresh",
            post(dns_blocklists::refresh_one),
        )
        .route(
            "/api/v1/dns/blocklists/refresh-all",
            post(dns_blocklists::refresh_everything),
        )
        .route(
            "/api/v1/dns/blocklists/schedule",
            put(dns_blocklists::put_schedule),
        )
        .route(
            "/api/v1/dns/blocklists/enabled",
            put(dns_blocklists::set_enabled),
        )
        .route(
            "/api/v1/dns/whitelist",
            post(dns_blocklists::create_whitelist),
        )
        .route(
            "/api/v1/dns/whitelist/{id}",
            delete(dns_blocklists::delete_whitelist),
        )
        .route(
            "/api/v1/dns/customblocks",
            post(dns_blocklists::create_customblock),
        )
        .route(
            "/api/v1/dns/customblocks/{id}",
            delete(dns_blocklists::delete_customblock),
        )
        .layer(middleware::from_fn(perm_check!(Permission::DnsWrite)))
}

pub(crate) fn dhcp_read() -> Router<AppState> {
    Router::new()
        .route("/api/v1/dhcp/status", get(dhcp::dhcp_status))
        .route("/api/v1/dhcp/v4/config", get(dhcp::get_config))
        .route("/api/v1/dhcp/v4/subnets", get(dhcp::list_subnets))
        .route("/api/v1/dhcp/v4/reservations", get(dhcp::list_reservations))
        .route("/api/v1/dhcp/v4/leases", get(dhcp::list_leases))
        .route("/api/v1/dhcp/ddns", get(dhcp::get_ddns_config))
        .route("/api/v1/dhcp/ha/config", get(dhcp::get_ha_config))
        .route("/api/v1/dhcp/ha/status", get(dhcp::get_ha_status))
        .route("/api/v1/dhcp/pool-stats", get(dhcp::get_pool_stats))
        .route("/api/v1/dhcp/metrics", get(dhcp::get_metrics))
        .route("/api/v1/dhcp/logs", get(dhcp::dhcp_logs))
        .layer(middleware::from_fn(perm_check!(Permission::DhcpRead)))
}

pub(crate) fn dhcp_write() -> Router<AppState> {
    Router::new()
        .route("/api/v1/dhcp/start", post(dhcp::dhcp_start))
        .route("/api/v1/dhcp/stop", post(dhcp::dhcp_stop))
        .route("/api/v1/dhcp/restart", post(dhcp::dhcp_restart))
        .route("/api/v1/dhcp/v4/config", put(dhcp::update_config))
        .route("/api/v1/dhcp/v4/subnets", post(dhcp::create_subnet))
        .route(
            "/api/v1/dhcp/v4/subnets/{id}",
            put(dhcp::update_subnet).delete(dhcp::delete_subnet),
        )
        .route(
            "/api/v1/dhcp/v4/reservations",
            post(dhcp::create_reservation),
        )
        .route(
            "/api/v1/dhcp/v4/reservations/{id}",
            put(dhcp::update_reservation).delete(dhcp::delete_reservation),
        )
        .route("/api/v1/dhcp/v4/leases/{ip}", delete(dhcp::release_lease))
        .route("/api/v1/dhcp/v4/apply", post(dhcp::apply_config))
        .route("/api/v1/dhcp/ddns", put(dhcp::update_ddns_config))
        .route("/api/v1/dhcp/ha/config", put(dhcp::update_ha_config))
        .layer(middleware::from_fn(perm_check!(Permission::DhcpWrite)))
}

pub(crate) fn aliases_read() -> Router<AppState> {
    Router::new()
        .route("/api/v1/aliases", get(aliases::list_aliases))
        .route("/api/v1/aliases/{id}", get(aliases::get_alias))
        .layer(middleware::from_fn(perm_check!(Permission::AliasesRead)))
}

pub(crate) fn aliases_write() -> Router<AppState> {
    Router::new()
        .route("/api/v1/aliases", post(aliases::create_alias))
        .route(
            "/api/v1/aliases/{id}",
            put(aliases::update_alias).delete(aliases::delete_alias),
        )
        .layer(middleware::from_fn(perm_check!(Permission::AliasesWrite)))
}

pub(crate) fn ifaces_read() -> Router<AppState> {
    Router::new()
        .route("/api/v1/interfaces", get(routes::list_interfaces))
        .route(
            "/api/v1/interfaces/detailed",
            get(iface::list_interfaces_detailed),
        )
        .route("/api/v1/interfaces/roles", get(iface::list_interface_roles))
        .route(
            "/api/v1/interfaces/{name}/stats",
            get(routes::get_interface_stats),
        )
        .route("/api/v1/vlans", get(iface::list_vlans))
        .route("/api/v1/routes", get(routes::list_static_routes))
        .route("/api/v1/routes/system", get(routes::get_system_routes))
        .layer(middleware::from_fn(perm_check!(Permission::InterfacesRead)))
}

pub(crate) fn ifaces_write() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/interfaces/{name}/role",
            put(iface::set_interface_role).delete(iface::delete_interface_role),
        )
        .route(
            "/api/v1/interfaces/config/{name}",
            put(iface::configure_interface),
        )
        .route("/api/v1/vlans", post(iface::create_vlan))
        .route(
            "/api/v1/vlans/{id}",
            put(iface::update_vlan).delete(iface::delete_vlan),
        )
        .route("/api/v1/routes", post(routes::create_static_route))
        .route(
            "/api/v1/routes/{id}",
            put(routes::update_static_route).delete(routes::delete_static_route),
        )
        .layer(middleware::from_fn(perm_check!(
            Permission::InterfacesWrite
        )))
}

pub(crate) fn connections_view() -> Router<AppState> {
    Router::new()
        .route("/api/v1/connections", get(routes::list_connections))
        .route("/api/v1/blocked", get(routes::list_blocked_traffic))
        .layer(middleware::from_fn(perm_check!(
            Permission::ConnectionsView
        )))
}

pub(crate) fn logs_view() -> Router<AppState> {
    Router::new()
        .route("/api/v1/logs", get(routes::list_logs))
        .layer(middleware::from_fn(perm_check!(Permission::LogsView)))
}

pub(crate) fn users_read() -> Router<AppState> {
    Router::new()
        .route("/api/v1/auth/users", get(routes::list_users))
        .route("/api/v1/auth/users/{id}", get(routes::get_user))
        .route("/api/v1/auth/audit", get(routes::list_user_audit))
        .route("/api/v1/auth/roles", get(routes::list_roles))
        .route("/api/v1/auth/permissions", get(routes::list_permissions))
        .layer(middleware::from_fn(perm_check!(Permission::UsersRead)))
}

pub(crate) fn users_write() -> Router<AppState> {
    Router::new()
        .route("/api/v1/auth/users", post(routes::create_user))
        .route(
            "/api/v1/auth/users/{id}",
            put(routes::update_user).delete(routes::delete_user_handler),
        )
        .route("/api/v1/auth/api-keys", post(routes::create_api_key))
        .route("/api/v1/auth/roles", post(routes::create_role))
        .route(
            "/api/v1/auth/roles/{id}",
            put(routes::update_role).delete(routes::delete_role),
        )
        .layer(middleware::from_fn(perm_check!(Permission::UsersWrite)))
}

pub(crate) fn settings_read() -> Router<AppState> {
    Router::new()
        .route("/api/v1/auth/settings", get(routes::get_auth_settings))
        .route(
            "/api/v1/auth/oauth/providers",
            get(routes::list_oauth_providers),
        )
        .route("/api/v1/settings/tls", get(routes::get_tls_settings))
        .route("/api/v1/settings/valkey", get(routes::get_valkey_settings))
        .route(
            "/api/v1/settings/dashboard-history",
            get(routes::get_dashboard_history_settings),
        )
        .route(
            "/api/v1/settings/ids-alerts",
            get(routes::get_ids_alert_settings),
        )
        .route("/api/v1/settings/pf-tuning", get(routes::get_pf_tuning))
        .route(
            "/api/v1/settings/{section}",
            get(routes::get_generic_settings),
        )
        .route("/api/v1/settings/ai", get(routes::get_ai_settings))
        .route("/api/v1/settings/ai/models", get(routes::list_ai_models))
        .route("/api/v1/ca", get(ca::get_ca_info))
        .route("/api/v1/ca/cert.pem", get(ca::get_ca_cert_pem))
        .route("/api/v1/ca/crl", get(ca::get_crl))
        .route("/api/v1/ca/certs", get(ca::list_certs))
        .route("/api/v1/ca/certs/{id}", get(ca::get_cert))
        .route("/api/v1/ca/certs/{id}/cert.pem", get(ca::download_cert))
        .route("/api/v1/time/status", get(time_service::time_status))
        .route("/api/v1/time/config", get(time_service::get_config))
        .route("/api/v1/time/sources", get(time_service::list_sources))
        .route("/api/v1/time/logs", get(time_service::time_logs))
        .route("/api/v1/acme/account", get(acme::get_account))
        .route("/api/v1/acme/certs", get(acme::list_certs))
        .route("/api/v1/acme/certs/{id}", get(acme::get_cert))
        .route(
            "/api/v1/acme/certs/{id}/cert.pem",
            get(acme::download_cert_pem),
        )
        .route("/api/v1/acme/dns-providers", get(acme::list_providers))
        .route(
            "/api/v1/acme/certs/{cert_id}/targets",
            get(acme::list_targets),
        )
        .route("/api/v1/ddns/records", get(acme::list_ddns))
        .route("/api/v1/ddns/config", get(acme::get_ddns_config))
        .layer(middleware::from_fn(perm_check!(Permission::SettingsRead)))
}

pub(crate) fn settings_write() -> Router<AppState> {
    Router::new()
        .route("/api/v1/auth/settings", put(routes::update_auth_settings))
        .route(
            "/api/v1/auth/oauth/providers",
            post(routes::create_oauth_provider),
        )
        .route(
            "/api/v1/auth/oauth/providers/{id}",
            delete(routes::delete_oauth_provider),
        )
        .route("/api/v1/settings/tls", put(routes::update_tls_settings))
        .route(
            "/api/v1/settings/valkey",
            put(routes::update_valkey_settings),
        )
        .route(
            "/api/v1/settings/dashboard-history",
            put(routes::update_dashboard_history_settings),
        )
        .route(
            "/api/v1/settings/ids-alerts",
            put(routes::update_ids_alert_settings),
        )
        .route("/api/v1/settings/pf-tuning", put(routes::put_pf_tuning))
        .route(
            "/api/v1/settings/{section}",
            put(routes::update_generic_settings),
        )
        .route("/api/v1/settings/ai", put(routes::update_ai_settings))
        .route("/api/v1/settings/ai/test", post(routes::test_ai_provider))
        .route("/api/v1/ca", post(ca::generate_ca))
        .route("/api/v1/ca/certs", post(ca::issue_cert))
        .route("/api/v1/ca/certs/{id}", delete(ca::delete_cert))
        .route("/api/v1/ca/certs/{id}/key.pem", get(ca::download_cert_key))
        .route("/api/v1/ca/certs/{id}/revoke", post(ca::revoke_cert))
        .route("/api/v1/time/config", put(time_service::update_config))
        .route("/api/v1/time/sources", post(time_service::create_source))
        .route(
            "/api/v1/time/sources/{id}",
            put(time_service::update_source).delete(time_service::delete_source),
        )
        .route("/api/v1/time/start", post(time_service::time_start))
        .route("/api/v1/time/stop", post(time_service::time_stop))
        .route("/api/v1/time/restart", post(time_service::time_restart))
        .route("/api/v1/time/apply", post(time_service::apply_config))
        .route("/api/v1/acme/account", put(acme::put_account))
        .route("/api/v1/acme/certs", post(acme::create_cert))
        .route("/api/v1/acme/certs/{id}", delete(acme::delete_cert))
        .route("/api/v1/acme/certs/{id}/renew", post(acme::renew_now))
        .route("/api/v1/acme/certs/{id}/publish", post(acme::publish_now))
        .route(
            "/api/v1/acme/certs/{id}/key.pem",
            get(acme::download_key_pem),
        )
        .route("/api/v1/acme/dns-providers", post(acme::create_provider))
        .route(
            "/api/v1/acme/dns-providers/{id}",
            put(acme::update_provider).delete(acme::delete_provider),
        )
        .route(
            "/api/v1/acme/dns-providers/{id}/test",
            post(acme::test_provider),
        )
        .route(
            "/api/v1/acme/certs/{cert_id}/targets",
            post(acme::create_target),
        )
        .route(
            "/api/v1/acme/export-targets/{id}",
            delete(acme::delete_target),
        )
        .route("/api/v1/ddns/records", post(acme::create_ddns))
        .route(
            "/api/v1/ddns/records/{id}",
            put(acme::update_ddns).delete(acme::delete_ddns),
        )
        .route(
            "/api/v1/ddns/records/{id}/update",
            post(acme::force_update_ddns),
        )
        .route("/api/v1/ddns/config", put(acme::put_ddns_config))
        .layer(middleware::from_fn(perm_check!(Permission::SettingsWrite)))
}

pub(crate) fn plugins_read() -> Router<AppState> {
    Router::new()
        .route("/api/v1/plugins", get(plugins::list_plugins))
        .route("/api/v1/plugins/{name}/logs", get(plugins::get_plugin_logs))
        .route(
            "/api/v1/plugins/{name}/config",
            get(plugins::get_plugin_config),
        )
        .route("/api/v1/plugins/discover", get(plugins::discover_plugins))
        .layer(middleware::from_fn(perm_check!(Permission::PluginsRead)))
}

pub(crate) fn plugins_write() -> Router<AppState> {
    Router::new()
        .route("/api/v1/plugins/toggle", post(plugins::enable_plugin))
        .route(
            "/api/v1/plugins/{name}/config",
            put(plugins::update_plugin_config),
        )
        .layer(middleware::from_fn(perm_check!(Permission::PluginsWrite)))
}

pub(crate) fn updates_read() -> Router<AppState> {
    Router::new()
        .route("/api/v1/updates/status", get(updates::update_status))
        .route("/api/v1/updates/check", post(updates::check_updates))
        .route("/api/v1/updates/schedule", get(updates::get_schedule))
        .route("/api/v1/updates/history", get(updates::update_history))
        .route(
            "/api/v1/updates/aifw/status",
            get(updates::aifw_update_status),
        )
        .route(
            "/api/v1/updates/aifw/check",
            post(updates::aifw_check_update),
        )
        .layer(middleware::from_fn(perm_check!(Permission::UpdatesRead)))
}

pub(crate) fn updates_install() -> Router<AppState> {
    Router::new()
        .route("/api/v1/updates/install", post(updates::install_updates))
        .route("/api/v1/updates/schedule", put(updates::update_schedule))
        .route(
            "/api/v1/updates/aifw/install",
            post(updates::aifw_install_update),
        )
        .route(
            "/api/v1/updates/aifw/rollback",
            post(updates::aifw_rollback),
        )
        .route(
            "/api/v1/updates/aifw/restart",
            post(updates::aifw_restart_services),
        )
        .route("/api/v1/updates/aifw/reboot", post(updates::aifw_reboot))
        .route(
            "/api/v1/updates/aifw/prerelease",
            post(updates::set_prerelease_channel),
        )
        .layer(middleware::from_fn(perm_check!(Permission::UpdatesInstall)))
}

/// Local-tarball install — needs a large body limit (500 MB) for the
/// tarball upload, so it gets its own router with DefaultBodyLimit applied
/// before the auth/permission middleware. The perm_check is still applied
/// so only UpdatesInstall-capable sessions can trigger it.
pub(crate) fn updates_install_local() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/updates/aifw/install-local",
            post(updates::install_aifw_update_local),
        )
        .layer(axum::extract::DefaultBodyLimit::max(500 * 1024 * 1024))
        .layer(middleware::from_fn(perm_check!(Permission::UpdatesInstall)))
}

pub(crate) fn backup_read() -> Router<AppState> {
    Router::new()
        .route("/api/v1/config/history", get(backup::config_history))
        .route("/api/v1/config/version", get(backup::get_version))
        .route("/api/v1/config/diff", get(backup::diff_versions))
        .route("/api/v1/config/check", get(backup::check_config))
        .route("/api/v1/config/export", get(routes::export_config))
        .route(
            "/api/v1/config/preview-opnsense",
            post(opnsense::preview_opnsense)
                .layer(axum::extract::DefaultBodyLimit::max(15 * 1024 * 1024)),
        )
        .route(
            "/api/v1/config/import-preview",
            post(backup::preview_import),
        )
        .route(
            "/api/v1/config/restore-preview",
            get(backup::preview_restore),
        )
        .route(
            "/api/v1/config/commit-confirm/status",
            get(backup::commit_confirm_status),
        )
        .route("/api/v1/config/retention", get(backup::get_retention))
        .route("/api/v1/backup/s3/config", get(backup_s3::get_s3_config))
        .route("/api/v1/backup/s3/list", get(backup_s3::list_s3))
        .route(
            "/api/v1/notify/smtp/config",
            get(backup_s3::get_smtp_config),
        )
        .layer(middleware::from_fn(perm_check!(Permission::BackupRead)))
}

pub(crate) fn backup_write() -> Router<AppState> {
    Router::new()
        .route("/api/v1/config/import", post(routes::import_config))
        .route("/api/v1/config/restore", post(backup::restore_version))
        .route(
            "/api/v1/config/import-opnsense",
            post(opnsense::import_opnsense)
                .layer(axum::extract::DefaultBodyLimit::max(15 * 1024 * 1024)),
        )
        .route("/api/v1/config/save", post(backup::save_version))
        .route(
            "/api/v1/config/commit-confirm",
            post(backup::commit_confirm_start),
        )
        .route(
            "/api/v1/config/commit-confirm/confirm",
            post(backup::commit_confirm_accept),
        )
        .route("/api/v1/config/retention", put(backup::put_retention))
        .route("/api/v1/backup/s3/config", put(backup_s3::put_s3_config))
        .route("/api/v1/backup/s3/test", post(backup_s3::test_s3))
        .route("/api/v1/backup/s3/import", post(backup_s3::import_s3))
        .route(
            "/api/v1/notify/smtp/config",
            put(backup_s3::put_smtp_config),
        )
        .route("/api/v1/notify/smtp/test", post(backup_s3::test_smtp))
        .layer(middleware::from_fn(perm_check!(Permission::BackupWrite)))
}

pub(crate) fn system_read() -> Router<AppState> {
    Router::new()
        .route("/api/v1/system/general", get(system::get_general))
        .route("/api/v1/system/banner", get(system::get_banner))
        .route("/api/v1/system/ssh", get(system::get_ssh))
        .route("/api/v1/system/console", get(system::get_console))
        .route("/api/v1/system/info", get(system::get_info))
        .route("/api/v1/system/timezones", get(system::list_timezones))
        .layer(middleware::from_fn(perm_check!(Permission::SettingsRead)))
}

pub(crate) fn system_write() -> Router<AppState> {
    Router::new()
        .route("/api/v1/system/general", put(system::put_general))
        .route("/api/v1/system/banner", put(system::put_banner))
        .route("/api/v1/system/ssh", put(system::put_ssh))
        .route("/api/v1/system/console", put(system::put_console))
        .layer(middleware::from_fn(perm_check!(Permission::SettingsWrite)))
}

pub(crate) fn system_reboot() -> Router<AppState> {
    Router::new()
        .route("/api/v1/updates/reboot", post(updates::reboot_system))
        .route("/api/v1/updates/shutdown", post(updates::shutdown_system))
        .route("/api/v1/multiwan/enable-fibs", post(multiwan::enable_fibs))
        .layer(middleware::from_fn(perm_check!(Permission::SystemReboot)))
}

pub(crate) fn proxy_read() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/reverse-proxy/status",
            get(reverse_proxy::rp_status),
        )
        .route(
            "/api/v1/reverse-proxy/config",
            get(reverse_proxy::get_config),
        )
        .route("/api/v1/reverse-proxy/logs", get(reverse_proxy::rp_logs))
        .route(
            "/api/v1/reverse-proxy/entrypoints",
            get(reverse_proxy::list_entrypoints),
        )
        .route(
            "/api/v1/reverse-proxy/http/routers",
            get(reverse_proxy::list_http_routers),
        )
        .route(
            "/api/v1/reverse-proxy/http/services",
            get(reverse_proxy::list_http_services),
        )
        .route(
            "/api/v1/reverse-proxy/http/middlewares",
            get(reverse_proxy::list_http_middlewares),
        )
        .route(
            "/api/v1/reverse-proxy/tcp/routers",
            get(reverse_proxy::list_tcp_routers),
        )
        .route(
            "/api/v1/reverse-proxy/tcp/services",
            get(reverse_proxy::list_tcp_services),
        )
        .route(
            "/api/v1/reverse-proxy/udp/routers",
            get(reverse_proxy::list_udp_routers),
        )
        .route(
            "/api/v1/reverse-proxy/udp/services",
            get(reverse_proxy::list_udp_services),
        )
        .route(
            "/api/v1/reverse-proxy/tls/certs",
            get(reverse_proxy::list_tls_certs),
        )
        .route(
            "/api/v1/reverse-proxy/tls/options",
            get(reverse_proxy::list_tls_options),
        )
        .route(
            "/api/v1/reverse-proxy/cert-resolvers",
            get(reverse_proxy::list_cert_resolvers),
        )
        .layer(middleware::from_fn(perm_check!(Permission::ProxyRead)))
}

pub(crate) fn proxy_write() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/reverse-proxy/config",
            put(reverse_proxy::update_config),
        )
        .route(
            "/api/v1/reverse-proxy/validate",
            post(reverse_proxy::validate_config),
        )
        .route(
            "/api/v1/reverse-proxy/entrypoints",
            post(reverse_proxy::create_entrypoint),
        )
        .route(
            "/api/v1/reverse-proxy/entrypoints/{id}",
            put(reverse_proxy::update_entrypoint).delete(reverse_proxy::delete_entrypoint),
        )
        .route(
            "/api/v1/reverse-proxy/http/routers",
            post(reverse_proxy::create_http_router),
        )
        .route(
            "/api/v1/reverse-proxy/http/routers/{id}",
            put(reverse_proxy::update_http_router).delete(reverse_proxy::delete_http_router),
        )
        .route(
            "/api/v1/reverse-proxy/http/services",
            post(reverse_proxy::create_http_service),
        )
        .route(
            "/api/v1/reverse-proxy/http/services/{id}",
            put(reverse_proxy::update_http_service).delete(reverse_proxy::delete_http_service),
        )
        .route(
            "/api/v1/reverse-proxy/http/middlewares",
            post(reverse_proxy::create_http_middleware),
        )
        .route(
            "/api/v1/reverse-proxy/http/middlewares/{id}",
            put(reverse_proxy::update_http_middleware)
                .delete(reverse_proxy::delete_http_middleware),
        )
        .route(
            "/api/v1/reverse-proxy/tcp/routers",
            post(reverse_proxy::create_tcp_router),
        )
        .route(
            "/api/v1/reverse-proxy/tcp/routers/{id}",
            put(reverse_proxy::update_tcp_router).delete(reverse_proxy::delete_tcp_router),
        )
        .route(
            "/api/v1/reverse-proxy/tcp/services",
            post(reverse_proxy::create_tcp_service),
        )
        .route(
            "/api/v1/reverse-proxy/tcp/services/{id}",
            put(reverse_proxy::update_tcp_service).delete(reverse_proxy::delete_tcp_service),
        )
        .route(
            "/api/v1/reverse-proxy/udp/routers",
            post(reverse_proxy::create_udp_router),
        )
        .route(
            "/api/v1/reverse-proxy/udp/routers/{id}",
            put(reverse_proxy::update_udp_router).delete(reverse_proxy::delete_udp_router),
        )
        .route(
            "/api/v1/reverse-proxy/udp/services",
            post(reverse_proxy::create_udp_service),
        )
        .route(
            "/api/v1/reverse-proxy/udp/services/{id}",
            put(reverse_proxy::update_udp_service).delete(reverse_proxy::delete_udp_service),
        )
        .route(
            "/api/v1/reverse-proxy/tls/certs",
            post(reverse_proxy::create_tls_cert),
        )
        .route(
            "/api/v1/reverse-proxy/tls/certs/{id}",
            put(reverse_proxy::update_tls_cert).delete(reverse_proxy::delete_tls_cert),
        )
        .route(
            "/api/v1/reverse-proxy/tls/options",
            post(reverse_proxy::create_tls_option),
        )
        .route(
            "/api/v1/reverse-proxy/tls/options/{id}",
            put(reverse_proxy::update_tls_option).delete(reverse_proxy::delete_tls_option),
        )
        .route(
            "/api/v1/reverse-proxy/cert-resolvers",
            post(reverse_proxy::create_cert_resolver),
        )
        .route(
            "/api/v1/reverse-proxy/cert-resolvers/{id}",
            put(reverse_proxy::update_cert_resolver).delete(reverse_proxy::delete_cert_resolver),
        )
        .route("/api/v1/reverse-proxy/start", post(reverse_proxy::rp_start))
        .route("/api/v1/reverse-proxy/stop", post(reverse_proxy::rp_stop))
        .route(
            "/api/v1/reverse-proxy/restart",
            post(reverse_proxy::rp_restart),
        )
        .route(
            "/api/v1/reverse-proxy/apply",
            post(reverse_proxy::apply_config),
        )
        .layer(middleware::from_fn(perm_check!(Permission::ProxyWrite)))
}

pub(crate) fn multiwan_read() -> Router<AppState> {
    Router::new()
        .route("/api/v1/multiwan/instances", get(multiwan::list_instances))
        .route(
            "/api/v1/multiwan/instances/{id}",
            get(multiwan::get_instance),
        )
        .route(
            "/api/v1/multiwan/instances/{id}/members",
            get(multiwan::list_members),
        )
        .route("/api/v1/multiwan/fibs", get(multiwan::list_fibs))
        .route("/api/v1/multiwan/gateways", get(multiwan::list_gateways))
        .route("/api/v1/multiwan/gateways/{id}", get(multiwan::get_gateway))
        .route(
            "/api/v1/multiwan/gateways/{id}/events",
            get(multiwan::list_gateway_events),
        )
        .route("/api/v1/multiwan/groups", get(multiwan::list_groups))
        .route(
            "/api/v1/multiwan/groups/{id}/members",
            get(multiwan::list_group_members),
        )
        .route(
            "/api/v1/multiwan/groups/{id}/active",
            get(multiwan::group_active),
        )
        .route("/api/v1/multiwan/policies", get(multiwan::list_policies))
        .route("/api/v1/multiwan/leaks", get(multiwan::list_leaks))
        .route("/api/v1/multiwan/flows", get(multiwan::list_flows))
        .route("/api/v1/multiwan/gateways/{id}/sla", get(multiwan::get_sla))
        .route("/api/v1/multiwan/config.yaml", get(multiwan::export_config))
        .layer(middleware::from_fn(perm_check!(Permission::MultiWanRead)))
}

pub(crate) fn multiwan_write() -> Router<AppState> {
    Router::new()
        .route(
            "/api/v1/multiwan/instances",
            post(multiwan::create_instance),
        )
        .route(
            "/api/v1/multiwan/instances/{id}",
            put(multiwan::update_instance).delete(multiwan::delete_instance),
        )
        .route(
            "/api/v1/multiwan/instances/{id}/members",
            post(multiwan::add_member),
        )
        .route(
            "/api/v1/multiwan/instances/{id}/members/{iface}",
            delete(multiwan::remove_member),
        )
        .route("/api/v1/multiwan/gateways", post(multiwan::create_gateway))
        .route(
            "/api/v1/multiwan/gateways/{id}",
            put(multiwan::update_gateway).delete(multiwan::delete_gateway),
        )
        .route(
            "/api/v1/multiwan/gateways/{id}/probe-now",
            post(multiwan::probe_now),
        )
        .route("/api/v1/multiwan/groups", post(multiwan::create_group))
        .route(
            "/api/v1/multiwan/groups/{id}",
            put(multiwan::update_group).delete(multiwan::delete_group),
        )
        .route(
            "/api/v1/multiwan/groups/{id}/members",
            post(multiwan::add_group_member),
        )
        .route(
            "/api/v1/multiwan/groups/{id}/members/{gw}",
            delete(multiwan::remove_group_member),
        )
        .route("/api/v1/multiwan/policies", post(multiwan::create_policy))
        .route(
            "/api/v1/multiwan/policies/{id}",
            put(multiwan::update_policy).delete(multiwan::delete_policy),
        )
        .route("/api/v1/multiwan/apply", post(multiwan::apply_policies))
        .route(
            "/api/v1/multiwan/policies/reorder",
            put(multiwan::reorder_policies),
        )
        .route(
            "/api/v1/multiwan/policies/{id}/duplicate",
            post(multiwan::duplicate_policy),
        )
        .route(
            "/api/v1/multiwan/policies/{id}/toggle",
            put(multiwan::toggle_policy),
        )
        .route("/api/v1/multiwan/leaks", post(multiwan::create_leak))
        .route("/api/v1/multiwan/leaks/{id}", delete(multiwan::delete_leak))
        .route(
            "/api/v1/multiwan/leaks/seed-mgmt",
            post(multiwan::seed_mgmt_escapes),
        )
        .route("/api/v1/multiwan/preview", post(multiwan::preview_policies))
        .route(
            "/api/v1/multiwan/flows/{label}/migrate",
            post(multiwan::migrate_flow),
        )
        .route("/api/v1/multiwan/apply-yaml", post(multiwan::import_config))
        .layer(middleware::from_fn(perm_check!(Permission::MultiWanWrite)))
}

pub(crate) fn cluster_read() -> Router<AppState> {
    cluster::read_routes().layer(middleware::from_fn(perm_check!(Permission::HaManage)))
}

pub(crate) fn cluster_write() -> Router<AppState> {
    cluster::write_routes().layer(middleware::from_fn(perm_check!(Permission::HaManage)))
}
