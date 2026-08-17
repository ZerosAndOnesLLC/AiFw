//! Rule-header variable resolution (`$HOME_NET`, `$HTTP_PORTS`, …).
//!
//! Suricata rules reference address and port groups by name. Before #485
//! the engine treated any `$`-prefixed constraint as "matches everything",
//! so a rule scoped to `$HOME_NET -> $EXTERNAL_NET` fired on traffic in
//! either direction — a silent false-positive source on every deployment.
//!
//! `$HOME_NET` / `$EXTERNAL_NET` come from [`IdsConfig`]; the remaining
//! names carry the defaults from stock `suricata.yaml` (server groups all
//! alias `$HOME_NET`). Unknown variables resolve to *nothing* — the
//! constraint can never match, which is the fail-closed choice — and are
//! logged once so the operator can see which rules are inert.

use std::sync::LazyLock;

use aifw_common::ids::IdsConfig;
use dashmap::DashSet;

/// Address-group variables that stock Suricata defines as `$HOME_NET`.
const HOME_NET_ALIASES: &[&str] = &[
    "HTTP_SERVERS",
    "SMTP_SERVERS",
    "SQL_SERVERS",
    "DNS_SERVERS",
    "TELNET_SERVERS",
    "AIM_SERVERS",
    "DC_SERVERS",
    "DNP3_SERVER",
    "DNP3_CLIENT",
    "MODBUS_SERVER",
    "MODBUS_CLIENT",
    "ENIP_SERVER",
    "ENIP_CLIENT",
];

/// Port-group variables and their stock `suricata.yaml` values.
const PORT_VARS: &[(&str, &str)] = &[
    (
        "HTTP_PORTS",
        "[80,81,311,383,591,593,901,1220,1414,1741,1830,2301,2381,2809,3037,3128,3702,4343,4848,5250,6988,7000,7001,7144,7145,7510,7777,7779,8000,8008,8014,8028,8080,8085,8088,8090,8118,8123,8180,8181,8243,8280,8300,8800,8888,8899,9000,9060,9080,9090,9091,9443,9999,11371,34443,34444,41080,50002,55555]",
    ),
    ("SHELLCODE_PORTS", "!80"),
    ("ORACLE_PORTS", "1521"),
    ("SSH_PORTS", "22"),
    ("DNP3_PORTS", "20000"),
    ("MODBUS_PORTS", "502"),
    ("FILE_DATA_PORTS", "[$HTTP_PORTS,110,143]"),
    ("FTP_PORTS", "21"),
    ("GENEVE_PORTS", "6081"),
    ("VXLAN_PORTS", "4789"),
    ("TEREDO_PORTS", "3544"),
];

/// A resolved address-group variable.
pub enum AddressVar<'a> {
    /// The variable expands to these entries (each a CIDR, IP, `!`-negated
    /// entry, or nested variable), matched with group semantics.
    Group(&'a [String]),
    /// Not a known variable: matches nothing.
    Unknown,
}

/// Resolve `$NAME` (or `NAME`) to its address group under `cfg`.
pub fn resolve_address_var<'a>(cfg: &'a IdsConfig, var: &str) -> AddressVar<'a> {
    let name = var.strip_prefix('$').unwrap_or(var);
    if name == "HOME_NET" || HOME_NET_ALIASES.contains(&name) {
        return AddressVar::Group(&cfg.home_net);
    }
    if name == "EXTERNAL_NET" {
        return AddressVar::Group(&cfg.external_net);
    }
    AddressVar::Unknown
}

/// Resolve `$NAME` (or `NAME`) to its port constraint text, or `None`
/// for an unknown variable.
pub fn resolve_port_var(var: &str) -> Option<&'static str> {
    let name = var.strip_prefix('$').unwrap_or(var);
    PORT_VARS.iter().find(|(n, _)| *n == name).map(|(_, v)| *v)
}

/// Maximum nesting when a variable's expansion references another
/// variable (`$EXTERNAL_NET` → `!$HOME_NET`). Deeper than this is a
/// configuration loop, not a real ruleset.
pub const MAX_VAR_DEPTH: u8 = 8;

static WARNED: LazyLock<DashSet<String>> = LazyLock::new(DashSet::new);

/// Log an unknown-variable reference once per name per process so the
/// operator learns which rules are inert without flooding the log.
pub fn warn_unknown_once(kind: &str, var: &str) {
    if WARNED.insert(var.to_string()) {
        tracing::warn!(
            variable = var,
            "IDS rule references an undefined {kind} variable — the constraint will never match"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn home_net_and_aliases_resolve_to_config() {
        let cfg = IdsConfig {
            home_net: vec!["10.0.0.0/8".into()],
            ..IdsConfig::default()
        };
        for v in ["$HOME_NET", "HOME_NET", "$HTTP_SERVERS", "$DNS_SERVERS"] {
            match resolve_address_var(&cfg, v) {
                AddressVar::Group(g) => assert_eq!(g, &["10.0.0.0/8".to_string()]),
                AddressVar::Unknown => panic!("{v} should resolve"),
            }
        }
        match resolve_address_var(&cfg, "$EXTERNAL_NET") {
            AddressVar::Group(g) => assert_eq!(g, &["!$HOME_NET".to_string()]),
            AddressVar::Unknown => panic!("EXTERNAL_NET should resolve"),
        }
        assert!(matches!(
            resolve_address_var(&cfg, "$NOPE"),
            AddressVar::Unknown
        ));
    }

    #[test]
    fn port_vars_have_suricata_defaults() {
        assert_eq!(resolve_port_var("$SSH_PORTS"), Some("22"));
        assert_eq!(resolve_port_var("SHELLCODE_PORTS"), Some("!80"));
        assert!(resolve_port_var("$HTTP_PORTS").unwrap().contains(",8080,"));
        assert_eq!(resolve_port_var("$WHATEVER_PORTS"), None);
    }
}
