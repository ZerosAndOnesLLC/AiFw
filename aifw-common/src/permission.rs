use serde::{Deserialize, Serialize};

/// All granular permissions in the system.
/// Each variant has a fixed bit index used for the u64 bitmask in JWT claims.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    DashboardView,
    RulesRead,
    RulesWrite,
    NatRead,
    NatWrite,
    VpnRead,
    VpnWrite,
    GeoipRead,
    GeoipWrite,
    IdsRead,
    IdsWrite,
    DnsRead,
    DnsWrite,
    DhcpRead,
    DhcpWrite,
    AliasesRead,
    AliasesWrite,
    InterfacesRead,
    InterfacesWrite,
    ConnectionsView,
    LogsView,
    UsersRead,
    UsersWrite,
    SettingsRead,
    SettingsWrite,
    PluginsRead,
    PluginsWrite,
    UpdatesRead,
    UpdatesInstall,
    BackupRead,
    BackupWrite,
    SystemReboot,
    ProxyRead,
    ProxyWrite,
    MultiWanRead,
    MultiWanWrite,
    HaManage,
}

impl Permission {
    /// Bit index for this permission in the bitmask (0..36).
    pub fn bit_index(self) -> u8 {
        self as u8
    }

    /// String representation (e.g. "rules:read").
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DashboardView => "dashboard:view",
            Self::RulesRead => "rules:read",
            Self::RulesWrite => "rules:write",
            Self::NatRead => "nat:read",
            Self::NatWrite => "nat:write",
            Self::VpnRead => "vpn:read",
            Self::VpnWrite => "vpn:write",
            Self::GeoipRead => "geoip:read",
            Self::GeoipWrite => "geoip:write",
            Self::IdsRead => "ids:read",
            Self::IdsWrite => "ids:write",
            Self::DnsRead => "dns:read",
            Self::DnsWrite => "dns:write",
            Self::DhcpRead => "dhcp:read",
            Self::DhcpWrite => "dhcp:write",
            Self::AliasesRead => "aliases:read",
            Self::AliasesWrite => "aliases:write",
            Self::InterfacesRead => "interfaces:read",
            Self::InterfacesWrite => "interfaces:write",
            Self::ConnectionsView => "connections:view",
            Self::LogsView => "logs:view",
            Self::UsersRead => "users:read",
            Self::UsersWrite => "users:write",
            Self::SettingsRead => "settings:read",
            Self::SettingsWrite => "settings:write",
            Self::PluginsRead => "plugins:read",
            Self::PluginsWrite => "plugins:write",
            Self::UpdatesRead => "updates:read",
            Self::UpdatesInstall => "updates:install",
            Self::BackupRead => "backup:read",
            Self::BackupWrite => "backup:write",
            Self::SystemReboot => "system:reboot",
            Self::ProxyRead => "proxy:read",
            Self::ProxyWrite => "proxy:write",
            Self::MultiWanRead => "multiwan:read",
            Self::MultiWanWrite => "multiwan:write",
            Self::HaManage => "ha:manage",
        }
    }

    /// Parse from string (e.g. "rules:read").
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "dashboard:view" => Some(Self::DashboardView),
            "rules:read" => Some(Self::RulesRead),
            "rules:write" => Some(Self::RulesWrite),
            "nat:read" => Some(Self::NatRead),
            "nat:write" => Some(Self::NatWrite),
            "vpn:read" => Some(Self::VpnRead),
            "vpn:write" => Some(Self::VpnWrite),
            "geoip:read" => Some(Self::GeoipRead),
            "geoip:write" => Some(Self::GeoipWrite),
            "ids:read" => Some(Self::IdsRead),
            "ids:write" => Some(Self::IdsWrite),
            "dns:read" => Some(Self::DnsRead),
            "dns:write" => Some(Self::DnsWrite),
            "dhcp:read" => Some(Self::DhcpRead),
            "dhcp:write" => Some(Self::DhcpWrite),
            "aliases:read" => Some(Self::AliasesRead),
            "aliases:write" => Some(Self::AliasesWrite),
            "interfaces:read" => Some(Self::InterfacesRead),
            "interfaces:write" => Some(Self::InterfacesWrite),
            "connections:view" => Some(Self::ConnectionsView),
            "logs:view" => Some(Self::LogsView),
            "users:read" => Some(Self::UsersRead),
            "users:write" => Some(Self::UsersWrite),
            "settings:read" => Some(Self::SettingsRead),
            "settings:write" => Some(Self::SettingsWrite),
            "plugins:read" => Some(Self::PluginsRead),
            "plugins:write" => Some(Self::PluginsWrite),
            "updates:read" => Some(Self::UpdatesRead),
            "updates:install" => Some(Self::UpdatesInstall),
            "backup:read" => Some(Self::BackupRead),
            "backup:write" => Some(Self::BackupWrite),
            "system:reboot" => Some(Self::SystemReboot),
            "proxy:read" => Some(Self::ProxyRead),
            "proxy:write" => Some(Self::ProxyWrite),
            "multiwan:read" => Some(Self::MultiWanRead),
            "multiwan:write" => Some(Self::MultiWanWrite),
            "ha:manage" => Some(Self::HaManage),
            _ => None,
        }
    }
}

impl std::fmt::Display for Permission {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// All permissions in bit-index order.
pub const ALL_PERMISSIONS: &[Permission] = &[
    Permission::DashboardView,
    Permission::RulesRead,
    Permission::RulesWrite,
    Permission::NatRead,
    Permission::NatWrite,
    Permission::VpnRead,
    Permission::VpnWrite,
    Permission::GeoipRead,
    Permission::GeoipWrite,
    Permission::IdsRead,
    Permission::IdsWrite,
    Permission::DnsRead,
    Permission::DnsWrite,
    Permission::DhcpRead,
    Permission::DhcpWrite,
    Permission::AliasesRead,
    Permission::AliasesWrite,
    Permission::InterfacesRead,
    Permission::InterfacesWrite,
    Permission::ConnectionsView,
    Permission::LogsView,
    Permission::UsersRead,
    Permission::UsersWrite,
    Permission::SettingsRead,
    Permission::SettingsWrite,
    Permission::PluginsRead,
    Permission::PluginsWrite,
    Permission::UpdatesRead,
    Permission::UpdatesInstall,
    Permission::BackupRead,
    Permission::BackupWrite,
    Permission::SystemReboot,
    Permission::ProxyRead,
    Permission::ProxyWrite,
    Permission::MultiWanRead,
    Permission::MultiWanWrite,
    Permission::HaManage,
];

/// A set of permissions stored as a u64 bitmask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PermissionSet(pub u64);

impl PermissionSet {
    pub fn new() -> Self {
        Self(0)
    }

    /// Create from a u64 bitmask (e.g. from JWT or DB).
    pub fn from_bits(bits: u64) -> Self {
        Self(bits)
    }

    /// Get the raw bitmask.
    pub fn to_bits(self) -> u64 {
        self.0
    }

    /// Check if this set contains a permission.
    pub fn has(self, perm: Permission) -> bool {
        self.0 & (1u64 << perm.bit_index()) != 0
    }

    /// Add a permission to the set.
    pub fn grant(&mut self, perm: Permission) {
        self.0 |= 1u64 << perm.bit_index();
    }

    /// Remove a permission from the set.
    pub fn revoke(&mut self, perm: Permission) {
        self.0 &= !(1u64 << perm.bit_index());
    }

    /// Create from a slice of permissions.
    pub fn from_permissions(perms: &[Permission]) -> Self {
        let mut set = Self::new();
        for &p in perms {
            set.grant(p);
        }
        set
    }

    /// Expand to a list of permission strings.
    pub fn to_strings(self) -> Vec<&'static str> {
        ALL_PERMISSIONS
            .iter()
            .filter(|&&p| self.has(p))
            .map(|p| p.as_str())
            .collect()
    }

    /// Build from a list of permission strings.
    pub fn from_strings(strings: &[&str]) -> Self {
        let mut set = Self::new();
        for s in strings {
            if let Some(p) = Permission::from_str(s) {
                set.grant(p);
            }
        }
        set
    }

    /// All permissions set.
    pub fn all() -> Self {
        Self::from_permissions(ALL_PERMISSIONS)
    }
}

/// Returns the default permissions for a built-in role name.
pub fn builtin_role_permissions(role: &str) -> Vec<Permission> {
    match role {
        "admin" => ALL_PERMISSIONS.to_vec(),
        "operator" => ALL_PERMISSIONS
            .iter()
            .filter(|p| {
                !matches!(
                    p,
                    Permission::UsersWrite
                        | Permission::SettingsWrite
                        | Permission::UpdatesInstall
                        | Permission::SystemReboot
                        | Permission::HaManage
                )
            })
            .copied()
            .collect(),
        "viewer" => ALL_PERMISSIONS
            .iter()
            .filter(|p| {
                let s = p.as_str();
                (s.ends_with(":read") || s.ends_with(":view"))
                    && !matches!(
                        p,
                        Permission::UsersRead | Permission::SettingsRead | Permission::BackupRead
                    )
            })
            .copied()
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_roundtrip() {
        let mut set = PermissionSet::new();
        set.grant(Permission::RulesRead);
        set.grant(Permission::NatWrite);
        assert!(set.has(Permission::RulesRead));
        assert!(set.has(Permission::NatWrite));
        assert!(!set.has(Permission::RulesWrite));

        let bits = set.to_bits();
        let restored = PermissionSet::from_bits(bits);
        assert_eq!(set, restored);
    }

    #[test]
    fn test_string_roundtrip() {
        let set = PermissionSet::from_permissions(&[
            Permission::DashboardView,
            Permission::RulesRead,
            Permission::LogsView,
        ]);
        let strings = set.to_strings();
        assert_eq!(strings, vec!["dashboard:view", "rules:read", "logs:view"]);

        let str_refs: Vec<&str> = strings.iter().map(|s| *s).collect();
        let restored = PermissionSet::from_strings(&str_refs);
        assert_eq!(set, restored);
    }

    #[test]
    fn test_admin_has_all() {
        let perms = builtin_role_permissions("admin");
        assert_eq!(perms.len(), ALL_PERMISSIONS.len());
        let set = PermissionSet::from_permissions(&perms);
        assert_eq!(set, PermissionSet::all());
    }

    #[test]
    fn test_operator_lacks_admin_perms() {
        let set = PermissionSet::from_permissions(&builtin_role_permissions("operator"));
        assert!(set.has(Permission::RulesRead));
        assert!(set.has(Permission::RulesWrite));
        assert!(set.has(Permission::UsersRead));
        assert!(!set.has(Permission::UsersWrite));
        assert!(!set.has(Permission::SettingsWrite));
        assert!(!set.has(Permission::UpdatesInstall));
        assert!(!set.has(Permission::SystemReboot));
        // HA management (demote, snapshot-push, cert-push, failover-event injection)
        // is admin-only; operator can observe HA status via read endpoints that
        // require no separate permission today.
        assert!(!set.has(Permission::HaManage));
    }

    #[test]
    fn test_viewer_read_only() {
        let set = PermissionSet::from_permissions(&builtin_role_permissions("viewer"));
        assert!(set.has(Permission::RulesRead));
        assert!(set.has(Permission::DashboardView));
        assert!(set.has(Permission::ConnectionsView));
        assert!(!set.has(Permission::RulesWrite));
        assert!(!set.has(Permission::NatWrite));
        assert!(!set.has(Permission::UsersWrite));
        assert!(!set.has(Permission::SystemReboot));
    }

    #[test]
    fn test_unknown_role_empty() {
        let perms = builtin_role_permissions("nonexistent");
        assert!(perms.is_empty());
    }

    #[test]
    fn test_permission_from_str() {
        assert_eq!(
            Permission::from_str("rules:read"),
            Some(Permission::RulesRead)
        );
        assert_eq!(
            Permission::from_str("system:reboot"),
            Some(Permission::SystemReboot)
        );
        assert_eq!(Permission::from_str("invalid"), None);
    }

    #[test]
    fn test_all_permissions_unique_bits() {
        let mut seen = std::collections::HashSet::new();
        for p in ALL_PERMISSIONS {
            assert!(seen.insert(p.bit_index()), "duplicate bit index for {p}");
        }
    }

    #[test]
    fn test_grant_revoke() {
        let mut set = PermissionSet::all();
        assert!(set.has(Permission::SystemReboot));
        set.revoke(Permission::SystemReboot);
        assert!(!set.has(Permission::SystemReboot));
        set.grant(Permission::SystemReboot);
        assert!(set.has(Permission::SystemReboot));
    }
}
