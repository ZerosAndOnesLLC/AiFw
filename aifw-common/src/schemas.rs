//! Canonical SQL `CREATE TABLE` strings for cross-crate-shared schemas.
//!
//! Background: the audit caught twelve `CREATE TABLE IF NOT EXISTS`
//! definitions that lived in both `aifw-setup/src/apply.rs` (first-boot
//! wizard) AND the canonical engine module (`aifw-api/src/auth/mod.rs`,
//! `aifw-core/src/db.rs`, etc.). Because `CREATE TABLE IF NOT EXISTS` is
//! idempotent, whichever ran first won — and the two definitions could
//! drift. Auth gained FOREIGN KEYs in aifw-api, but the aifw-setup wizard
//! created the same tables without them; on a fresh install the constraint
//! never landed.
//!
//! These constants are the single source of truth for the affected tables.
//! Both the wizard and the engine migrations execute the same string.
//!
//! Schema versioning beyond `CREATE TABLE IF NOT EXISTS` (ADD COLUMN
//! migrations, etc.) still lives in the engine modules — those run at
//! every aifw-api startup and the constants here are only the initial
//! shape.

/// `users` table: local accounts with password hash, TOTP, and auth provider
pub const USERS_CREATE: &str = r#"CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    totp_secret TEXT,
    auth_provider TEXT NOT NULL DEFAULT 'local',
    created_at TEXT NOT NULL
)"#;

/// `recovery_codes` table: hashed one-time 2FA recovery codes per user
pub const RECOVERY_CODES_CREATE: &str = r#"CREATE TABLE IF NOT EXISTS recovery_codes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
)"#;

/// `auth_config` table: key/value store for auth settings (JWT secret, OAuth, ...)
pub const AUTH_CONFIG_CREATE: &str =
    "CREATE TABLE IF NOT EXISTS auth_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)";

/// `api_keys` table: hashed API keys with display prefix, owned by a user
pub const API_KEYS_CREATE: &str = r#"CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    prefix TEXT NOT NULL,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
)"#;

/// `interface_roles` table: maps interface names to their role (wan/lan/...)
pub const INTERFACE_ROLES_CREATE: &str = "CREATE TABLE IF NOT EXISTS interface_roles (interface_name TEXT PRIMARY KEY, role TEXT NOT NULL, updated_at TEXT NOT NULL)";

/// `dns_resolver_config` table: key/value store for DNS resolver settings
pub const DNS_RESOLVER_CONFIG_CREATE: &str =
    "CREATE TABLE IF NOT EXISTS dns_resolver_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)";

/// `dns_access_lists` table: per-network allow/deny entries for the DNS resolver
pub const DNS_ACCESS_LISTS_CREATE: &str = "CREATE TABLE IF NOT EXISTS dns_access_lists (id TEXT PRIMARY KEY, network TEXT NOT NULL, action TEXT NOT NULL, description TEXT, enabled INTEGER NOT NULL DEFAULT 1, created_at TEXT NOT NULL)";

/// `dhcp_config` table: key/value store for DHCP server settings
pub const DHCP_CONFIG_CREATE: &str =
    "CREATE TABLE IF NOT EXISTS dhcp_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)";

/// `dhcp_subnets` table: DHCP address pools per subnet (gateway, DNS, lease times)
pub const DHCP_SUBNETS_CREATE: &str = r#"CREATE TABLE IF NOT EXISTS dhcp_subnets (
    id TEXT PRIMARY KEY,
    network TEXT NOT NULL,
    pool_start TEXT NOT NULL,
    pool_end TEXT NOT NULL,
    gateway TEXT NOT NULL,
    dns_servers TEXT,
    domain_name TEXT,
    lease_time INTEGER,
    preferred_time INTEGER,
    subnet_type TEXT NOT NULL DEFAULT 'address',
    delegated_length INTEGER,
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    created_at TEXT NOT NULL
)"#;

/// `static_routes` table: user-defined static routes (destination, gateway, metric)
pub const STATIC_ROUTES_CREATE: &str = r#"CREATE TABLE IF NOT EXISTS static_routes (
    id TEXT PRIMARY KEY,
    destination TEXT NOT NULL,
    gateway TEXT NOT NULL,
    interface TEXT,
    metric INTEGER DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    created_at TEXT NOT NULL
)"#;
