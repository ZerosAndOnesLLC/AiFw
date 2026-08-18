//! Auth/RBAC schema migration. Creates the users, tokens, OAuth, roles,
//! schedules, and audit tables and seeds the built-in roles.

/// Role id of the built-in `system` role (#318): what AiFw's own service
/// identities run as. Not assignable to human users.
pub const SYSTEM_ROLE_ID: &str = "builtin-system";
/// Username of the locked service account behind the daemon-loopback and
/// inbound cluster-peer API keys.
pub const SYSTEM_USERNAME: &str = "aifw-daemon";

use sqlx::sqlite::SqlitePool;

pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    // Shared schemas live in aifw_common::schemas (QUAL-C5) so the wizard
    // and this migration always see the same DDL.
    sqlx::query(aifw_common::schemas::USERS_CREATE)
        .execute(pool)
        .await?;

    sqlx::query(aifw_common::schemas::API_KEYS_CREATE)
        .execute(pool)
        .await?;

    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS refresh_tokens (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            family_id TEXT NOT NULL,
            expires_at TEXT NOT NULL,
            revoked INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )"#,
    )
    .execute(pool)
    .await?;

    // SEC-H8: a short, non-secret prefix of the raw token lets rotate/revoke
    // do an O(1) indexed lookup instead of Argon2-verifying every row. Legacy
    // rows (pre-upgrade) have NULL prefix and simply won't match a lookup —
    // those refresh tokens become invalid on upgrade (services restart anyway),
    // forcing a harmless re-login.
    let _ = sqlx::query("ALTER TABLE refresh_tokens ADD COLUMN token_prefix TEXT")
        .execute(pool)
        .await;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_refresh_tokens_prefix ON refresh_tokens(token_prefix)",
    )
    .execute(pool)
    .await?;

    sqlx::query(aifw_common::schemas::RECOVERY_CODES_CREATE)
        .execute(pool)
        .await?;

    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS oauth_providers (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            provider_type TEXT NOT NULL,
            client_id TEXT NOT NULL,
            client_secret TEXT NOT NULL,
            auth_url TEXT NOT NULL,
            token_url TEXT NOT NULL,
            userinfo_url TEXT NOT NULL,
            scopes TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )"#,
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS oauth_identities (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            provider_id TEXT NOT NULL,
            provider_user_id TEXT NOT NULL,
            email TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (provider_id) REFERENCES oauth_providers(id)
        )"#,
    )
    .execute(pool)
    .await?;

    // SEC-H9: short-lived CSRF state store. A `state` nonce is created at
    // /oauth/{provider}/authorize and must be presented (and consumed) at the
    // callback, binding the callback to a request this server initiated.
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS oauth_states (
            state TEXT PRIMARY KEY,
            provider TEXT NOT NULL,
            created_at TEXT NOT NULL
        )"#,
    )
    .execute(pool)
    .await?;

    sqlx::query(aifw_common::schemas::AUTH_CONFIG_CREATE)
        .execute(pool)
        .await?;

    // #170: PKCE/redirect columns on oauth_states + TOTP-pending tickets.
    super::oauth_flow::migrate(pool).await?;

    // Add role and enabled columns if they don't exist
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'admin'")
        .execute(pool)
        .await;
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")
        .execute(pool)
        .await;

    // Static routes — shared schema
    sqlx::query(aifw_common::schemas::STATIC_ROUTES_CREATE)
        .execute(pool)
        .await?;

    // Add fib column (0 = main FIB). Multi-WAN (#132) routes can target
    // additional FIBs created via routing instances.
    let _ = sqlx::query("ALTER TABLE static_routes ADD COLUMN fib INTEGER NOT NULL DEFAULT 0")
        .execute(pool)
        .await;

    // Schedules
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS schedules (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            description TEXT,
            time_ranges TEXT NOT NULL,
            days_of_week TEXT NOT NULL DEFAULT 'mon,tue,wed,thu,fri,sat,sun',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        )"#,
    )
    .execute(pool)
    .await?;

    // Add schedule_id column to rules if not exists
    let _ = sqlx::query("ALTER TABLE rules ADD COLUMN schedule_id TEXT")
        .execute(pool)
        .await;

    // User audit log
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS user_audit_log (
            id TEXT PRIMARY KEY,
            user_id TEXT,
            actor_id TEXT NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            ip_addr TEXT,
            created_at TEXT NOT NULL
        )"#,
    )
    .execute(pool)
    .await?;

    // Token blacklist for access token revocation
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS revoked_tokens (
            jti TEXT PRIMARY KEY,
            expires_at TEXT NOT NULL
        )"#,
    )
    .execute(pool)
    .await?;

    // --- RBAC: roles table ---
    sqlx::query(
        r#"CREATE TABLE IF NOT EXISTS roles (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL UNIQUE,
            permissions INTEGER NOT NULL DEFAULT 0,
            builtin INTEGER NOT NULL DEFAULT 0,
            description TEXT,
            created_at TEXT NOT NULL DEFAULT (datetime('now'))
        )"#,
    )
    .execute(pool)
    .await?;

    // Seed built-in roles (idempotent)
    {
        use aifw_common::permission::{PermissionSet, builtin_role_permissions};
        let admin_bits =
            PermissionSet::from_permissions(&builtin_role_permissions("admin")).to_bits() as i64;
        let operator_bits =
            PermissionSet::from_permissions(&builtin_role_permissions("operator")).to_bits() as i64;
        let viewer_bits =
            PermissionSet::from_permissions(&builtin_role_permissions("viewer")).to_bits() as i64;
        let system_bits =
            PermissionSet::from_permissions(&builtin_role_permissions("system")).to_bits() as i64;

        sqlx::query(
            "INSERT OR IGNORE INTO roles (id, name, permissions, builtin, description) VALUES (?1, ?2, ?3, 1, ?4)"
        )
        .bind("builtin-admin").bind("admin").bind(admin_bits).bind("Full system access")
        .execute(pool).await?;

        sqlx::query(
            "INSERT OR IGNORE INTO roles (id, name, permissions, builtin, description) VALUES (?1, ?2, ?3, 1, ?4)"
        )
        .bind("builtin-operator").bind("operator").bind(operator_bits).bind("Operational access without system administration")
        .execute(pool).await?;

        sqlx::query(
            "INSERT OR IGNORE INTO roles (id, name, permissions, builtin, description) VALUES (?1, ?2, ?3, 1, ?4)"
        )
        .bind("builtin-viewer").bind("viewer").bind(viewer_bits).bind("Read-only access")
        .execute(pool).await?;

        // #318: internal service identity (aifw-daemon loopback / cluster peer keys).
        sqlx::query(
            "INSERT OR IGNORE INTO roles (id, name, permissions, builtin, description) VALUES (?1, ?2, ?3, 1, ?4)"
        )
        .bind(SYSTEM_ROLE_ID).bind("system").bind(system_bits)
        .bind("AiFw internal services (aifw-daemon loopback, cluster peer) — not for people")
        .execute(pool).await?;

        // Update built-in role permissions in case new permissions were added
        sqlx::query("UPDATE roles SET permissions = ?1 WHERE id = 'builtin-admin'")
            .bind(admin_bits)
            .execute(pool)
            .await?;
        sqlx::query("UPDATE roles SET permissions = ?1 WHERE id = 'builtin-operator'")
            .bind(operator_bits)
            .execute(pool)
            .await?;
        sqlx::query("UPDATE roles SET permissions = ?1 WHERE id = 'builtin-viewer'")
            .bind(viewer_bits)
            .execute(pool)
            .await?;
        sqlx::query("UPDATE roles SET permissions = ?1 WHERE id = ?2")
            .bind(system_bits)
            .bind(SYSTEM_ROLE_ID)
            .execute(pool)
            .await?;
    }

    // Add role_id column to users (references roles table)
    let _ = sqlx::query("ALTER TABLE users ADD COLUMN role_id TEXT")
        .execute(pool)
        .await;

    // Backfill role_id from legacy role string
    sqlx::query(
        "UPDATE users SET role_id = 'builtin-admin' WHERE role = 'admin' AND role_id IS NULL",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "UPDATE users SET role_id = 'builtin-operator' WHERE role = 'operator' AND role_id IS NULL",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "UPDATE users SET role_id = 'builtin-viewer' WHERE role = 'viewer' AND role_id IS NULL",
    )
    .execute(pool)
    .await?;

    // #318: the aifw-daemon service user was created without a role and so
    // inherited the column default ('admin'). Demote every such row to the
    // system role; the daemon only ever calls HaManage endpoints.
    sqlx::query(
        "UPDATE users SET role = 'system', role_id = ?1
         WHERE username = ?2 AND auth_provider = 'system'
           AND (role_id IS NULL OR role_id = 'builtin-admin' OR role = 'admin')",
    )
    .bind(SYSTEM_ROLE_ID)
    .bind(SYSTEM_USERNAME)
    .execute(pool)
    .await?;

    Ok(())
}
