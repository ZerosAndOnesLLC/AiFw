-- QUAL-C6: baseline migration for the new sqlx::migrate framework.
--
-- For appliances upgrading from a pre-v5.95.38 image, every table already
-- exists from the engine-side `migrate()` functions running at startup,
-- so each statement below is `CREATE TABLE IF NOT EXISTS` and is a no-op.
-- For fresh installs, this baseline lands the canonical schemas. The
-- `_sqlx_migrations` tracking table created by sqlx itself records that
-- version 0001 has been applied so future migrations (0002_*.sql, etc.)
-- run in order with proper version tracking.
--
-- New schemas going forward MUST go in a numbered file in this directory;
-- the engine-side `CREATE TABLE IF NOT EXISTS` pattern is deprecated.
-- ALTER TABLE migrations for existing tables also go here as new files.

-- Mirror aifw_common::schemas constants so a fresh DB ends up with the
-- same shape regardless of which startup path runs first.

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    totp_secret TEXT,
    auth_provider TEXT NOT NULL DEFAULT 'local',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS recovery_codes (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS auth_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    prefix TEXT NOT NULL,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);
