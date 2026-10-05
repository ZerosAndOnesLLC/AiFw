-- Plugin system (#plugins overhaul). plugin_config predates versioned
-- migrations (it was created inline by aifw-api), so it is created here only
-- for fresh installs; the `secrets` / `updated_at` columns are added to
-- existing installs by aifw_plugins::store::PluginStore::migrate via
-- add_column_if_missing.
CREATE TABLE IF NOT EXISTS plugin_config (
    name     TEXT PRIMARY KEY,
    enabled  INTEGER NOT NULL DEFAULT 0,
    settings TEXT
);

-- Per-plugin persistent key/value store (PluginContext::kv_*). Lets plugins
-- keep state across restarts, e.g. the last good threat-feed lists so pf
-- tables can be restored at boot without network access.
CREATE TABLE IF NOT EXISTS plugin_kv (
    plugin     TEXT NOT NULL,
    key        TEXT NOT NULL,
    value      TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    PRIMARY KEY (plugin, key)
);
