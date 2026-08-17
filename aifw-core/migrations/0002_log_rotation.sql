-- #205: log rotation policy for AiFw-managed service logs. Single global
-- row (id = 1); rendered into /usr/local/etc/newsyslog.conf.d/aifw.conf
-- by aifw_core::log_rotation.
CREATE TABLE IF NOT EXISTS log_rotation_config (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    max_size_mb INTEGER NOT NULL DEFAULT 5,
    keep        INTEGER NOT NULL DEFAULT 7,
    compression TEXT    NOT NULL DEFAULT 'gzip',
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
INSERT OR IGNORE INTO log_rotation_config (id) VALUES (1);
