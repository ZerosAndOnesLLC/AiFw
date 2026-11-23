-- HA certificate proof (#731). A node keeps a sealed copy of the inbound
-- peer key it was given (api_keys only holds its hash), so it can prove its
-- API certificate to the peer before that peer sends any credential:
-- POST /api/v1/cluster/pin-proof answers HMAC(key, nonce + fingerprint).
-- One row: a node accepts pushes from one master. `peer_key` is sealed with
-- aifw_core::secrets (listed in SEALED_COLUMNS).
CREATE TABLE IF NOT EXISTS cluster_inbound_peer_key (
    id         INTEGER PRIMARY KEY CHECK (id = 1),
    peer_key   TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
