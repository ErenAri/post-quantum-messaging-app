CREATE TABLE IF NOT EXISTS discovery_handles (
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    handle_hash_sha256 TEXT NOT NULL,
    handle_kind TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, handle_hash_sha256, handle_kind)
);

CREATE INDEX IF NOT EXISTS idx_discovery_handles_hash
ON discovery_handles(handle_hash_sha256, handle_kind);

CREATE TABLE IF NOT EXISTS contacts (
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    contact_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    alias TEXT,
    verified_by_qr INTEGER NOT NULL DEFAULT 0,
    verified_fingerprint_sha256 TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, contact_user_id)
);

CREATE INDEX IF NOT EXISTS idx_contacts_user
ON contacts(user_id, updated_at);
