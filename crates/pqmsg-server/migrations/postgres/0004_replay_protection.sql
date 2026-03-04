CREATE TABLE IF NOT EXISTS relay_dedup (
    dedup_key TEXT PRIMARY KEY,
    expires_at_unix BIGINT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_relay_dedup_expires
ON relay_dedup(expires_at_unix);

CREATE TABLE IF NOT EXISTS inbox_cursors (
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    last_message_id BIGINT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_inbox_cursors_user
ON inbox_cursors(user_id);
