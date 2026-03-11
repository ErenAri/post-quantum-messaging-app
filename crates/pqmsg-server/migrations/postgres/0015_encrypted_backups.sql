CREATE TABLE IF NOT EXISTS encrypted_backups (
    backup_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    backup_version INTEGER NOT NULL,
    blob_object_key TEXT NOT NULL,
    byte_len BIGINT NOT NULL,
    recovery_hint TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_encrypted_backups_user
ON encrypted_backups(user_id);
