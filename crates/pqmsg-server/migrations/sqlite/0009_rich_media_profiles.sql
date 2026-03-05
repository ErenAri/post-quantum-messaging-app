PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS encrypted_files (
    file_id TEXT PRIMARY KEY,
    owner_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    owner_device_id TEXT NOT NULL,
    recipient_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    mime_type TEXT NOT NULL,
    file_blob BLOB NOT NULL,
    byte_len INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_encrypted_files_recipient_created
ON encrypted_files(recipient_user_id, created_at, file_id);

CREATE INDEX IF NOT EXISTS idx_encrypted_files_owner_created
ON encrypted_files(owner_user_id, created_at, file_id);

CREATE TABLE IF NOT EXISTS user_profiles (
    user_id TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    display_name TEXT,
    avatar_mime TEXT,
    avatar_blob BLOB,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS presence_state (
    user_id TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    status TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_presence_expires
ON presence_state(expires_at);

CREATE TABLE IF NOT EXISTS typing_state (
    recipient_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    sender_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    sender_device_id TEXT NOT NULL,
    is_typing INTEGER NOT NULL,
    updated_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (recipient_user_id, sender_user_id, sender_device_id)
);

CREATE INDEX IF NOT EXISTS idx_typing_recipient_expires
ON typing_state(recipient_user_id, expires_at);
