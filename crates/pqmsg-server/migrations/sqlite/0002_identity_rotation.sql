CREATE TABLE IF NOT EXISTS identity_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    version INTEGER NOT NULL,
    identity_x25519_pub BLOB NOT NULL,
    identity_sig_pub BLOB NOT NULL,
    device_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    changed_at TEXT NOT NULL,
    UNIQUE(user_id, version)
);

CREATE INDEX IF NOT EXISTS idx_identity_events_user_version
ON identity_events(user_id, version DESC);

INSERT INTO identity_events (
    user_id,
    version,
    identity_x25519_pub,
    identity_sig_pub,
    device_id,
    event_type,
    changed_at
)
SELECT
    u.user_id,
    1,
    u.identity_x25519_pub,
    u.identity_sig_pub,
    u.device_id,
    'initial',
    u.created_at
FROM users u
WHERE NOT EXISTS (
    SELECT 1
    FROM identity_events ie
    WHERE ie.user_id = u.user_id
);

CREATE TABLE IF NOT EXISTS identity_rotation_challenges (
    challenge_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    nonce BLOB NOT NULL,
    new_identity_x25519_pub BLOB NOT NULL,
    new_identity_sig_pub BLOB NOT NULL,
    new_device_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_rotation_challenges_user_consumed
ON identity_rotation_challenges(user_id, consumed, created_at);
