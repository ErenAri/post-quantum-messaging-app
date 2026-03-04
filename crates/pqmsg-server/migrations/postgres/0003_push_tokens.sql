CREATE TABLE IF NOT EXISTS push_tokens (
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    provider TEXT NOT NULL,
    token TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, device_id, provider)
);

CREATE INDEX IF NOT EXISTS idx_push_tokens_user
ON push_tokens(user_id);
