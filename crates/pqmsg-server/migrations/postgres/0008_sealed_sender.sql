CREATE TABLE IF NOT EXISTS sealed_relay_messages (
    message_id BIGSERIAL PRIMARY KEY,
    recipient_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    recipient_device_id TEXT NOT NULL,
    message_blob BYTEA NOT NULL,
    received_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sealed_relay_inbox
ON sealed_relay_messages(recipient_user_id, recipient_device_id, message_id);

CREATE TABLE IF NOT EXISTS sealed_inbox_cursors (
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    last_message_id BIGINT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, device_id)
);
