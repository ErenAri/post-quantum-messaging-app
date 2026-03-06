-- Message delivery/read receipts
CREATE TABLE IF NOT EXISTS message_receipts (
    id BIGSERIAL PRIMARY KEY,
    message_id BIGINT NOT NULL,
    recipient_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    recipient_device_id TEXT NOT NULL,
    receipt_type TEXT NOT NULL,  -- 'delivered' or 'read'
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_receipts_message
ON message_receipts(message_id, receipt_type);

CREATE INDEX IF NOT EXISTS idx_receipts_recipient
ON message_receipts(recipient_user_id, recipient_device_id, created_at);

CREATE UNIQUE INDEX IF NOT EXISTS idx_receipts_unique
ON message_receipts(message_id, recipient_user_id, recipient_device_id, receipt_type);

-- Disappearing messages expiry metadata
CREATE TABLE IF NOT EXISTS message_expiry_meta (
    message_id BIGINT NOT NULL,
    recipient_device_id TEXT NOT NULL,
    expires_at TEXT,
    PRIMARY KEY (message_id, recipient_device_id)
);

CREATE INDEX IF NOT EXISTS idx_message_expiry
ON message_expiry_meta(expires_at);
