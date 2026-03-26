CREATE TABLE IF NOT EXISTS private_group_messages (
    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    sender_membership_handle_sha256 TEXT NOT NULL,
    sender_user_id TEXT NOT NULL,
    sent_at_unix_ms INTEGER NOT NULL,
    ciphertext_nonce_base64 TEXT NOT NULL,
    ciphertext_base64 TEXT NOT NULL,
    ciphertext_aad_base64 TEXT NOT NULL,
    sender_hybrid_signature_base64 TEXT NOT NULL,
    received_at TEXT NOT NULL,
    FOREIGN KEY (group_id, epoch)
        REFERENCES private_group_states (group_id, epoch)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_private_group_messages_group_epoch_message
    ON private_group_messages (group_id, epoch, message_id);
