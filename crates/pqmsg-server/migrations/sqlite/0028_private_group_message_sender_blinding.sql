ALTER TABLE private_group_messages RENAME TO private_group_messages_old;

CREATE TABLE IF NOT EXISTS private_group_messages (
    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
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

INSERT INTO private_group_messages (
    message_id,
    group_id,
    epoch,
    sent_at_unix_ms,
    ciphertext_nonce_base64,
    ciphertext_base64,
    ciphertext_aad_base64,
    sender_hybrid_signature_base64,
    received_at
)
SELECT
    message_id,
    group_id,
    epoch,
    sent_at_unix_ms,
    ciphertext_nonce_base64,
    ciphertext_base64,
    ciphertext_aad_base64,
    sender_hybrid_signature_base64,
    received_at
FROM private_group_messages_old;

DROP TABLE private_group_messages_old;

CREATE INDEX IF NOT EXISTS idx_private_group_messages_group_epoch_message
    ON private_group_messages (group_id, epoch, message_id);
