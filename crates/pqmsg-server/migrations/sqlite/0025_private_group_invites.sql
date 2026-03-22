CREATE TABLE IF NOT EXISTS private_group_invites (
    invite_token TEXT PRIMARY KEY,
    group_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    invite_commitment_sha256 TEXT NOT NULL,
    invite_ciphertext_nonce_base64 TEXT NOT NULL,
    invite_ciphertext_base64 TEXT NOT NULL,
    invite_ciphertext_aad_base64 TEXT NOT NULL,
    created_by_membership_handle_sha256 TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT NULL,
    FOREIGN KEY (group_id, epoch)
        REFERENCES private_group_states (group_id, epoch)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_private_group_invites_group_epoch
    ON private_group_invites (group_id, epoch, revoked_at, expires_at);
