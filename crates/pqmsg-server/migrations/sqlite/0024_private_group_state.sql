CREATE TABLE IF NOT EXISTS private_group_states (
    group_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    state_commitment_sha256 TEXT NOT NULL,
    ciphertext_nonce_base64 TEXT NOT NULL,
    ciphertext_base64 TEXT NOT NULL,
    ciphertext_aad_base64 TEXT NOT NULL,
    published_by_membership_handle_sha256 TEXT NOT NULL,
    published_at TEXT NOT NULL,
    PRIMARY KEY (group_id, epoch)
);

CREATE TABLE IF NOT EXISTS private_group_member_credentials (
    membership_handle_sha256 TEXT PRIMARY KEY,
    group_id TEXT NOT NULL,
    epoch INTEGER NOT NULL,
    member_commitment_sha256 TEXT NOT NULL,
    fetch_key_sha256 TEXT NOT NULL,
    publish_key_sha256 TEXT NULL,
    created_at TEXT NOT NULL,
    revoked_at TEXT NULL,
    FOREIGN KEY (group_id, epoch)
        REFERENCES private_group_states (group_id, epoch)
        ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_private_group_member_credentials_epoch
    ON private_group_member_credentials (group_id, epoch, revoked_at, membership_handle_sha256);
