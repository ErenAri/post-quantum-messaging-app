CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    identity_x25519_pub BYTEA NOT NULL,
    identity_sig_pub BYTEA NOT NULL,
    device_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS prekeys (
    user_id TEXT PRIMARY KEY REFERENCES users(user_id) ON DELETE CASCADE,
    signed_prekey_x25519_pub BYTEA NOT NULL,
    sig_over_spk BYTEA NOT NULL,
    pq_signed_prekey_pub_mlkem768 BYTEA NOT NULL,
    sig_over_pqspk BYTEA NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS one_time_prekeys_x25519 (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    prekey BYTEA NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_otk_x25519_user_consumed
ON one_time_prekeys_x25519(user_id, consumed, id);

CREATE TABLE IF NOT EXISTS one_time_prekeys_mlkem768 (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    prekey BYTEA NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_otk_mlkem_user_consumed
ON one_time_prekeys_mlkem768(user_id, consumed, id);

CREATE TABLE IF NOT EXISTS relay_messages (
    message_id BIGSERIAL PRIMARY KEY,
    recipient_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    sender_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    message_blob BYTEA NOT NULL,
    received_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_relay_inbox
ON relay_messages(recipient_user_id, message_id);
