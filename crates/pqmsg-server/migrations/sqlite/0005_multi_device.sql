PRAGMA foreign_keys = OFF;

CREATE TABLE IF NOT EXISTS user_devices (
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    linked_at TEXT NOT NULL,
    revoked_at TEXT,
    PRIMARY KEY (user_id, device_id)
);

CREATE INDEX IF NOT EXISTS idx_user_devices_active
ON user_devices(user_id, active, device_id);

INSERT OR IGNORE INTO user_devices (user_id, device_id, active, linked_at, revoked_at)
SELECT user_id, device_id, 1, created_at, NULL
FROM users;

CREATE TABLE IF NOT EXISTS prekeys_v2 (
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    signed_prekey_x25519_pub BLOB NOT NULL,
    sig_over_spk BLOB NOT NULL,
    pq_signed_prekey_pub_mlkem768 BLOB NOT NULL,
    sig_over_pqspk BLOB NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, device_id)
);

INSERT INTO prekeys_v2 (
    user_id,
    device_id,
    signed_prekey_x25519_pub,
    sig_over_spk,
    pq_signed_prekey_pub_mlkem768,
    sig_over_pqspk,
    updated_at
)
SELECT
    p.user_id,
    u.device_id,
    p.signed_prekey_x25519_pub,
    p.sig_over_spk,
    p.pq_signed_prekey_pub_mlkem768,
    p.sig_over_pqspk,
    p.updated_at
FROM prekeys p
JOIN users u ON u.user_id = p.user_id;

DROP TABLE prekeys;
ALTER TABLE prekeys_v2 RENAME TO prekeys;

CREATE INDEX IF NOT EXISTS idx_prekeys_user
ON prekeys(user_id);

CREATE TABLE IF NOT EXISTS one_time_prekeys_x25519_v2 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    prekey BLOB NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

INSERT INTO one_time_prekeys_x25519_v2 (id, user_id, device_id, prekey, consumed, created_at)
SELECT
    otk.id,
    otk.user_id,
    u.device_id,
    otk.prekey,
    otk.consumed,
    otk.created_at
FROM one_time_prekeys_x25519 otk
JOIN users u ON u.user_id = otk.user_id;

DROP TABLE one_time_prekeys_x25519;
ALTER TABLE one_time_prekeys_x25519_v2 RENAME TO one_time_prekeys_x25519;

CREATE INDEX IF NOT EXISTS idx_otk_x25519_user_consumed
ON one_time_prekeys_x25519(user_id, device_id, consumed, id);

CREATE TABLE IF NOT EXISTS one_time_prekeys_mlkem768_v2 (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    prekey BLOB NOT NULL,
    consumed INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

INSERT INTO one_time_prekeys_mlkem768_v2 (id, user_id, device_id, prekey, consumed, created_at)
SELECT
    otk.id,
    otk.user_id,
    u.device_id,
    otk.prekey,
    otk.consumed,
    otk.created_at
FROM one_time_prekeys_mlkem768 otk
JOIN users u ON u.user_id = otk.user_id;

DROP TABLE one_time_prekeys_mlkem768;
ALTER TABLE one_time_prekeys_mlkem768_v2 RENAME TO one_time_prekeys_mlkem768;

CREATE INDEX IF NOT EXISTS idx_otk_mlkem_user_consumed
ON one_time_prekeys_mlkem768(user_id, device_id, consumed, id);

CREATE TABLE IF NOT EXISTS relay_messages_v2 (
    message_id INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    recipient_device_id TEXT NOT NULL,
    sender_user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    device_id TEXT NOT NULL,
    message_blob BLOB NOT NULL,
    received_at TEXT NOT NULL
);

INSERT INTO relay_messages_v2 (
    message_id,
    recipient_user_id,
    recipient_device_id,
    sender_user_id,
    device_id,
    message_blob,
    received_at
)
SELECT
    r.message_id,
    r.recipient_user_id,
    u.device_id,
    r.sender_user_id,
    r.device_id,
    r.message_blob,
    r.received_at
FROM relay_messages r
JOIN users u ON u.user_id = r.recipient_user_id;

DROP TABLE relay_messages;
ALTER TABLE relay_messages_v2 RENAME TO relay_messages;

CREATE INDEX IF NOT EXISTS idx_relay_inbox
ON relay_messages(recipient_user_id, recipient_device_id, message_id);

PRAGMA foreign_keys = ON;
