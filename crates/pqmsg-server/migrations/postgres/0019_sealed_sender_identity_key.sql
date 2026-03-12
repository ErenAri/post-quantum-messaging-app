ALTER TABLE sealed_relay_messages
ADD COLUMN IF NOT EXISTS sender_identity_x25519_pub BYTEA;

UPDATE sealed_relay_messages
SET sender_identity_x25519_pub = users.identity_x25519_pub
FROM users
WHERE users.user_id = sealed_relay_messages.sender_user_id
  AND sealed_relay_messages.sender_user_id IS NOT NULL
  AND sealed_relay_messages.sender_identity_x25519_pub IS NULL;
