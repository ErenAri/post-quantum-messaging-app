ALTER TABLE sealed_relay_messages
ADD COLUMN sender_identity_x25519_pub BLOB;

UPDATE sealed_relay_messages
SET sender_identity_x25519_pub = (
    SELECT identity_x25519_pub
    FROM users
    WHERE users.user_id = sealed_relay_messages.sender_user_id
)
WHERE sender_user_id IS NOT NULL
  AND sender_identity_x25519_pub IS NULL;
