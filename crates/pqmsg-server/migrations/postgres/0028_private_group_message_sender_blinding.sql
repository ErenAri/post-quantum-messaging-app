ALTER TABLE private_group_messages
DROP COLUMN IF EXISTS sender_user_id;

ALTER TABLE private_group_messages
DROP COLUMN IF EXISTS sender_membership_handle_sha256;
