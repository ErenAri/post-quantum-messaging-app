ALTER TABLE sealed_relay_messages
ADD COLUMN IF NOT EXISTS sender_user_id TEXT;
