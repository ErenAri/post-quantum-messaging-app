ALTER TABLE encrypted_files
    ADD COLUMN IF NOT EXISTS object_key TEXT;

ALTER TABLE user_profiles
    ADD COLUMN IF NOT EXISTS avatar_object_key TEXT;
