ALTER TABLE encrypted_files
    ADD COLUMN object_key TEXT;

ALTER TABLE user_profiles
    ADD COLUMN avatar_object_key TEXT;
