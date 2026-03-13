ALTER TABLE user_profiles
    ADD COLUMN username_lookup_enabled BOOLEAN NOT NULL DEFAULT TRUE;

UPDATE user_profiles
SET username_lookup_enabled = FALSE
WHERE username_normalized IS NULL;
