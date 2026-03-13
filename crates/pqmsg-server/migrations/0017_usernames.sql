ALTER TABLE user_profiles
    ADD COLUMN username TEXT;

ALTER TABLE user_profiles
    ADD COLUMN username_normalized TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS idx_user_profiles_username_normalized
    ON user_profiles(username_normalized)
    WHERE username_normalized IS NOT NULL;
