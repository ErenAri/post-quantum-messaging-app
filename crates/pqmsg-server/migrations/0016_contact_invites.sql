CREATE TABLE IF NOT EXISTS contact_invites (
    invite_token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_contact_invites_user
ON contact_invites(user_id);

CREATE INDEX IF NOT EXISTS idx_contact_invites_expires_at
ON contact_invites(expires_at);
