ALTER TABLE contact_invites
    ADD COLUMN purpose TEXT NOT NULL DEFAULT 'manual';

CREATE INDEX IF NOT EXISTS idx_contact_invites_user_purpose
    ON contact_invites(user_id, purpose);
