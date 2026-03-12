ALTER TABLE identity_rotation_challenges
ADD COLUMN IF NOT EXISTS new_identity_pq_sig_pub BYTEA;
