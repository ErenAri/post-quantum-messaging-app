ALTER TABLE users
ADD COLUMN IF NOT EXISTS identity_pq_sig_pub BYTEA;

ALTER TABLE prekeys
ADD COLUMN IF NOT EXISTS pq_sig_over_spk BYTEA;

ALTER TABLE prekeys
ADD COLUMN IF NOT EXISTS pq_sig_over_pqspk BYTEA;

ALTER TABLE identity_events
ADD COLUMN IF NOT EXISTS identity_pq_sig_pub BYTEA;
