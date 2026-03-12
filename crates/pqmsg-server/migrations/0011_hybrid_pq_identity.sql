ALTER TABLE users
ADD COLUMN identity_pq_sig_pub BLOB;

ALTER TABLE prekeys
ADD COLUMN pq_sig_over_spk BLOB;

ALTER TABLE prekeys
ADD COLUMN pq_sig_over_pqspk BLOB;

ALTER TABLE identity_events
ADD COLUMN identity_pq_sig_pub BLOB;
