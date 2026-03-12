ALTER TABLE users
ADD COLUMN IF NOT EXISTS sealed_delivery_token BYTEA;
