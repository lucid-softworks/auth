ALTER TABLE lucid_auth_migrations
    ADD COLUMN IF NOT EXISTS checksum TEXT;
