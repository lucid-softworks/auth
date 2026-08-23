ALTER TABLE lucid_auth_users
    ADD COLUMN IF NOT EXISTS additional_fields JSONB NOT NULL DEFAULT '{}'::jsonb;
