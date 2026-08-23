ALTER TABLE lucid_auth_sessions
    ADD COLUMN IF NOT EXISTS additional_fields JSONB NOT NULL DEFAULT '{}'::jsonb;
