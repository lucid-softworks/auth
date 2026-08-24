ALTER TABLE lucid_auth_accounts
    ADD COLUMN IF NOT EXISTS additional_fields JSONB NOT NULL DEFAULT '{}'::jsonb;

ALTER TABLE lucid_auth_verifications
    ADD COLUMN IF NOT EXISTS additional_fields JSONB NOT NULL DEFAULT '{}'::jsonb;
