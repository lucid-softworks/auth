ALTER TABLE lucid_auth_accounts
    ADD COLUMN IF NOT EXISTS issuer TEXT;

UPDATE lucid_auth_accounts
SET issuer = CASE
    WHEN provider_id = 'credential' THEN 'local:credential'
    ELSE 'local:oauth:' || provider_id
END
WHERE issuer IS NULL;

ALTER TABLE lucid_auth_accounts
    ALTER COLUMN issuer SET NOT NULL,
    ALTER COLUMN issuer SET DEFAULT 'local:credential',
    ADD COLUMN IF NOT EXISTS access_token TEXT,
    ADD COLUMN IF NOT EXISTS refresh_token TEXT,
    ADD COLUMN IF NOT EXISTS id_token TEXT,
    ADD COLUMN IF NOT EXISTS access_token_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS refresh_token_expires_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS scope TEXT;

ALTER TABLE lucid_auth_accounts
    DROP CONSTRAINT IF EXISTS lucid_auth_accounts_user_id_provider_id_key,
    DROP CONSTRAINT IF EXISTS lucid_auth_accounts_provider_id_account_id_key;

CREATE UNIQUE INDEX IF NOT EXISTS lucid_auth_accounts_issuer_account_id_key
    ON lucid_auth_accounts(issuer, account_id);

CREATE INDEX IF NOT EXISTS lucid_auth_accounts_user_id_idx
    ON lucid_auth_accounts(user_id);
