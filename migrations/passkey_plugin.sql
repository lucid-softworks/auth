CREATE TABLE IF NOT EXISTS lucid_auth_passkeys (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES lucid_auth_users(id) ON DELETE CASCADE,
    name TEXT,
    credential_id TEXT NOT NULL UNIQUE,
    credential JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

ALTER TABLE lucid_auth_passkeys
    ADD COLUMN IF NOT EXISTS public_key TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS counter BIGINT NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS device_type TEXT NOT NULL DEFAULT 'singleDevice',
    ADD COLUMN IF NOT EXISTS backed_up BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS transports TEXT,
    ADD COLUMN IF NOT EXISTS aaguid TEXT;

UPDATE lucid_auth_passkeys
SET counter = COALESCE((credential #>> '{cred,counter}')::BIGINT, counter),
    device_type = CASE
        WHEN COALESCE((credential #>> '{cred,backup_eligible}')::BOOLEAN, FALSE)
            THEN 'multiDevice'
        ELSE 'singleDevice'
    END,
    backed_up = COALESCE((credential #>> '{cred,backup_state}')::BOOLEAN, backed_up),
    transports = COALESCE(
        (
            SELECT string_agg(value, ',' ORDER BY ordinal)
            FROM jsonb_array_elements_text(credential #> '{cred,transports}')
                WITH ORDINALITY AS transport(value, ordinal)
        ),
        transports
    )
WHERE public_key = '';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'lucid_auth_passkeys_counter_valid'
          AND conrelid = 'lucid_auth_passkeys'::regclass
    ) THEN
        ALTER TABLE lucid_auth_passkeys
            ADD CONSTRAINT lucid_auth_passkeys_counter_valid
            CHECK (counter BETWEEN 0 AND 4294967295);
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'lucid_auth_passkeys_device_type_valid'
          AND conrelid = 'lucid_auth_passkeys'::regclass
    ) THEN
        ALTER TABLE lucid_auth_passkeys
            ADD CONSTRAINT lucid_auth_passkeys_device_type_valid
            CHECK (device_type IN ('singleDevice', 'multiDevice'));
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS lucid_auth_passkeys_user_id_idx
    ON lucid_auth_passkeys(user_id);
