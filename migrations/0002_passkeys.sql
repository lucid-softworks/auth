CREATE TABLE IF NOT EXISTS lucid_auth_passkeys (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES lucid_auth_users(id) ON DELETE CASCADE,
    name TEXT,
    credential_id TEXT NOT NULL UNIQUE,
    credential JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS lucid_auth_passkeys_user_id_idx
    ON lucid_auth_passkeys(user_id);
