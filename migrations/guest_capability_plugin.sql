CREATE TABLE IF NOT EXISTS lucid_auth_guest_grants (
    id UUID PRIMARY KEY,
    label TEXT NOT NULL,
    token_hash TEXT UNIQUE,
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
    resource_scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    valid_from TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    max_uses INTEGER,
    uses INTEGER NOT NULL DEFAULT 0,
    created_by UUID NOT NULL REFERENCES lucid_auth_users(id) ON DELETE CASCADE,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT lucid_auth_guest_grant_uses CHECK (max_uses IS NULL OR max_uses > 0),
    CONSTRAINT lucid_auth_guest_grant_window CHECK (expires_at > valid_from)
);

ALTER TABLE lucid_auth_guest_grants
    DROP CONSTRAINT IF EXISTS lucid_auth_guest_grants_created_by_fkey;
ALTER TABLE lucid_auth_guest_grants
    ADD CONSTRAINT lucid_auth_guest_grants_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES lucid_auth_users(id) ON DELETE CASCADE;

CREATE TABLE IF NOT EXISTS lucid_auth_guest_grant_sessions (
    session_id UUID PRIMARY KEY REFERENCES lucid_auth_sessions(id) ON DELETE CASCADE,
    grant_id UUID NOT NULL REFERENCES lucid_auth_guest_grants(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS lucid_auth_guest_grant_sessions_grant_idx
    ON lucid_auth_guest_grant_sessions(grant_id);

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'lucid_auth_sessions'
          AND column_name = 'guest_grant_id'
    ) THEN
        INSERT INTO lucid_auth_guest_grant_sessions (session_id, grant_id)
        SELECT id, guest_grant_id FROM lucid_auth_sessions WHERE guest_grant_id IS NOT NULL
        ON CONFLICT (session_id) DO NOTHING;

        ALTER TABLE lucid_auth_sessions
            DROP CONSTRAINT IF EXISTS lucid_auth_sessions_guest_grant_id_fkey;
        ALTER TABLE lucid_auth_sessions DROP COLUMN guest_grant_id;
    END IF;
END $$;
