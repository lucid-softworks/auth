CREATE TABLE lucid_auth_guest_grants (
    id UUID PRIMARY KEY,
    label TEXT NOT NULL,
    token_hash TEXT UNIQUE,
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
    resource_scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    valid_from TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    max_uses INTEGER,
    uses INTEGER NOT NULL DEFAULT 0,
    created_by UUID NOT NULL REFERENCES {{lucid-auth:user-table}}(id) ON DELETE CASCADE,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT lucid_auth_guest_grant_uses CHECK (max_uses IS NULL OR max_uses > 0),
    CONSTRAINT lucid_auth_guest_grant_window CHECK (expires_at > valid_from)
);

CREATE TABLE lucid_auth_guest_grant_sessions (
    session_id UUID PRIMARY KEY REFERENCES {{lucid-auth:session-table}}(id) ON DELETE CASCADE,
    grant_id UUID NOT NULL REFERENCES lucid_auth_guest_grants(id) ON DELETE CASCADE
);

CREATE INDEX lucid_auth_guest_grant_sessions_grant_idx
    ON lucid_auth_guest_grant_sessions(grant_id);
