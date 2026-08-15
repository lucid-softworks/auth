CREATE TABLE IF NOT EXISTS lucid_auth_audit_events (
    id UUID PRIMARY KEY,
    actor_user_id UUID REFERENCES lucid_auth_users(id) ON DELETE SET NULL,
    subject_user_id UUID REFERENCES lucid_auth_users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target TEXT,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS lucid_auth_audit_events_created_at_idx
    ON lucid_auth_audit_events(created_at DESC);
