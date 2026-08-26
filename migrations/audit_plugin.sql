CREATE TABLE lucid_auth_audit_events (
    id UUID PRIMARY KEY,
    actor_user_id UUID REFERENCES {{lucid-auth:user-table}}(id) ON DELETE SET NULL,
    subject_user_id UUID REFERENCES {{lucid-auth:user-table}}(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target TEXT,
    outcome TEXT NOT NULL DEFAULT 'success',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT lucid_auth_audit_outcome_valid CHECK (outcome IN ('success', 'failure'))
);

CREATE INDEX lucid_auth_audit_events_created_at_idx
    ON lucid_auth_audit_events(created_at DESC);
