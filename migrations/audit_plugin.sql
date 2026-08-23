CREATE TABLE IF NOT EXISTS lucid_auth_audit_events (
    id UUID PRIMARY KEY,
    actor_user_id UUID REFERENCES lucid_auth_users(id) ON DELETE SET NULL,
    subject_user_id UUID REFERENCES lucid_auth_users(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    target TEXT,
    outcome TEXT NOT NULL DEFAULT 'success',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT lucid_auth_audit_outcome_valid CHECK (outcome IN ('success', 'failure'))
);

ALTER TABLE lucid_auth_audit_events
    ADD COLUMN IF NOT EXISTS outcome TEXT NOT NULL DEFAULT 'success';

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'lucid_auth_audit_outcome_valid'
          AND conrelid = 'lucid_auth_audit_events'::regclass
    ) THEN
        ALTER TABLE lucid_auth_audit_events
            ADD CONSTRAINT lucid_auth_audit_outcome_valid
            CHECK (outcome IN ('success', 'failure'));
    END IF;
END
$$;

CREATE INDEX IF NOT EXISTS lucid_auth_audit_events_created_at_idx
    ON lucid_auth_audit_events(created_at DESC);
