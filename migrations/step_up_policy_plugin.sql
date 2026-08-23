CREATE TABLE IF NOT EXISTS lucid_auth_step_up_sessions (
    session_id UUID PRIMARY KEY REFERENCES lucid_auth_sessions(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES lucid_auth_users(id) ON DELETE CASCADE,
    assurance TEXT NOT NULL,
    authenticated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT lucid_auth_step_up_assurance_valid CHECK (
        assurance IN (
            'pending_enrollment',
            'pending_passkey',
            'strong_passkey',
            'strong_two_factor',
            'recovery'
        )
    )
);

CREATE INDEX IF NOT EXISTS lucid_auth_step_up_sessions_user_id_idx
    ON lucid_auth_step_up_sessions(user_id);

CREATE TABLE IF NOT EXISTS lucid_auth_step_up_recovery_codes (
    user_id UUID NOT NULL REFERENCES lucid_auth_users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, code_hash)
);

DO $$
BEGIN
    IF to_regclass('lucid_auth_legacy_session_assurance') IS NOT NULL THEN
        INSERT INTO lucid_auth_step_up_sessions (
            session_id, user_id, assurance, authenticated_at
        )
        SELECT
            session_id,
            user_id,
            CASE assurance
                WHEN 'password_pending_passkey' THEN 'pending_passkey'
                WHEN 'password_and_passkey' THEN 'strong_passkey'
                WHEN 'passkey' THEN 'strong_passkey'
                WHEN 'recovery' THEN 'recovery'
                ELSE 'pending_enrollment'
            END,
            authenticated_at
        FROM lucid_auth_legacy_session_assurance
        ON CONFLICT (session_id) DO NOTHING;
        DROP TABLE lucid_auth_legacy_session_assurance;
    END IF;

    IF to_regclass('lucid_auth_recovery_codes') IS NOT NULL THEN
        INSERT INTO lucid_auth_step_up_recovery_codes (user_id, code_hash, created_at)
        SELECT user_id, code_hash, created_at FROM lucid_auth_recovery_codes
        ON CONFLICT (user_id, code_hash) DO NOTHING;
        DROP TABLE lucid_auth_recovery_codes;
    END IF;
END $$;
