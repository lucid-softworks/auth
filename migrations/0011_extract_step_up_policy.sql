DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'lucid_auth_sessions'
          AND column_name = 'assurance'
    ) THEN
        CREATE TABLE IF NOT EXISTS lucid_auth_legacy_session_assurance (
            session_id UUID PRIMARY KEY REFERENCES lucid_auth_sessions(id) ON DELETE CASCADE,
            user_id UUID NOT NULL REFERENCES lucid_auth_users(id) ON DELETE CASCADE,
            assurance TEXT NOT NULL,
            authenticated_at TIMESTAMPTZ NOT NULL
        );
        INSERT INTO lucid_auth_legacy_session_assurance (
            session_id, user_id, assurance, authenticated_at
        )
        SELECT id, user_id, assurance, created_at FROM lucid_auth_sessions
        ON CONFLICT (session_id) DO NOTHING;
        ALTER TABLE lucid_auth_sessions ADD COLUMN authentication_method TEXT;
        UPDATE lucid_auth_sessions
        SET authentication_method = CASE assurance
            WHEN 'anonymous' THEN 'anonymous'
            WHEN 'email_verified' THEN 'email_verified'
            WHEN 'passkey' THEN 'passkey'
            WHEN 'password_and_passkey' THEN 'passkey'
            ELSE 'password'
        END;
        ALTER TABLE lucid_auth_sessions
            ALTER COLUMN authentication_method SET NOT NULL;
        ALTER TABLE lucid_auth_sessions DROP COLUMN assurance;
    END IF;
END $$;
