DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = current_schema()
          AND table_name = 'lucid_auth_users'
          AND column_name = 'must_change_password'
    ) THEN
        CREATE TABLE IF NOT EXISTS lucid_auth_legacy_temporary_passwords (
            user_id UUID PRIMARY KEY REFERENCES lucid_auth_users(id) ON DELETE CASCADE,
            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        INSERT INTO lucid_auth_legacy_temporary_passwords (user_id)
        SELECT id FROM lucid_auth_users WHERE must_change_password = TRUE
        ON CONFLICT (user_id) DO NOTHING;
        ALTER TABLE lucid_auth_users DROP COLUMN must_change_password;
    END IF;
END $$;
