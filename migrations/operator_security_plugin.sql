CREATE TABLE IF NOT EXISTS lucid_auth_operator_temporary_passwords (
    user_id UUID PRIMARY KEY REFERENCES lucid_auth_users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
    IF to_regclass('lucid_auth_legacy_temporary_passwords') IS NOT NULL THEN
        INSERT INTO lucid_auth_operator_temporary_passwords (user_id, created_at)
        SELECT user_id, created_at FROM lucid_auth_legacy_temporary_passwords
        ON CONFLICT (user_id) DO NOTHING;
        DROP TABLE lucid_auth_legacy_temporary_passwords;
    END IF;
END $$;
