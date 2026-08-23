CREATE TABLE IF NOT EXISTS lucid_auth_two_factors (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL UNIQUE REFERENCES lucid_auth_users(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    encrypted_secret TEXT,
    encrypted_backup_codes TEXT,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    failed_verification_count INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    last_totp_counter BIGINT,
    CONSTRAINT lucid_auth_two_factor_failure_count_valid
        CHECK (failed_verification_count >= 0)
);

CREATE INDEX IF NOT EXISTS lucid_auth_two_factors_user_id_idx
    ON lucid_auth_two_factors(user_id);
