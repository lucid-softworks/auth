CREATE TABLE IF NOT EXISTS lucid_auth_recovery_codes (
    user_id UUID NOT NULL REFERENCES lucid_auth_users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, code_hash)
);
