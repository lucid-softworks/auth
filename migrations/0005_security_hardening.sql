CREATE TABLE IF NOT EXISTS lucid_auth_rate_limits (
    key TEXT PRIMARY KEY,
    attempts INTEGER NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT lucid_auth_rate_limit_attempts CHECK (attempts > 0)
);

CREATE INDEX IF NOT EXISTS lucid_auth_rate_limits_expires_at_idx
    ON lucid_auth_rate_limits(expires_at);
