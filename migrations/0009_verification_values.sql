CREATE TABLE IF NOT EXISTS lucid_auth_verifications (
    purpose TEXT NOT NULL,
    identifier TEXT NOT NULL,
    payload JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (purpose, identifier)
);

CREATE INDEX IF NOT EXISTS lucid_auth_verifications_expiry_idx
    ON lucid_auth_verifications(expires_at);
