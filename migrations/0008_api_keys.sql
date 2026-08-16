CREATE TABLE IF NOT EXISTS lucid_auth_api_keys (
    id UUID PRIMARY KEY,
    config_id TEXT NOT NULL,
    name TEXT NOT NULL,
    start TEXT NOT NULL,
    prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    reference_id UUID NOT NULL REFERENCES lucid_auth_users(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    rate_limit_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    rate_limit_window_seconds BIGINT NOT NULL,
    rate_limit_max INTEGER NOT NULL,
    request_count INTEGER NOT NULL DEFAULT 0,
    last_request TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    permissions JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT lucid_auth_api_keys_rate_window_check
        CHECK (rate_limit_window_seconds BETWEEN 1 AND 86400),
    CONSTRAINT lucid_auth_api_keys_rate_max_check
        CHECK (rate_limit_max BETWEEN 1 AND 100000),
    CONSTRAINT lucid_auth_api_keys_request_count_check
        CHECK (request_count >= 0)
);

CREATE INDEX IF NOT EXISTS lucid_auth_api_keys_reference_config_idx
    ON lucid_auth_api_keys(reference_id, config_id, created_at DESC);

CREATE INDEX IF NOT EXISTS lucid_auth_api_keys_expiry_idx
    ON lucid_auth_api_keys(expires_at);
