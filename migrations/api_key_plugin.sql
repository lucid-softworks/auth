CREATE TABLE IF NOT EXISTS lucid_auth_api_keys (
    id UUID PRIMARY KEY,
    config_id TEXT NOT NULL DEFAULT 'default',
    name TEXT,
    start TEXT,
    prefix TEXT,
    key_hash TEXT NOT NULL,
    reference_id TEXT NOT NULL,
    refill_interval BIGINT,
    refill_amount BIGINT,
    last_refill_at TIMESTAMPTZ,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    rate_limit_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    rate_limit_time_window BIGINT,
    rate_limit_max BIGINT,
    request_count BIGINT NOT NULL DEFAULT 0,
    remaining BIGINT,
    last_request TIMESTAMPTZ,
    expires_at TIMESTAMPTZ,
    permissions JSONB,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT lucid_auth_api_keys_request_count_check CHECK (request_count >= 0),
    CONSTRAINT lucid_auth_api_keys_remaining_check CHECK (remaining IS NULL OR remaining >= 0)
);

CREATE UNIQUE INDEX IF NOT EXISTS lucid_auth_api_keys_key_hash_idx
    ON lucid_auth_api_keys(key_hash);

CREATE INDEX IF NOT EXISTS lucid_auth_api_keys_reference_config_idx
    ON lucid_auth_api_keys(reference_id, config_id, created_at DESC);

CREATE INDEX IF NOT EXISTS lucid_auth_api_keys_expiry_idx
    ON lucid_auth_api_keys(expires_at);
