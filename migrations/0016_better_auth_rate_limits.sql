ALTER TABLE lucid_auth_rate_limits
    RENAME COLUMN attempts TO count;

ALTER TABLE lucid_auth_rate_limits
    ALTER COLUMN count TYPE BIGINT;

ALTER TABLE lucid_auth_rate_limits
    ADD COLUMN last_request BIGINT;

UPDATE lucid_auth_rate_limits
SET last_request = (EXTRACT(EPOCH FROM expires_at) * 1000)::BIGINT;

ALTER TABLE lucid_auth_rate_limits
    ALTER COLUMN last_request SET NOT NULL,
    DROP COLUMN expires_at;

ALTER TABLE lucid_auth_rate_limits
    RENAME CONSTRAINT lucid_auth_rate_limit_attempts TO lucid_auth_rate_limit_count;

DROP INDEX IF EXISTS lucid_auth_rate_limits_expires_at_idx;

CREATE INDEX lucid_auth_rate_limits_last_request_idx
    ON lucid_auth_rate_limits(last_request);
