CREATE TABLE IF NOT EXISTS lucid_auth_users (
    id UUID PRIMARY KEY,
    username TEXT UNIQUE,
    display_username TEXT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    image TEXT,
    role TEXT NOT NULL,
    is_anonymous BOOLEAN NOT NULL DEFAULT FALSE,
    banned BOOLEAN NOT NULL DEFAULT FALSE,
    ban_reason TEXT,
    ban_expires TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT lucid_auth_username_presence CHECK (is_anonymous OR username IS NOT NULL)
);

CREATE TABLE IF NOT EXISTS lucid_auth_accounts (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES lucid_auth_users(id) ON DELETE CASCADE,
    provider_id TEXT NOT NULL,
    account_id TEXT NOT NULL,
    password_hash TEXT,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    UNIQUE (user_id, provider_id),
    UNIQUE (provider_id, account_id)
);

CREATE TABLE IF NOT EXISTS lucid_auth_sessions (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES lucid_auth_users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    actor_user_id UUID REFERENCES lucid_auth_users(id),
    assurance TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    ip_address TEXT,
    user_agent TEXT
);

CREATE INDEX IF NOT EXISTS lucid_auth_sessions_user_id_idx
    ON lucid_auth_sessions(user_id);
CREATE INDEX IF NOT EXISTS lucid_auth_sessions_expires_at_idx
    ON lucid_auth_sessions(expires_at);
