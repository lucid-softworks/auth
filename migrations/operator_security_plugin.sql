CREATE TABLE lucid_auth_operator_temporary_passwords (
    user_id UUID PRIMARY KEY REFERENCES {{lucid-auth:user-table}}(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
