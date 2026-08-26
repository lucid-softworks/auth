CREATE TABLE lucid_auth_step_up_sessions (
    session_id {{lucid-auth:session-id-type}} PRIMARY KEY REFERENCES {{lucid-auth:session-table}}(id) ON DELETE CASCADE,
    user_id {{lucid-auth:user-id-type}} NOT NULL REFERENCES {{lucid-auth:user-table}}(id) ON DELETE CASCADE,
    assurance TEXT NOT NULL,
    authenticated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT lucid_auth_step_up_assurance_valid CHECK (
        assurance IN (
            'pending_enrollment',
            'pending_passkey',
            'strong_passkey',
            'strong_two_factor',
            'recovery'
        )
    )
);

CREATE INDEX lucid_auth_step_up_sessions_user_id_idx
    ON lucid_auth_step_up_sessions(user_id);

CREATE TABLE lucid_auth_step_up_recovery_codes (
    user_id {{lucid-auth:user-id-type}} NOT NULL REFERENCES {{lucid-auth:user-table}}(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (user_id, code_hash)
);
