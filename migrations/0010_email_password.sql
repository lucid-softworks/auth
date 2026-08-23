UPDATE lucid_auth_users SET email = LOWER(email);

ALTER TABLE lucid_auth_users
    DROP CONSTRAINT IF EXISTS lucid_auth_username_presence;

CREATE UNIQUE INDEX IF NOT EXISTS lucid_auth_users_normalized_email_idx
    ON lucid_auth_users (LOWER(email));
