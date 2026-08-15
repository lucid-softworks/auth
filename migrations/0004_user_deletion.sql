ALTER TABLE lucid_auth_sessions
    DROP CONSTRAINT IF EXISTS lucid_auth_sessions_actor_user_id_fkey;
ALTER TABLE lucid_auth_sessions
    ADD CONSTRAINT lucid_auth_sessions_actor_user_id_fkey
    FOREIGN KEY (actor_user_id) REFERENCES lucid_auth_users(id) ON DELETE CASCADE;

ALTER TABLE lucid_auth_guest_grants
    DROP CONSTRAINT IF EXISTS lucid_auth_guest_grants_created_by_fkey;
ALTER TABLE lucid_auth_guest_grants
    ADD CONSTRAINT lucid_auth_guest_grants_created_by_fkey
    FOREIGN KEY (created_by) REFERENCES lucid_auth_users(id) ON DELETE CASCADE;
