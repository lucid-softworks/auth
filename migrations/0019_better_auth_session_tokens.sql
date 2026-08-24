-- Better Auth returns the opaque session token from listSessions and accepts
-- that same value in revokeSession. Previously stored SHA-256 values cannot be
-- recovered, so upgrading intentionally invalidates those incompatible rows.
DELETE FROM lucid_auth_sessions;
ALTER TABLE lucid_auth_sessions RENAME COLUMN token_hash TO token;
