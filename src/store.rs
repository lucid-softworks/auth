use crate::{AuditEvent, AuthError, AuthSession, AuthUser, GuestGrant, StoredPasskey};
use async_trait::async_trait;
use uuid::Uuid;

/// Result of atomically removing a passkey while preserving a configured minimum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyDeleteOutcome {
    Deleted { remaining: usize },
    NotFound,
    MinimumRequired,
}

/// Persistence boundary required by [`crate::AuthService`].
#[async_trait]
pub trait AuthStore: AccessStore + SecurityStore + Send + Sync {
    async fn create_password_user(
        &self,
        user: AuthUser,
        password_hash: String,
    ) -> Result<AuthUser, AuthError>;

    async fn upsert_password_user(
        &self,
        user: AuthUser,
        password_hash: String,
    ) -> Result<AuthUser, AuthError>;

    async fn create_anonymous_user(&self, user: AuthUser) -> Result<AuthUser, AuthError>;

    async fn find_user_by_username(&self, username: &str) -> Result<Option<AuthUser>, AuthError>;

    async fn find_password_hash(&self, user_id: Uuid) -> Result<Option<String>, AuthError>;

    async fn update_password_hash(
        &self,
        user_id: Uuid,
        password_hash: String,
    ) -> Result<(), AuthError>;

    async fn set_password_hash(
        &self,
        user_id: Uuid,
        password_hash: String,
    ) -> Result<(), AuthError>;

    async fn save_passkey(&self, passkey: StoredPasskey) -> Result<StoredPasskey, AuthError>;

    async fn list_passkeys(&self, user_id: Uuid) -> Result<Vec<StoredPasskey>, AuthError>;

    async fn list_all_passkeys(&self) -> Result<Vec<StoredPasskey>, AuthError>;

    async fn update_passkey(&self, passkey: StoredPasskey) -> Result<(), AuthError>;

    async fn update_passkey_name(
        &self,
        user_id: Uuid,
        passkey_id: Uuid,
        name: String,
    ) -> Result<Option<StoredPasskey>, AuthError>;

    async fn delete_passkey(
        &self,
        user_id: Uuid,
        passkey_id: Uuid,
        minimum_remaining: usize,
    ) -> Result<PasskeyDeleteOutcome, AuthError>;

    async fn delete_user_passkeys(&self, user_id: Uuid) -> Result<(), AuthError>;

    async fn find_user_by_id(&self, user_id: Uuid) -> Result<Option<AuthUser>, AuthError>;

    async fn create_session(&self, session: AuthSession) -> Result<(), AuthError>;

    async fn find_session(
        &self,
        token_hash: &str,
    ) -> Result<Option<(AuthSession, AuthUser)>, AuthError>;

    async fn delete_session(&self, token_hash: &str) -> Result<(), AuthError>;

    async fn delete_expired_sessions(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AuthError>;
}

/// Durable security state shared by every authentication service instance.
#[async_trait]
pub trait SecurityStore: Send + Sync {
    async fn rate_limit_exceeded(
        &self,
        key: &str,
        now: chrono::DateTime<chrono::Utc>,
        max_attempts: usize,
    ) -> Result<bool, AuthError>;

    async fn record_auth_failure(
        &self,
        key: &str,
        now: chrono::DateTime<chrono::Utc>,
        window: chrono::Duration,
    ) -> Result<(), AuthError>;

    async fn clear_auth_failures(&self, key: &str) -> Result<(), AuthError>;

    async fn replace_recovery_codes(
        &self,
        user_id: Uuid,
        code_hashes: Vec<String>,
    ) -> Result<(), AuthError>;

    async fn consume_recovery_code(
        &self,
        user_id: Uuid,
        code_hash: &str,
    ) -> Result<bool, AuthError>;

    async fn recovery_code_count(&self, user_id: Uuid) -> Result<usize, AuthError>;

    async fn delete_recovery_codes(&self, user_id: Uuid) -> Result<(), AuthError>;
}

/// Administrative, authorization and audit persistence kept separate from login storage.
#[async_trait]
pub trait AccessStore: Send + Sync {
    async fn list_users(&self, limit: usize, offset: usize) -> Result<Vec<AuthUser>, AuthError>;

    async fn count_users(&self) -> Result<i64, AuthError>;

    async fn count_users_by_role(&self, role: &str) -> Result<i64, AuthError>;

    async fn update_user_role(&self, user_id: Uuid, role: &str) -> Result<AuthUser, AuthError>;

    async fn update_user_ban(
        &self,
        user_id: Uuid,
        banned: bool,
        reason: Option<String>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<AuthUser, AuthError>;

    async fn delete_user(&self, user_id: Uuid) -> Result<(), AuthError>;

    async fn list_sessions(&self, user_id: Uuid) -> Result<Vec<AuthSession>, AuthError>;

    async fn delete_session_by_id(&self, session_id: Uuid) -> Result<(), AuthError>;

    async fn delete_user_sessions(&self, user_id: Uuid) -> Result<(), AuthError>;

    async fn create_guest_grant(&self, grant: GuestGrant) -> Result<GuestGrant, AuthError>;

    async fn consume_guest_grant(
        &self,
        token_hash: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<GuestGrant>, AuthError>;

    async fn find_guest_grant(&self, grant_id: Uuid) -> Result<Option<GuestGrant>, AuthError>;

    async fn list_guest_grants(&self) -> Result<Vec<GuestGrant>, AuthError>;

    async fn revoke_guest_grant(
        &self,
        grant_id: Uuid,
        revoked_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AuthError>;

    async fn append_audit_event(&self, event: AuditEvent) -> Result<(), AuthError>;

    async fn list_audit_events(&self, limit: usize) -> Result<Vec<AuditEvent>, AuthError>;

    /// Atomically replaces credentials for the named sole owner. This is an
    /// out-of-band operator primitive and must never be exposed as an HTTP route.
    async fn recover_sole_owner(
        &self,
        user_id: Uuid,
        password_hash: String,
        event: AuditEvent,
    ) -> Result<bool, AuthError>;
}
