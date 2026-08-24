use crate::{
    ApiKey, AuthError, AuthSession, AuthUser, OAuthAccount, StoredPasskey, VerificationValue,
};
use async_trait::async_trait;
use uuid::Uuid;

/// Result of atomically removing a passkey while preserving a configured minimum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyDeleteOutcome {
    Deleted { remaining: usize },
    NotFound,
    MinimumRequired,
}

#[derive(Debug, Clone)]
pub enum EmailVerificationOutcome {
    InvalidToken,
    Expired,
    UserNotFound,
    AlreadyVerified(AuthUser),
    Verified(AuthUser),
}

#[derive(Debug, Clone)]
pub enum PasswordResetOutcome {
    InvalidToken,
    UserNotFound,
    Reset(Box<AuthUser>),
}

/// Fields atomically changed by Better Auth's current-user update route.
#[derive(Debug, Clone, Default)]
pub struct UserProfileUpdate {
    pub name: Option<String>,
    pub image: Option<Option<String>>,
    pub username: Option<String>,
    pub display_username: Option<String>,
    pub additional_fields: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct OAuthAccountOwner {
    pub account: OAuthAccount,
    pub user: AuthUser,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountDeleteOutcome {
    Deleted,
    NotFound,
    LastAccount,
}

#[derive(Debug, Clone)]
pub enum OAuthTokenUpdateOutcome {
    Updated(OAuthAccount),
    Stale(OAuthAccount),
    NotFound,
}

/// Persistence boundary required by [`crate::AuthService`].
#[async_trait]
pub trait AuthStore:
    AccessStore + ApiKeyStore + OAuthAccountStore + SecurityStore + VerificationStore + Send + Sync
{
    fn jwk_store(&self) -> Option<&dyn crate::JwkStore> {
        None
    }

    async fn create_password_user(
        &self,
        user: AuthUser,
        credential_account: OAuthAccount,
    ) -> Result<AuthUser, AuthError>;

    async fn upsert_password_user(
        &self,
        user: AuthUser,
        credential_account: OAuthAccount,
    ) -> Result<AuthUser, AuthError>;

    async fn create_anonymous_user(&self, user: AuthUser) -> Result<AuthUser, AuthError>;

    async fn create_user_without_account(&self, user: AuthUser) -> Result<AuthUser, AuthError>;

    async fn find_user_by_username(&self, username: &str) -> Result<Option<AuthUser>, AuthError>;

    async fn find_user_by_email(&self, email: &str) -> Result<Option<AuthUser>, AuthError>;

    async fn update_user_profile(
        &self,
        user_id: Uuid,
        update: UserProfileUpdate,
    ) -> Result<Option<AuthUser>, AuthError>;

    async fn update_user_email(
        &self,
        user_id: Uuid,
        expected_email: &str,
        new_email: &str,
        email_verified: bool,
    ) -> Result<Option<AuthUser>, AuthError>;

    /// Atomically consumes a purpose-bound token and marks its user verified.
    async fn consume_email_verification(
        &self,
        token_hash: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<EmailVerificationOutcome, AuthError>;

    async fn consume_password_reset(
        &self,
        token_hash: &str,
        password_hash: String,
        now: chrono::DateTime<chrono::Utc>,
        revoke_sessions: bool,
    ) -> Result<PasswordResetOutcome, AuthError>;

    async fn promote_email_owner(
        &self,
        user_id: Uuid,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<AuthUser>, AuthError>;

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

    async fn find_passkey_by_id(
        &self,
        passkey_id: Uuid,
    ) -> Result<Option<StoredPasskey>, AuthError>;

    async fn find_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<StoredPasskey>, AuthError>;

    /// Updates verified authenticator state only if its persisted signature
    /// counter still matches the value used during verification.
    async fn update_passkey_after_authentication(
        &self,
        passkey: StoredPasskey,
        expected_counter: u32,
    ) -> Result<bool, AuthError>;

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

    async fn find_session(&self, token: &str)
    -> Result<Option<(AuthSession, AuthUser)>, AuthError>;

    async fn find_session_by_id(&self, session_id: Uuid) -> Result<Option<AuthSession>, AuthError>;

    async fn update_session_fields(
        &self,
        session_id: Uuid,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<AuthSession>, AuthError>;

    /// Atomically extends an existing session without recreating a session
    /// concurrently removed after it was read.
    async fn refresh_session(
        &self,
        token: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
        updated_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<AuthSession>, AuthError>;

    async fn delete_session(&self, token: &str) -> Result<(), AuthError>;

    async fn expire_session(
        &self,
        session_id: Uuid,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AuthError>;

    async fn delete_expired_sessions(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AuthError>;
}

#[async_trait]
pub trait OAuthAccountStore: Send + Sync {
    async fn find_oauth_account_owner(
        &self,
        issuer: &str,
        account_id: &str,
    ) -> Result<Option<OAuthAccountOwner>, AuthError>;
    async fn create_oauth_user(
        &self,
        user: AuthUser,
        account: OAuthAccount,
    ) -> Result<OAuthAccountOwner, AuthError>;
    async fn link_oauth_account(&self, account: OAuthAccount) -> Result<OAuthAccount, AuthError>;
    async fn update_oauth_account_tokens(
        &self,
        account: OAuthAccount,
    ) -> Result<OAuthAccount, AuthError>;
    async fn list_user_accounts(&self, user_id: Uuid) -> Result<Vec<OAuthAccount>, AuthError>;
    async fn delete_user_account(
        &self,
        user_id: Uuid,
        account_id: Uuid,
        allow_last: bool,
    ) -> Result<AccountDeleteOutcome, AuthError>;
    async fn compare_and_swap_oauth_tokens(
        &self,
        account: OAuthAccount,
        expected_refresh_token: Option<&str>,
        expected_updated_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<OAuthTokenUpdateOutcome, AuthError>;
}

/// Durable one-time state for verification, OAuth, and challenge flows.
#[async_trait]
pub trait VerificationStore: Send + Sync {
    async fn create_verification(&self, value: VerificationValue) -> Result<(), AuthError>;

    /// Atomically creates a verification reservation only when its key is free.
    async fn reserve_verification(&self, value: VerificationValue) -> Result<bool, AuthError>;

    async fn find_verification(
        &self,
        purpose: &str,
        identifier: &str,
    ) -> Result<Option<VerificationValue>, AuthError>;

    /// Atomically consumes a matching unexpired value. Concurrent callers may
    /// never receive the same record twice.
    async fn consume_verification(
        &self,
        purpose: &str,
        identifier: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<VerificationValue>, AuthError>;

    async fn update_verification(
        &self,
        value: VerificationValue,
    ) -> Result<Option<VerificationValue>, AuthError>;

    async fn delete_verification(
        &self,
        purpose: &str,
        identifier: &str,
    ) -> Result<Option<VerificationValue>, AuthError>;

    async fn delete_expired_verifications(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, AuthError>;
}

/// Persistence boundary for Better Auth-compatible API keys.
#[async_trait]
pub trait ApiKeyStore: Send + Sync {
    async fn create_api_key(&self, api_key: ApiKey) -> Result<ApiKey, AuthError>;

    async fn find_api_key(&self, api_key_id: Uuid) -> Result<Option<ApiKey>, AuthError>;

    async fn find_api_key_by_hash(&self, key_hash: &str) -> Result<Option<ApiKey>, AuthError>;

    async fn list_api_keys(
        &self,
        reference_id: &str,
        config_id: Option<&str>,
    ) -> Result<Vec<ApiKey>, AuthError>;

    async fn update_api_key(&self, api_key: ApiKey) -> Result<Option<ApiKey>, AuthError>;

    async fn delete_api_key(&self, api_key_id: Uuid) -> Result<bool, AuthError>;

    async fn delete_expired_api_keys(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, AuthError>;

    /// Atomically records one allowed request and rejects expired, revoked, or
    /// rate-limited keys.
    async fn record_api_key_use(
        &self,
        api_key_id: Uuid,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<ApiKeyUseOutcome, AuthError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiKeyUseOutcome {
    Allowed(Box<ApiKey>),
    Invalid,
    RateLimited { retry_after_milliseconds: i64 },
    UsageExceeded,
}

/// Durable security state shared by every authentication service instance.
#[async_trait]
pub trait SecurityStore: Send + Sync {
    /// Atomically consumes one request from a Better Auth rolling window.
    async fn consume_rate_limit(
        &self,
        key: &str,
        now: chrono::DateTime<chrono::Utc>,
        rule: crate::RateLimitRule,
        longest_window: u64,
    ) -> Result<crate::RateLimitOutcome, AuthError>;
}

/// Administrative, authorization and audit persistence kept separate from login storage.
#[async_trait]
pub trait AccessStore: Send + Sync {
    async fn list_users(
        &self,
        query: &crate::AdminListUsersQuery,
    ) -> Result<Vec<AuthUser>, AuthError>;

    async fn count_users(&self, conditions: &[crate::AdminListCondition])
    -> Result<i64, AuthError>;

    async fn count_users_by_role(&self, role: &str) -> Result<i64, AuthError>;

    async fn update_user_role(&self, user_id: Uuid, role: &str) -> Result<AuthUser, AuthError>;

    async fn update_user_ban(
        &self,
        user_id: Uuid,
        banned: bool,
        reason: Option<String>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<AuthUser, AuthError>;

    async fn admin_update_user(
        &self,
        user_id: Uuid,
        update: crate::AdminUserUpdate,
    ) -> Result<AuthUser, AuthError>;

    async fn delete_user(&self, user_id: Uuid) -> Result<(), AuthError>;

    async fn list_sessions(&self, user_id: Uuid) -> Result<Vec<AuthSession>, AuthError>;

    async fn delete_session_by_id(&self, session_id: Uuid) -> Result<(), AuthError>;

    async fn delete_user_sessions(&self, user_id: Uuid) -> Result<(), AuthError>;
}
