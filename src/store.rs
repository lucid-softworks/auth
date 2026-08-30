use crate::{
    ApiKey, AuthError, AuthSession, AuthUser, OAuthAccount, StoredPasskey, VerificationValue,
};
use async_trait::async_trait;
use std::sync::Arc;

mod database_id;
mod transaction;

pub use database_id::{
    DatabaseAccountCreate, DatabaseAccountOwnerWrite, DatabaseCreate, DatabaseIdInput,
    DatabaseIdPlan, DatabaseIdSupplier, DatabaseIdValue, DatabaseWrite, DatabaseWriteOperation,
    DependentAccountContext, DependentAccountPreparer, PreparedDatabaseId,
};
pub use transaction::{
    DatabaseCreateOperation, DatabaseTransaction, DatabaseTransactionFuture,
    DatabaseTransactionOperation, run_database_transaction,
};

/// Result of atomically removing a passkey while preserving a configured minimum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasskeyDeleteOutcome {
    Deleted { remaining: usize },
    NotFound,
    MinimumRequired,
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
    /// Optional logical-model boundary used by Better Auth Infrastructure Dash's
    /// authenticated five-action raw adapter endpoint.
    async fn dash_find_records(
        &self,
        _model: &str,
        _where_clause: &[crate::DashAdapterWhere],
        _limit: Option<usize>,
        _offset: usize,
        _sort: Option<&crate::DashAdapterSort>,
        _select: &[String],
    ) -> Result<Option<Vec<serde_json::Map<String, serde_json::Value>>>, AuthError> {
        Ok(None)
    }

    async fn dash_create_record(
        &self,
        _model: &str,
        _data: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<serde_json::Map<String, serde_json::Value>>, AuthError> {
        Ok(None)
    }

    async fn dash_update_record(
        &self,
        _model: &str,
        _where_clause: &[crate::DashAdapterWhere],
        _update: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Option<serde_json::Map<String, serde_json::Value>>>, AuthError> {
        Ok(None)
    }

    async fn dash_count_records(
        &self,
        _model: &str,
        _where_clause: &[crate::DashAdapterWhere],
    ) -> Result<Option<u64>, AuthError> {
        Ok(None)
    }

    /// Runs one Better Auth adapter transaction without retries.
    ///
    /// Implementations must expose the same staged view to the operation and
    /// to reentrant database hooks, commit only after the operation succeeds,
    /// and roll back on every error.
    async fn transaction(
        &self,
        operation: Box<dyn DatabaseTransactionOperation>,
    ) -> Result<Box<dyn std::any::Any + Send>, AuthError>;

    fn database_adapter_name(&self) -> &str {
        "Auth Adapter"
    }

    /// Better Auth adapter capabilities that participate in ID preparation.
    fn database_id_capabilities(&self) -> crate::DatabaseIdAdapterCapabilities {
        crate::DatabaseIdAdapterCapabilities::default()
    }

    /// Optional adapter-level custom ID generator.
    fn database_id_generator(&self) -> Option<&dyn crate::DatabaseIdGenerator> {
        None
    }

    /// Binds the complete Better Auth schema after plugin validation.
    fn bind_schema(&self, schema: Arc<crate::AuthSchemaCatalog>) -> Result<(), AuthError>;

    fn jwk_store(&self) -> Option<&dyn crate::JwkStore> {
        None
    }

    async fn create_password_user(
        &self,
        user: DatabaseCreate<AuthUser>,
        credential_account: &dyn DependentAccountPreparer,
    ) -> Result<OAuthAccountOwner, AuthError>;

    async fn upsert_password_user(
        &self,
        user: DatabaseWrite<AuthUser>,
        credential_account: &dyn DependentAccountPreparer,
    ) -> Result<DatabaseAccountOwnerWrite, AuthError>;

    async fn create_anonymous_user(
        &self,
        user: DatabaseCreate<AuthUser>,
    ) -> Result<AuthUser, AuthError>;

    async fn create_user_without_account(
        &self,
        user: DatabaseCreate<AuthUser>,
    ) -> Result<AuthUser, AuthError>;

    async fn find_user_by_username(&self, username: &str) -> Result<Option<AuthUser>, AuthError>;

    async fn find_user_by_email(&self, email: &str) -> Result<Option<AuthUser>, AuthError>;

    async fn update_user_profile(
        &self,
        user_id: &str,
        update: UserProfileUpdate,
    ) -> Result<Option<AuthUser>, AuthError>;

    async fn update_user_email(
        &self,
        user_id: &str,
        expected_email: &str,
        new_email: &str,
        email_verified: bool,
    ) -> Result<Option<AuthUser>, AuthError>;

    async fn promote_email_owner(
        &self,
        user_id: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<Option<AuthUser>, AuthError>;

    async fn find_password_hash(&self, user_id: &str) -> Result<Option<String>, AuthError>;

    async fn update_password_hash(
        &self,
        user_id: &str,
        password_hash: String,
    ) -> Result<(), AuthError>;

    async fn set_password_hash(
        &self,
        account_id: &dyn DatabaseIdSupplier,
        user_id: &str,
        password_hash: String,
    ) -> Result<(), AuthError>;

    async fn save_passkey(
        &self,
        passkey: DatabaseCreate<StoredPasskey>,
    ) -> Result<StoredPasskey, AuthError>;

    async fn list_passkeys(&self, user_id: &str) -> Result<Vec<StoredPasskey>, AuthError>;

    async fn find_passkey_by_id(
        &self,
        passkey_id: &str,
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
        user_id: &str,
        passkey_id: &str,
        name: String,
    ) -> Result<Option<StoredPasskey>, AuthError>;

    async fn delete_passkey(
        &self,
        user_id: &str,
        passkey_id: &str,
        minimum_remaining: usize,
    ) -> Result<PasskeyDeleteOutcome, AuthError>;

    async fn delete_user_passkeys(&self, user_id: &str) -> Result<(), AuthError>;

    async fn find_user_by_id(&self, user_id: &str) -> Result<Option<AuthUser>, AuthError>;

    async fn create_session(
        &self,
        session: DatabaseCreate<AuthSession>,
    ) -> Result<AuthSession, AuthError>;

    async fn find_session(&self, token: &str)
    -> Result<Option<(AuthSession, AuthUser)>, AuthError>;

    async fn find_session_by_id(&self, session_id: &str) -> Result<Option<AuthSession>, AuthError>;

    async fn update_session_fields(
        &self,
        session_id: &str,
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
        session_id: &str,
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
        user: DatabaseCreate<AuthUser>,
        account: &dyn DependentAccountPreparer,
    ) -> Result<OAuthAccountOwner, AuthError>;
    async fn link_oauth_account(
        &self,
        account: DatabaseCreate<OAuthAccount>,
    ) -> Result<OAuthAccount, AuthError>;
    async fn update_oauth_account_tokens(
        &self,
        account: OAuthAccount,
    ) -> Result<OAuthAccount, AuthError>;
    async fn list_user_accounts(&self, user_id: &str) -> Result<Vec<OAuthAccount>, AuthError>;
    async fn delete_user_account(
        &self,
        user_id: &str,
        account_id: &str,
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
    async fn create_verification(
        &self,
        value: DatabaseCreate<VerificationValue>,
    ) -> Result<VerificationValue, AuthError>;

    /// Atomically creates a verification reservation only when its key is free.
    async fn reserve_verification(
        &self,
        value: DatabaseCreate<VerificationValue>,
    ) -> Result<Option<VerificationValue>, AuthError>;

    async fn find_verification(
        &self,
        identifier: &str,
    ) -> Result<Option<VerificationValue>, AuthError>;

    /// Atomically consumes a matching value. Concurrent callers may never
    /// receive the same record twice. Expiry is evaluated by the service after
    /// identifier fallback has selected its winner.
    async fn consume_verification(
        &self,
        identifier: &str,
    ) -> Result<Option<VerificationValue>, AuthError>;

    async fn update_verification(
        &self,
        value: VerificationValue,
    ) -> Result<Option<VerificationValue>, AuthError>;

    async fn delete_verification(
        &self,
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
    async fn create_api_key(&self, api_key: DatabaseCreate<ApiKey>) -> Result<ApiKey, AuthError>;

    async fn find_api_key(&self, api_key_id: &str) -> Result<Option<ApiKey>, AuthError>;

    async fn find_api_key_by_hash(&self, key_hash: &str) -> Result<Option<ApiKey>, AuthError>;

    async fn list_api_keys(
        &self,
        reference_id: &str,
        config_id: Option<&str>,
    ) -> Result<Vec<ApiKey>, AuthError>;

    async fn update_api_key(&self, api_key: ApiKey) -> Result<Option<ApiKey>, AuthError>;

    async fn delete_api_key(&self, api_key_id: &str) -> Result<bool, AuthError>;

    async fn delete_expired_api_keys(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, AuthError>;

    /// Atomically records one allowed request and rejects expired, revoked, or
    /// rate-limited keys.
    async fn record_api_key_use(
        &self,
        api_key_id: &str,
        now: chrono::DateTime<chrono::Utc>,
        rate_limit_enabled: bool,
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
        id: &dyn DatabaseIdSupplier,
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

    async fn update_user_role(&self, user_id: &str, role: &str) -> Result<AuthUser, AuthError>;

    async fn update_user_ban(
        &self,
        user_id: &str,
        banned: bool,
        reason: Option<String>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<AuthUser, AuthError>;

    async fn admin_update_user(
        &self,
        user_id: &str,
        update: crate::AdminUserUpdate,
    ) -> Result<AuthUser, AuthError>;

    async fn delete_user(&self, user_id: &str) -> Result<(), AuthError>;

    async fn list_sessions(&self, user_id: &str) -> Result<Vec<AuthSession>, AuthError>;

    async fn delete_session_by_id(&self, session_id: &str) -> Result<(), AuthError>;

    async fn delete_user_sessions(&self, user_id: &str) -> Result<(), AuthError>;
}
