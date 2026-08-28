use crate::{AuthError, AuthSession, AuthStore, AuthUser, PasskeyDeleteOutcome, StoredPasskey};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use std::sync::Arc;

mod access;
mod adapter;
mod api_key;
mod audit;
mod device_authorization;
mod guest_capability;
mod jwt;
mod migrate;
mod oauth;
mod oauth_provider;
mod operator_security;
mod organization;
mod passkey;
mod phone_number;
mod physical_schema;
mod plugin;
mod rows;
mod schema;
mod security;
mod session;
mod siwe;
mod step_up;
mod transaction;
mod two_factor;
mod user;
mod verification;

#[cfg(test)]
pub(crate) use physical_schema::PostgresValue;
pub(crate) use physical_schema::{PostgresModel, PostgresWrite};

pub use adapter::{PostgresAdapterConfig, PostgresStore};
pub use device_authorization::PostgresDeviceAuthorizationStore;
pub use oauth_provider::PostgresOAuthProviderStore;
pub use schema::{
    PostgresMigrationDescriptor, PostgresMigrationPlan, PostgresSchemaIssue, PostgresSchemaObject,
    PostgresSchemaReport,
};

impl PostgresStore {
    async fn load_user_by_id(&self, id: &str) -> Result<Option<AuthUser>, AuthError> {
        user::load_by_id(self, id).await
    }
}

#[async_trait]
impl AuthStore for PostgresStore {
    async fn transaction(
        &self,
        operation: Box<dyn crate::DatabaseTransactionOperation>,
    ) -> Result<Box<dyn std::any::Any + Send>, AuthError> {
        transaction::run(self, operation).await
    }

    fn database_adapter_name(&self) -> &str {
        "PostgreSQL Adapter"
    }

    fn database_id_capabilities(&self) -> crate::DatabaseIdAdapterCapabilities {
        crate::DatabaseIdAdapterCapabilities {
            supports_uuids: true,
            ..crate::DatabaseIdAdapterCapabilities::default()
        }
    }

    fn bind_schema(&self, schema: Arc<crate::AuthSchemaCatalog>) -> Result<(), AuthError> {
        self.bind_catalog(schema)
    }

    fn jwk_store(&self) -> Option<&dyn crate::JwkStore> {
        Some(self)
    }

    async fn create_password_user(
        &self,
        user: crate::store::DatabaseCreate<AuthUser>,
        credential_account: &dyn crate::store::DependentAccountPreparer,
    ) -> Result<crate::OAuthAccountOwner, AuthError> {
        user::create_password_user(self, user, credential_account).await
    }

    async fn upsert_password_user(
        &self,
        user: crate::store::DatabaseWrite<AuthUser>,
        credential_account: &dyn crate::store::DependentAccountPreparer,
    ) -> Result<crate::store::DatabaseAccountOwnerWrite, AuthError> {
        user::upsert_password_user(self, user, credential_account).await
    }

    async fn create_anonymous_user(
        &self,
        user: crate::store::DatabaseCreate<AuthUser>,
    ) -> Result<AuthUser, AuthError> {
        user::create_without_account(self, user).await
    }

    async fn create_user_without_account(
        &self,
        user: crate::store::DatabaseCreate<AuthUser>,
    ) -> Result<AuthUser, AuthError> {
        if let Some(transaction) = crate::database_hooks::current_transaction() {
            return match transaction
                .create(crate::DatabaseCreateOperation::User(user))
                .await?
            {
                crate::DatabaseRecord::User(user) => Ok(user),
                _ => unreachable!("transaction create preserves its model"),
            };
        }
        user::create_without_account(self, user).await
    }

    async fn find_user_by_username(&self, username: &str) -> Result<Option<AuthUser>, AuthError> {
        user::load_by_username(self, username).await
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<AuthUser>, AuthError> {
        user::load_by_email(self, email).await
    }

    async fn update_user_profile(
        &self,
        user_id: &str,
        update: crate::UserProfileUpdate,
    ) -> Result<Option<AuthUser>, AuthError> {
        user::update_profile(self, user_id, update).await
    }

    async fn update_user_email(
        &self,
        user_id: &str,
        expected_email: &str,
        new_email: &str,
        email_verified: bool,
    ) -> Result<Option<AuthUser>, AuthError> {
        user::update_email(self, user_id, expected_email, new_email, email_verified).await
    }

    async fn promote_email_owner(
        &self,
        user_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AuthUser>, AuthError> {
        user::promote_email_owner(self, user_id, now).await
    }

    async fn find_password_hash(&self, user_id: &str) -> Result<Option<String>, AuthError> {
        user::find_password_hash(self, user_id).await
    }

    async fn update_password_hash(
        &self,
        user_id: &str,
        password_hash: String,
    ) -> Result<(), AuthError> {
        user::update_password_hash(self, user_id, password_hash).await
    }

    async fn set_password_hash(
        &self,
        account_id: &dyn crate::store::DatabaseIdSupplier,
        user_id: &str,
        password_hash: String,
    ) -> Result<(), AuthError> {
        user::set_password_hash(self, account_id, user_id, password_hash).await
    }

    async fn save_passkey(
        &self,
        passkey: crate::store::DatabaseCreate<StoredPasskey>,
    ) -> Result<StoredPasskey, AuthError> {
        passkey::save(self, passkey).await
    }

    async fn list_passkeys(&self, user_id: &str) -> Result<Vec<StoredPasskey>, AuthError> {
        passkey::list_for_user(self, user_id).await
    }

    async fn find_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<StoredPasskey>, AuthError> {
        passkey::find_by_credential_id(self, credential_id).await
    }

    async fn find_passkey_by_id(
        &self,
        passkey_id: &str,
    ) -> Result<Option<StoredPasskey>, AuthError> {
        passkey::find_by_id(self, passkey_id).await
    }

    async fn update_passkey_after_authentication(
        &self,
        passkey: StoredPasskey,
        expected_counter: u32,
    ) -> Result<bool, AuthError> {
        passkey::compare_and_swap(self, passkey, expected_counter).await
    }

    async fn update_passkey_name(
        &self,
        user_id: &str,
        passkey_id: &str,
        name: String,
    ) -> Result<Option<StoredPasskey>, AuthError> {
        passkey::rename(self, user_id, passkey_id, name).await
    }

    async fn delete_passkey(
        &self,
        user_id: &str,
        passkey_id: &str,
        minimum_remaining: usize,
    ) -> Result<PasskeyDeleteOutcome, AuthError> {
        passkey::delete(self, user_id, passkey_id, minimum_remaining).await
    }

    async fn delete_user_passkeys(&self, user_id: &str) -> Result<(), AuthError> {
        passkey::delete_for_user(self, user_id).await
    }

    async fn find_user_by_id(&self, user_id: &str) -> Result<Option<AuthUser>, AuthError> {
        if let Some(transaction) = crate::database_hooks::current_transaction() {
            return transaction
                .find_by_id(crate::DatabaseModel::User, user_id)
                .await
                .map(|record| {
                    record.map(|record| match record {
                        crate::DatabaseRecord::User(user) => user,
                        _ => unreachable!("transaction lookup preserves its model"),
                    })
                });
        }
        self.load_user_by_id(user_id).await
    }

    async fn create_session(
        &self,
        session: crate::store::DatabaseCreate<AuthSession>,
    ) -> Result<AuthSession, AuthError> {
        session::create(self, session).await
    }

    async fn find_session(
        &self,
        token: &str,
    ) -> Result<Option<(AuthSession, AuthUser)>, AuthError> {
        session::find(self, token).await
    }

    async fn find_session_by_id(&self, session_id: &str) -> Result<Option<AuthSession>, AuthError> {
        session::find_by_id(self, session_id).await
    }

    async fn update_session_fields(
        &self,
        session_id: &str,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<AuthSession>, AuthError> {
        session::update_fields(self, session_id, fields).await
    }

    async fn refresh_session(
        &self,
        token: &str,
        expires_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Result<Option<AuthSession>, AuthError> {
        session::refresh(self, token, expires_at, updated_at).await
    }

    async fn delete_session(&self, token: &str) -> Result<(), AuthError> {
        session::delete(self, token).await
    }

    async fn expire_session(
        &self,
        session_id: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        session::expire(self, session_id, expires_at).await
    }

    async fn delete_expired_sessions(&self, now: DateTime<Utc>) -> Result<(), AuthError> {
        session::delete_expired(self, now).await
    }
}

fn storage_error(error: impl std::fmt::Display) -> AuthError {
    AuthError::Storage(error.to_string())
}
