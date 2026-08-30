use super::InstrumentedAuthStore;
use crate::{
    AuthError, AuthSession, AuthStore, AuthUser, DatabaseAccountOwnerWrite, DatabaseCreate,
    DatabaseIdSupplier, DatabaseWrite, DependentAccountPreparer, OAuthAccountOwner,
    PasskeyDeleteOutcome, StoredPasskey, UserProfileUpdate,
    instrumentation::{AdapterOperation, with_adapter_operation},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};

#[async_trait]
impl AuthStore for InstrumentedAuthStore {
    delegate_store_metadata!();

    async fn dash_find_records(
        &self,
        model: &str,
        where_clause: &[crate::DashAdapterWhere],
        limit: Option<usize>,
        offset: usize,
        sort: Option<&crate::DashAdapterSort>,
        select: &[String],
    ) -> Result<Option<Vec<serde_json::Map<String, serde_json::Value>>>, AuthError> {
        with_adapter_operation(
            AdapterOperation::FindMany,
            model,
            self.inner
                .dash_find_records(model, where_clause, limit, offset, sort, select),
        )
        .await
    }

    async fn dash_create_record(
        &self,
        model: &str,
        data: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<serde_json::Map<String, serde_json::Value>>, AuthError> {
        with_adapter_operation(
            AdapterOperation::Create,
            model,
            self.inner.dash_create_record(model, data),
        )
        .await
    }

    async fn dash_update_record(
        &self,
        model: &str,
        where_clause: &[crate::DashAdapterWhere],
        update: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<Option<serde_json::Map<String, serde_json::Value>>>, AuthError> {
        with_adapter_operation(
            AdapterOperation::Update,
            model,
            self.inner
                .dash_update_record(model, where_clause, update),
        )
        .await
    }

    async fn dash_count_records(
        &self,
        model: &str,
        where_clause: &[crate::DashAdapterWhere],
    ) -> Result<Option<u64>, AuthError> {
        with_adapter_operation(
            AdapterOperation::Count,
            model,
            self.inner.dash_count_records(model, where_clause),
        )
        .await
    }

    async fn transaction(
        &self,
        operation: Box<dyn crate::DatabaseTransactionOperation>,
    ) -> Result<Box<dyn std::any::Any + Send>, AuthError> {
        self.inner.transaction(operation).await
    }

    async fn create_password_user(
        &self,
        user: DatabaseCreate<AuthUser>,
        account: &dyn DependentAccountPreparer,
    ) -> Result<OAuthAccountOwner, AuthError> {
        with_adapter_operation(
            AdapterOperation::Create,
            "user",
            self.inner.create_password_user(user, account),
        )
        .await
    }

    async fn upsert_password_user(
        &self,
        user: DatabaseWrite<AuthUser>,
        account: &dyn DependentAccountPreparer,
    ) -> Result<DatabaseAccountOwnerWrite, AuthError> {
        with_adapter_operation(
            AdapterOperation::Update,
            "user",
            self.inner.upsert_password_user(user, account),
        )
        .await
    }

    async fn create_anonymous_user(
        &self,
        user: DatabaseCreate<AuthUser>,
    ) -> Result<AuthUser, AuthError> {
        with_adapter_operation(
            AdapterOperation::Create,
            "user",
            self.inner.create_anonymous_user(user),
        )
        .await
    }

    async fn create_user_without_account(
        &self,
        user: DatabaseCreate<AuthUser>,
    ) -> Result<AuthUser, AuthError> {
        with_adapter_operation(
            AdapterOperation::Create,
            "user",
            self.inner.create_user_without_account(user),
        )
        .await
    }

    async fn find_user_by_username(&self, username: &str) -> Result<Option<AuthUser>, AuthError> {
        with_adapter_operation(
            AdapterOperation::FindOne,
            "user",
            self.inner.find_user_by_username(username),
        )
        .await
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<AuthUser>, AuthError> {
        with_adapter_operation(
            AdapterOperation::FindOne,
            "user",
            self.inner.find_user_by_email(email),
        )
        .await
    }

    async fn update_user_profile(
        &self,
        user_id: &str,
        update: UserProfileUpdate,
    ) -> Result<Option<AuthUser>, AuthError> {
        with_adapter_operation(
            AdapterOperation::Update,
            "user",
            self.inner.update_user_profile(user_id, update),
        )
        .await
    }

    async fn update_user_email(
        &self,
        user_id: &str,
        expected_email: &str,
        new_email: &str,
        email_verified: bool,
    ) -> Result<Option<AuthUser>, AuthError> {
        with_adapter_operation(
            AdapterOperation::Update,
            "user",
            self.inner
                .update_user_email(user_id, expected_email, new_email, email_verified),
        )
        .await
    }

    async fn promote_email_owner(
        &self,
        user_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AuthUser>, AuthError> {
        with_adapter_operation(
            AdapterOperation::Update,
            "user",
            self.inner.promote_email_owner(user_id, now),
        )
        .await
    }

    async fn find_password_hash(&self, user_id: &str) -> Result<Option<String>, AuthError> {
        with_adapter_operation(
            AdapterOperation::FindOne,
            "account",
            self.inner.find_password_hash(user_id),
        )
        .await
    }

    async fn update_password_hash(
        &self,
        user_id: &str,
        password_hash: String,
    ) -> Result<(), AuthError> {
        with_adapter_operation(
            AdapterOperation::Update,
            "account",
            self.inner.update_password_hash(user_id, password_hash),
        )
        .await
    }

    async fn set_password_hash(
        &self,
        account_id: &dyn DatabaseIdSupplier,
        user_id: &str,
        password_hash: String,
    ) -> Result<(), AuthError> {
        with_adapter_operation(
            AdapterOperation::Update,
            "account",
            self.inner
                .set_password_hash(account_id, user_id, password_hash),
        )
        .await
    }

    async fn save_passkey(
        &self,
        passkey: DatabaseCreate<StoredPasskey>,
    ) -> Result<StoredPasskey, AuthError> {
        with_adapter_operation(
            AdapterOperation::Create,
            "passkey",
            self.inner.save_passkey(passkey),
        )
        .await
    }

    async fn list_passkeys(&self, user_id: &str) -> Result<Vec<StoredPasskey>, AuthError> {
        with_adapter_operation(
            AdapterOperation::FindMany,
            "passkey",
            self.inner.list_passkeys(user_id),
        )
        .await
    }

    async fn find_passkey_by_id(
        &self,
        passkey_id: &str,
    ) -> Result<Option<StoredPasskey>, AuthError> {
        with_adapter_operation(
            AdapterOperation::FindOne,
            "passkey",
            self.inner.find_passkey_by_id(passkey_id),
        )
        .await
    }

    async fn find_passkey_by_credential_id(
        &self,
        credential_id: &str,
    ) -> Result<Option<StoredPasskey>, AuthError> {
        with_adapter_operation(
            AdapterOperation::FindOne,
            "passkey",
            self.inner.find_passkey_by_credential_id(credential_id),
        )
        .await
    }

    async fn update_passkey_after_authentication(
        &self,
        passkey: StoredPasskey,
        expected_counter: u32,
    ) -> Result<bool, AuthError> {
        with_adapter_operation(
            AdapterOperation::Update,
            "passkey",
            self.inner
                .update_passkey_after_authentication(passkey, expected_counter),
        )
        .await
    }

    async fn update_passkey_name(
        &self,
        user_id: &str,
        passkey_id: &str,
        name: String,
    ) -> Result<Option<StoredPasskey>, AuthError> {
        with_adapter_operation(
            AdapterOperation::Update,
            "passkey",
            self.inner.update_passkey_name(user_id, passkey_id, name),
        )
        .await
    }

    async fn delete_passkey(
        &self,
        user_id: &str,
        passkey_id: &str,
        minimum_remaining: usize,
    ) -> Result<PasskeyDeleteOutcome, AuthError> {
        with_adapter_operation(
            AdapterOperation::Delete,
            "passkey",
            self.inner
                .delete_passkey(user_id, passkey_id, minimum_remaining),
        )
        .await
    }

    async fn delete_user_passkeys(&self, user_id: &str) -> Result<(), AuthError> {
        with_adapter_operation(
            AdapterOperation::DeleteMany,
            "passkey",
            self.inner.delete_user_passkeys(user_id),
        )
        .await
    }

    async fn find_user_by_id(&self, user_id: &str) -> Result<Option<AuthUser>, AuthError> {
        with_adapter_operation(
            AdapterOperation::FindOne,
            "user",
            self.inner.find_user_by_id(user_id),
        )
        .await
    }

    async fn create_session(
        &self,
        session: DatabaseCreate<AuthSession>,
    ) -> Result<AuthSession, AuthError> {
        with_adapter_operation(
            AdapterOperation::Create,
            "session",
            self.inner.create_session(session),
        )
        .await
    }

    async fn find_session(
        &self,
        token: &str,
    ) -> Result<Option<(AuthSession, AuthUser)>, AuthError> {
        with_adapter_operation(
            AdapterOperation::FindOne,
            "session",
            self.inner.find_session(token),
        )
        .await
    }

    async fn find_session_by_id(&self, session_id: &str) -> Result<Option<AuthSession>, AuthError> {
        with_adapter_operation(
            AdapterOperation::FindOne,
            "session",
            self.inner.find_session_by_id(session_id),
        )
        .await
    }

    async fn update_session_fields(
        &self,
        session_id: &str,
        fields: serde_json::Map<String, serde_json::Value>,
    ) -> Result<Option<AuthSession>, AuthError> {
        with_adapter_operation(
            AdapterOperation::Update,
            "session",
            self.inner.update_session_fields(session_id, fields),
        )
        .await
    }

    async fn refresh_session(
        &self,
        token: &str,
        expires_at: DateTime<Utc>,
        updated_at: DateTime<Utc>,
    ) -> Result<Option<AuthSession>, AuthError> {
        with_adapter_operation(
            AdapterOperation::Update,
            "session",
            self.inner.refresh_session(token, expires_at, updated_at),
        )
        .await
    }

    async fn delete_session(&self, token: &str) -> Result<(), AuthError> {
        with_adapter_operation(
            AdapterOperation::Delete,
            "session",
            self.inner.delete_session(token),
        )
        .await
    }

    async fn expire_session(
        &self,
        session_id: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        with_adapter_operation(
            AdapterOperation::Update,
            "session",
            self.inner.expire_session(session_id, expires_at),
        )
        .await
    }

    async fn delete_expired_sessions(&self, now: DateTime<Utc>) -> Result<(), AuthError> {
        with_adapter_operation(
            AdapterOperation::DeleteMany,
            "session",
            self.inner.delete_expired_sessions(now),
        )
        .await
    }
}
