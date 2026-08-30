use super::{SqliteComparisonMode, SqliteFilter, SqliteStore, codec, oauth, passkey, session};
mod write;
use crate::{
    AuthError, AuthSession, AuthStore, AuthUser, DatabaseAccountOwnerWrite,
    DatabaseIdAdapterCapabilities, DatabaseWrite, OAuthAccountOwner, StoredPasskey,
    UserProfileUpdate,
    store::{DatabaseCreate, DatabaseIdSupplier, DependentAccountPreparer},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use std::sync::Arc;

#[async_trait]
impl AuthStore for SqliteStore {
    async fn dash_find_records(
        &self,
        model: &str,
        where_clause: &[crate::DashAdapterWhere],
        limit: Option<usize>,
        offset: usize,
        sort: Option<&crate::DashAdapterSort>,
        select: &[String],
    ) -> Result<Option<Vec<Map<String, Value>>>, AuthError> {
        super::dash::find(self, model, where_clause, limit, offset, sort, select)
            .await
            .map(Some)
    }

    async fn dash_create_record(
        &self,
        model: &str,
        data: Map<String, Value>,
    ) -> Result<Option<Map<String, Value>>, AuthError> {
        self.insert_record(model, data).await.map(Some)
    }

    async fn dash_update_record(
        &self,
        model: &str,
        where_clause: &[crate::DashAdapterWhere],
        update: Map<String, Value>,
    ) -> Result<Option<Option<Map<String, Value>>>, AuthError> {
        let filters = super::dash::filters(where_clause);
        self.update_record(model, &filters, update).await.map(Some)
    }

    async fn dash_count_records(
        &self,
        model: &str,
        where_clause: &[crate::DashAdapterWhere],
    ) -> Result<Option<u64>, AuthError> {
        let filters = super::dash::filters(where_clause);
        self.count_records(model, &filters).await.map(Some)
    }

    async fn transaction(
        &self,
        operation: Box<dyn crate::DatabaseTransactionOperation>,
    ) -> Result<Box<dyn std::any::Any + Send>, AuthError> {
        super::transaction::run(self, operation).await
    }

    fn database_adapter_name(&self) -> &str {
        "SQLite Adapter"
    }

    fn database_id_capabilities(&self) -> DatabaseIdAdapterCapabilities {
        DatabaseIdAdapterCapabilities::default()
    }

    fn bind_schema(&self, schema: Arc<crate::AuthSchemaCatalog>) -> Result<(), AuthError> {
        self.bind_catalog(schema)
    }

    fn jwk_store(&self) -> Option<&dyn crate::JwkStore> {
        Some(self)
    }

    async fn create_password_user(
        &self,
        user: DatabaseCreate<AuthUser>,
        preparer: &dyn DependentAccountPreparer,
    ) -> Result<OAuthAccountOwner, AuthError> {
        write::create_dependent_user(self, user, preparer, true).await
    }

    async fn upsert_password_user(
        &self,
        user: DatabaseWrite<AuthUser>,
        preparer: &dyn DependentAccountPreparer,
    ) -> Result<DatabaseAccountOwnerWrite, AuthError> {
        write::upsert_password(self, user, preparer).await
    }

    async fn create_anonymous_user(
        &self,
        user: DatabaseCreate<AuthUser>,
    ) -> Result<AuthUser, AuthError> {
        write::create_user(self, user).await
    }

    async fn create_user_without_account(
        &self,
        user: DatabaseCreate<AuthUser>,
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
        write::create_user(self, user).await
    }

    async fn find_user_by_username(&self, username: &str) -> Result<Option<AuthUser>, AuthError> {
        find(self, "username", username).await
    }

    async fn find_user_by_email(&self, email: &str) -> Result<Option<AuthUser>, AuthError> {
        let mut filter = SqliteFilter::equal("email", json!(email));
        filter.mode = SqliteComparisonMode::Insensitive;
        find_filtered(self, &[filter]).await
    }

    async fn update_user_profile(
        &self,
        id: &str,
        update: UserProfileUpdate,
    ) -> Result<Option<AuthUser>, AuthError> {
        let model = self.physical_schema()?.model("user")?;
        let mut values = Map::new();
        if let Some(value) = update.name {
            values.insert("name".into(), json!(value));
        }
        if let Some(value) = update.image {
            values.insert("image".into(), json!(value));
        }
        if let Some(value) = update.username {
            write::require_field(&model, "username")?;
            values.insert("username".into(), json!(value));
        }
        if let Some(value) = update.display_username {
            write::require_field(&model, "displayUsername")?;
            values.insert("displayUsername".into(), json!(value));
        }
        for (field, value) in update.additional_fields {
            if write::fixed_user_field(&field) {
                return Err(AuthError::InvalidConfiguration(format!(
                    "user additional field '{field}' collides with a canonical Better Auth field"
                )));
            }
            values.insert(field, value);
        }
        values.insert("updatedAt".into(), json!(Utc::now()));
        write::update_user(self, &[SqliteFilter::equal("id", json!(id))], values).await
    }

    async fn update_user_email(
        &self,
        id: &str,
        expected_email: &str,
        new_email: &str,
        verified: bool,
    ) -> Result<Option<AuthUser>, AuthError> {
        let mut email = SqliteFilter::equal("email", json!(expected_email));
        email.mode = SqliteComparisonMode::Insensitive;
        write::update_user(
            self,
            &[SqliteFilter::equal("id", json!(id)), email],
            Map::from_iter([
                ("email".into(), json!(new_email.to_lowercase())),
                ("emailVerified".into(), json!(verified)),
                ("updatedAt".into(), json!(Utc::now())),
            ]),
        )
        .await
    }

    async fn promote_email_owner(
        &self,
        id: &str,
        now: DateTime<Utc>,
    ) -> Result<Option<AuthUser>, AuthError> {
        write::promote(self, id, now).await
    }

    async fn find_password_hash(&self, user_id: &str) -> Result<Option<String>, AuthError> {
        Ok(oauth::find_credential(self, user_id)
            .await?
            .and_then(|account| account.password))
    }

    async fn update_password_hash(&self, user_id: &str, hash: String) -> Result<(), AuthError> {
        let mut account = oauth::find_credential(self, user_id)
            .await?
            .ok_or(AuthError::CredentialAccountNotFound)?;
        account.password = Some(hash);
        account.updated_at = Utc::now();
        oauth::update(
            self,
            &account,
            &[SqliteFilter::equal("id", json!(account.id))],
        )
        .await?
        .ok_or(AuthError::CredentialAccountNotFound)?;
        write::touch(self, user_id, account.updated_at).await
    }

    async fn set_password_hash(
        &self,
        account_id: &dyn DatabaseIdSupplier,
        user_id: &str,
        hash: String,
    ) -> Result<(), AuthError> {
        write::set_password(self, account_id, user_id, hash).await
    }

    async fn save_passkey(
        &self,
        value: DatabaseCreate<StoredPasskey>,
    ) -> Result<StoredPasskey, AuthError> {
        passkey::save(self, value).await
    }
    async fn list_passkeys(&self, user_id: &str) -> Result<Vec<StoredPasskey>, AuthError> {
        passkey::list(self, user_id).await
    }
    async fn find_passkey_by_id(&self, id: &str) -> Result<Option<StoredPasskey>, AuthError> {
        passkey::find(self, "id", id).await
    }
    async fn find_passkey_by_credential_id(
        &self,
        id: &str,
    ) -> Result<Option<StoredPasskey>, AuthError> {
        passkey::find(self, "credentialID", id).await
    }
    async fn update_passkey_after_authentication(
        &self,
        value: StoredPasskey,
        counter: u32,
    ) -> Result<bool, AuthError> {
        passkey::compare_and_swap(self, value, counter).await
    }
    async fn update_passkey_name(
        &self,
        user_id: &str,
        id: &str,
        name: String,
    ) -> Result<Option<StoredPasskey>, AuthError> {
        passkey::rename(self, user_id, id, name).await
    }
    async fn delete_passkey(
        &self,
        user_id: &str,
        id: &str,
        minimum: usize,
    ) -> Result<crate::PasskeyDeleteOutcome, AuthError> {
        passkey::delete(self, user_id, id, minimum).await
    }
    async fn delete_user_passkeys(&self, user_id: &str) -> Result<(), AuthError> {
        passkey::delete_for_user(self, user_id).await
    }

    async fn find_user_by_id(&self, id: &str) -> Result<Option<AuthUser>, AuthError> {
        if let Some(transaction) = crate::database_hooks::current_transaction() {
            return transaction
                .find_by_id(crate::DatabaseModel::User, id)
                .await
                .map(|record| {
                    record.map(|record| match record {
                        crate::DatabaseRecord::User(user) => user,
                        _ => unreachable!("transaction lookup preserves its model"),
                    })
                });
        }
        find(self, "id", id).await
    }
    async fn create_session(
        &self,
        value: DatabaseCreate<AuthSession>,
    ) -> Result<AuthSession, AuthError> {
        session::create(self, value).await
    }
    async fn find_session(
        &self,
        token: &str,
    ) -> Result<Option<(AuthSession, AuthUser)>, AuthError> {
        let Some(session) = session::find_by_token(self, token).await? else {
            return Ok(None);
        };
        Ok(find(self, "id", &session.user_id)
            .await?
            .map(|user| (session, user)))
    }
    async fn find_session_by_id(&self, id: &str) -> Result<Option<AuthSession>, AuthError> {
        session::find_by_id(self, id).await
    }
    async fn update_session_fields(
        &self,
        id: &str,
        fields: Map<String, Value>,
    ) -> Result<Option<AuthSession>, AuthError> {
        session::update_fields(self, id, fields).await
    }
    async fn refresh_session(
        &self,
        token: &str,
        expires: DateTime<Utc>,
        updated: DateTime<Utc>,
    ) -> Result<Option<AuthSession>, AuthError> {
        session::refresh(self, token, expires, updated).await
    }
    async fn delete_session(&self, token: &str) -> Result<(), AuthError> {
        session::delete_by(self, "token", json!(token)).await
    }
    async fn expire_session(&self, id: &str, expires: DateTime<Utc>) -> Result<(), AuthError> {
        session::expire(self, id, expires).await
    }
    async fn delete_expired_sessions(&self, now: DateTime<Utc>) -> Result<(), AuthError> {
        session::delete_expired(self, now).await
    }
}

pub(super) async fn find(
    store: &SqliteStore,
    field: &str,
    value: &str,
) -> Result<Option<AuthUser>, AuthError> {
    find_filtered(store, &[SqliteFilter::equal(field, json!(value))]).await
}

async fn find_filtered(
    store: &SqliteStore,
    filters: &[SqliteFilter],
) -> Result<Option<AuthUser>, AuthError> {
    store
        .find_record("user", filters, &[])
        .await?
        .map(|record| codec::decode("user", record))
        .transpose()
}
