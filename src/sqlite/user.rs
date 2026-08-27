use super::{SqliteComparisonMode, SqliteFilter, SqliteStore, codec, oauth, passkey, session};
use crate::{
    AuthError, AuthSession, AuthStore, AuthUser, DatabaseAccountOwnerWrite,
    DatabaseIdAdapterCapabilities, DatabaseWrite, DatabaseWriteOperation, OAuthAccount,
    OAuthAccountOwner, StoredPasskey, UserProfileUpdate,
    store::{
        DatabaseCreate, DatabaseIdSupplier, DependentAccountContext, DependentAccountPreparer,
    },
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use std::sync::Arc;

#[async_trait]
impl AuthStore for SqliteStore {
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
        create_dependent_user(self, user, preparer, true).await
    }

    async fn upsert_password_user(
        &self,
        user: DatabaseWrite<AuthUser>,
        preparer: &dyn DependentAccountPreparer,
    ) -> Result<DatabaseAccountOwnerWrite, AuthError> {
        upsert_password(self, user, preparer).await
    }

    async fn create_anonymous_user(
        &self,
        user: DatabaseCreate<AuthUser>,
    ) -> Result<AuthUser, AuthError> {
        create_user(self, user).await
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
        create_user(self, user).await
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
            require_field(&model, "username")?;
            values.insert("username".into(), json!(value));
        }
        if let Some(value) = update.display_username {
            require_field(&model, "displayUsername")?;
            values.insert("displayUsername".into(), json!(value));
        }
        for (field, value) in update.additional_fields {
            if fixed_user_field(&field) {
                return Err(AuthError::InvalidConfiguration(format!(
                    "user additional field '{field}' collides with a canonical Better Auth field"
                )));
            }
            values.insert(field, value);
        }
        values.insert("updatedAt".into(), json!(Utc::now()));
        update_user(self, &[SqliteFilter::equal("id", json!(id))], values).await
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
        update_user(
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
        promote(self, id, now).await
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
        touch(self, user_id, account.updated_at).await
    }

    async fn set_password_hash(
        &self,
        account_id: &dyn DatabaseIdSupplier,
        user_id: &str,
        hash: String,
    ) -> Result<(), AuthError> {
        set_password(self, account_id, user_id, hash).await
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

async fn create_user(
    store: &SqliteStore,
    value: DatabaseCreate<AuthUser>,
) -> Result<AuthUser, AuthError> {
    let (mut user, id) = value.into_parts(store)?;
    user.email = user.email.to_lowercase();
    let record = codec::create_record(store, "user", &user, &id)?;
    codec::decode(
        "user",
        store
            .insert_record("user", record)
            .await
            .map_err(user_insert_error)?,
    )
}

async fn create_dependent_user(
    store: &SqliteStore,
    value: DatabaseCreate<AuthUser>,
    preparer: &dyn DependentAccountPreparer,
    credential: bool,
) -> Result<OAuthAccountOwner, AuthError> {
    let (mut user, id) = value.into_parts(store)?;
    user.email = user.email.to_lowercase();
    let schema = store.physical_schema()?;
    let mut transaction = store.pool.begin().await.map_err(storage)?;
    let record = codec::create_record(store, "user", &user, &id)?;
    let record = super::query::execute::insert(&mut transaction, schema, "user", record)
        .await
        .map_err(user_insert_error)?;
    let user: AuthUser = codec::decode("user", record)?;
    let write = preparer
        .prepare_account(DependentAccountContext {
            user: &user,
            user_operation: DatabaseWriteOperation::Create,
            existing_account: None,
        })
        .await?;
    let DatabaseWrite::Create(account) = write else {
        return Err(AuthError::Storage(
            "fresh password user preparer returned an account update".into(),
        ));
    };
    let (mut account, account_id) = account.into_parts(store)?;
    account.user_id = user.id.clone();
    if credential {
        account.account_id = user.id.clone();
    }
    let account =
        oauth::insert_transaction(store, &mut transaction, schema, account, account_id).await?;
    transaction.commit().await.map_err(storage)?;
    Ok(OAuthAccountOwner { account, user })
}

async fn upsert_password(
    store: &SqliteStore,
    value: DatabaseWrite<AuthUser>,
    preparer: &dyn DependentAccountPreparer,
) -> Result<DatabaseAccountOwnerWrite, AuthError> {
    let schema = store.physical_schema()?;
    let mut transaction = store.pool.begin().await.map_err(storage)?;
    let (user, user_operation) = match value {
        DatabaseWrite::Create(value) => {
            let (mut user, id) = value.into_parts(store)?;
            user.email = user.email.to_lowercase();
            let record = codec::create_record(store, "user", &user, &id)?;
            let stored = super::query::execute::insert(&mut transaction, schema, "user", record)
                .await
                .map_err(user_insert_error)?;
            (
                codec::decode::<AuthUser>("user", stored)?,
                DatabaseWriteOperation::Create,
            )
        }
        DatabaseWrite::Update(mut user) => {
            user.email = user.email.to_lowercase();
            let values = codec::update_record(store, "user", &user)?;
            let stored = super::query::execute::update_one(
                &mut transaction,
                schema,
                "user",
                &[SqliteFilter::equal("id", json!(user.id))],
                values,
            )
            .await?
            .ok_or(AuthError::NotFound)?;
            (
                codec::decode::<AuthUser>("user", stored)?,
                DatabaseWriteOperation::Update,
            )
        }
    };
    let existing = super::query::execute::find_one(
        &mut transaction,
        schema,
        "account",
        &[
            SqliteFilter::equal("userId", json!(user.id)),
            SqliteFilter::equal("providerId", json!("credential")),
        ],
        &[],
    )
    .await?
    .map(codec::decode_oauth)
    .transpose()?;
    let write = preparer
        .prepare_account(DependentAccountContext {
            user: &user,
            user_operation,
            existing_account: existing.as_ref(),
        })
        .await?;
    let (account, account_operation) =
        write_account(store, &mut transaction, schema, &user, existing, write).await?;
    transaction.commit().await.map_err(storage)?;
    Ok(DatabaseAccountOwnerWrite {
        owner: OAuthAccountOwner { account, user },
        user_operation,
        account_operation,
    })
}

async fn write_account(
    store: &SqliteStore,
    transaction: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    schema: &super::schema::SqliteSchema,
    user: &AuthUser,
    existing: Option<OAuthAccount>,
    write: DatabaseWrite<OAuthAccount>,
) -> Result<(OAuthAccount, DatabaseWriteOperation), AuthError> {
    match write {
        DatabaseWrite::Create(value) => {
            if existing.is_some() {
                return Err(AuthError::UserAlreadyExists);
            }
            let (mut account, id) = value.into_parts(store)?;
            account.user_id = user.id.clone();
            account.account_id = user.id.clone();
            Ok((
                oauth::insert_transaction(store, transaction, schema, account, id).await?,
                DatabaseWriteOperation::Create,
            ))
        }
        DatabaseWrite::Update(mut account) => {
            let existing = existing.ok_or(AuthError::CredentialAccountNotFound)?;
            if account.id != existing.id {
                return Err(AuthError::Storage(
                    "credential account update changed its database ID".into(),
                ));
            }
            account.user_id = user.id.clone();
            account.account_id = user.id.clone();
            let id = account.id.clone();
            let account = oauth::update_transaction(
                store,
                transaction,
                schema,
                &account,
                &[SqliteFilter::equal("id", json!(id))],
            )
            .await?
            .ok_or(AuthError::CredentialAccountNotFound)?;
            Ok((account, DatabaseWriteOperation::Update))
        }
    }
}

async fn update_user(
    store: &SqliteStore,
    filters: &[SqliteFilter],
    values: Map<String, Value>,
) -> Result<Option<AuthUser>, AuthError> {
    store
        .update_record("user", filters, values)
        .await
        .map_err(user_update_error)?
        .map(|record| codec::decode("user", record))
        .transpose()
}

async fn promote(
    store: &SqliteStore,
    id: &str,
    now: DateTime<Utc>,
) -> Result<Option<AuthUser>, AuthError> {
    let Some(user) = find(store, "id", id).await? else {
        return Ok(None);
    };
    if user.email_verified {
        return Ok(Some(user));
    }
    let schema = store.physical_schema()?;
    let mut transaction = store.pool.begin().await.map_err(storage)?;
    let filter = [SqliteFilter::equal("userId", json!(id))];
    super::query::execute::delete_many(&mut transaction, schema, "account", &filter).await?;
    super::query::execute::delete_many(&mut transaction, schema, "session", &filter).await?;
    let record = super::query::execute::update_one(
        &mut transaction,
        schema,
        "user",
        &[SqliteFilter::equal("id", json!(id))],
        Map::from_iter([
            ("emailVerified".into(), json!(true)),
            ("updatedAt".into(), json!(now)),
        ]),
    )
    .await?;
    transaction.commit().await.map_err(storage)?;
    record
        .map(|record| codec::decode("user", record))
        .transpose()
}

async fn set_password(
    store: &SqliteStore,
    supplier: &dyn DatabaseIdSupplier,
    user_id: &str,
    hash: String,
) -> Result<(), AuthError> {
    let now = Utc::now();
    let mut account = oauth::find_credential(store, user_id)
        .await?
        .unwrap_or_else(|| OAuthAccount {
            id: String::new(),
            user_id: user_id.into(),
            issuer: "local:credential".into(),
            account_id: user_id.into(),
            provider_id: "credential".into(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            password: None,
            additional_fields: Map::new(),
            created_at: now,
            updated_at: now,
        });
    account.password = Some(hash);
    account.updated_at = now;
    if account.id.is_empty() {
        oauth::insert(store, account, supplier.prepare()?).await?;
    } else {
        let id = account.id.clone();
        oauth::update(store, &account, &[SqliteFilter::equal("id", json!(id))])
            .await?
            .ok_or(AuthError::CredentialAccountNotFound)?;
    }
    touch(store, user_id, now).await
}

async fn touch(store: &SqliteStore, id: &str, now: DateTime<Utc>) -> Result<(), AuthError> {
    if store
        .update_record(
            "user",
            &[SqliteFilter::equal("id", json!(id))],
            Map::from_iter([("updatedAt".into(), json!(now))]),
        )
        .await?
        .is_some()
    {
        Ok(())
    } else {
        Err(AuthError::NotFound)
    }
}

fn require_field(model: &super::schema::SqliteModel<'_>, field: &str) -> Result<(), AuthError> {
    model.has_field(field).then_some(()).ok_or_else(|| {
        AuthError::InvalidConfiguration(format!(
            "user field '{field}' is not declared by the Better Auth schema"
        ))
    })
}

fn fixed_user_field(field: &str) -> bool {
    matches!(
        field,
        "id" | "name"
            | "email"
            | "emailVerified"
            | "image"
            | "createdAt"
            | "updatedAt"
            | "username"
            | "displayUsername"
            | "role"
            | "isAnonymous"
            | "banned"
            | "banReason"
            | "banExpires"
    )
}

fn user_insert_error(error: AuthError) -> AuthError {
    match error {
        AuthError::Storage(message) if message.contains("UNIQUE constraint failed") => {
            AuthError::UserAlreadyExists
        }
        error => error,
    }
}
fn user_update_error(error: AuthError) -> AuthError {
    match error {
        AuthError::Storage(message) if message.contains("UNIQUE constraint failed") => {
            AuthError::UserAlreadyExistsEmail
        }
        error => error,
    }
}
fn storage(error: sqlx::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}
