use super::find;
use crate::{
    AuthError, AuthUser, DatabaseAccountOwnerWrite, DatabaseWrite, DatabaseWriteOperation,
    OAuthAccount, OAuthAccountOwner,
    store::{
        DatabaseCreate, DatabaseIdSupplier, DependentAccountContext, DependentAccountPreparer,
    },
};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

use super::super::{MySqlFilter, MySqlStore, codec, oauth};

pub(super) async fn create_user(
    store: &MySqlStore,
    value: DatabaseCreate<AuthUser>,
) -> Result<AuthUser, AuthError> {
    let (mut user, id) = value.into_parts(store)?;
    user.email = user.email.to_lowercase();
    let record = codec::create_record(store, "user", &user, &id)?;
    codec::decode(
        "user",
        store
            .insert_required_record("user", record)
            .await
            .map_err(user_insert_error)?,
    )
}

pub(super) async fn create_dependent_user(
    store: &MySqlStore,
    value: DatabaseCreate<AuthUser>,
    preparer: &dyn DependentAccountPreparer,
    credential: bool,
) -> Result<OAuthAccountOwner, AuthError> {
    let (mut user, id) = value.into_parts(store)?;
    user.email = user.email.to_lowercase();
    let schema = store.physical_schema()?;
    let mut transaction = store.pool.begin().await.map_err(storage)?;
    let record = codec::create_record(store, "user", &user, &id)?;
    let record = super::super::query::execute::insert_required(&mut transaction, schema, "user", record)
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

pub(super) async fn upsert_password(
    store: &MySqlStore,
    value: DatabaseWrite<AuthUser>,
    preparer: &dyn DependentAccountPreparer,
) -> Result<DatabaseAccountOwnerWrite, AuthError> {
    let schema = store.physical_schema()?;
    let mut transaction = store.pool.begin().await.map_err(storage)?;
    let (user, user_operation) = write_user(store, &mut transaction, schema, value).await?;
    let existing = credential_account(&mut transaction, schema, &user.id).await?;
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

async fn write_user(
    store: &MySqlStore,
    transaction: &mut sqlx::Transaction<'_, sqlx::MySql>,
    schema: &super::super::schema::MySqlSchema,
    value: DatabaseWrite<AuthUser>,
) -> Result<(AuthUser, DatabaseWriteOperation), AuthError> {
    match value {
        DatabaseWrite::Create(value) => {
            let (mut user, id) = value.into_parts(store)?;
            user.email = user.email.to_lowercase();
            let record = codec::create_record(store, "user", &user, &id)?;
            let stored = super::super::query::execute::insert_required(transaction, schema, "user", record)
                .await
                .map_err(user_insert_error)?;
            Ok((
                codec::decode("user", stored)?,
                DatabaseWriteOperation::Create,
            ))
        }
        DatabaseWrite::Update(mut user) => {
            user.email = user.email.to_lowercase();
            let values = codec::update_record(store, "user", &user)?;
            let stored = super::super::query::execute::update_one(
                transaction,
                schema,
                "user",
                &[MySqlFilter::equal("id", json!(user.id))],
                values,
            )
            .await?
            .ok_or(AuthError::NotFound)?;
            Ok((
                codec::decode("user", stored)?,
                DatabaseWriteOperation::Update,
            ))
        }
    }
}

async fn credential_account(
    transaction: &mut sqlx::Transaction<'_, sqlx::MySql>,
    schema: &super::super::schema::MySqlSchema,
    user_id: &str,
) -> Result<Option<OAuthAccount>, AuthError> {
    super::super::query::execute::find_one(
        transaction,
        schema,
        "account",
        &[
            MySqlFilter::equal("userId", json!(user_id)),
            MySqlFilter::equal("providerId", json!("credential")),
        ],
        &[],
    )
    .await?
    .map(codec::decode_oauth)
    .transpose()
}

async fn write_account(
    store: &MySqlStore,
    transaction: &mut sqlx::Transaction<'_, sqlx::MySql>,
    schema: &super::super::schema::MySqlSchema,
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
                &[MySqlFilter::equal("id", json!(id))],
            )
            .await?
            .ok_or(AuthError::CredentialAccountNotFound)?;
            Ok((account, DatabaseWriteOperation::Update))
        }
    }
}

pub(super) async fn update_user(
    store: &MySqlStore,
    filters: &[MySqlFilter],
    values: Map<String, Value>,
) -> Result<Option<AuthUser>, AuthError> {
    store
        .update_record("user", filters, values)
        .await
        .map_err(user_update_error)?
        .map(|record| codec::decode("user", record))
        .transpose()
}

pub(super) async fn promote(
    store: &MySqlStore,
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
    let filter = [MySqlFilter::equal("userId", json!(id))];
    super::super::query::execute::delete_many(&mut transaction, schema, "account", &filter).await?;
    super::super::query::execute::delete_many(&mut transaction, schema, "session", &filter).await?;
    let record = super::super::query::execute::update_one(
        &mut transaction,
        schema,
        "user",
        &[MySqlFilter::equal("id", json!(id))],
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

pub(super) async fn set_password(
    store: &MySqlStore,
    supplier: &dyn DatabaseIdSupplier,
    user_id: &str,
    hash: String,
) -> Result<(), AuthError> {
    let now = Utc::now();
    let mut account = oauth::find_credential(store, user_id)
        .await?
        .unwrap_or_else(|| credential(user_id, now));
    account.password = Some(hash);
    account.updated_at = now;
    if account.id.is_empty() {
        oauth::insert(store, account, supplier.prepare()?).await?;
    } else {
        let id = account.id.clone();
        oauth::update(store, &account, &[MySqlFilter::equal("id", json!(id))])
            .await?
            .ok_or(AuthError::CredentialAccountNotFound)?;
    }
    touch(store, user_id, now).await
}

fn credential(user_id: &str, now: DateTime<Utc>) -> OAuthAccount {
    OAuthAccount {
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
    }
}

pub(super) async fn touch(
    store: &MySqlStore,
    id: &str,
    now: DateTime<Utc>,
) -> Result<(), AuthError> {
    if store
        .update_record(
            "user",
            &[MySqlFilter::equal("id", json!(id))],
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

pub(super) fn require_field(
    model: &super::super::schema::MySqlModel<'_>,
    field: &str,
) -> Result<(), AuthError> {
    model.has_field(field).then_some(()).ok_or_else(|| {
        AuthError::InvalidConfiguration(format!(
            "user field '{field}' is not declared by the Better Auth schema"
        ))
    })
}

pub(super) fn fixed_user_field(field: &str) -> bool {
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
