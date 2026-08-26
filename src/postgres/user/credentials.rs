use super::{decode_user, insert_transaction, user_insert_error, user_writes};
use crate::store::{DatabaseCreate, DatabaseIdValue, DatabaseWrite, PreparedDatabaseId};
use crate::{AuthError, AuthUser, OAuthAccount, OAuthAccountOwner};
use chrono::Utc;
use serde_json::{Map, Value, json};
use sqlx::{Postgres, QueryBuilder, Transaction};

pub(in crate::postgres) async fn create_password_user(
    store: &super::super::PostgresStore,
    user: DatabaseCreate<AuthUser>,
    credential_account: &dyn crate::store::DependentAccountPreparer,
) -> Result<OAuthAccountOwner, AuthError> {
    let (user, user_id) = user.into_parts(store)?;
    let user_model = store.user_model()?;
    let account_model = store.account_model()?;
    let mut transaction = store
        .pool
        .begin()
        .await
        .map_err(super::super::storage_error)?;
    let stored = insert_transaction(&mut transaction, &user_model, user, &user_id).await?;
    let credential_account = credential_account
        .prepare_account(crate::DependentAccountContext {
            user: &stored,
            user_operation: crate::DatabaseWriteOperation::Create,
            existing_account: None,
        })
        .await?;
    let DatabaseWrite::Create(credential_account) = credential_account else {
        return Err(AuthError::Storage(
            "fresh password user preparer returned an account update".into(),
        ));
    };
    let (mut credential_account, account_id) = credential_account.into_parts(store)?;
    credential_account.user_id = stored.id.clone();
    credential_account.account_id = stored.id.clone();
    let account = super::super::oauth::insert_account_transaction(
        &mut transaction,
        &account_model,
        &credential_account,
        &account_id,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(super::super::storage_error)?;
    Ok(OAuthAccountOwner {
        account,
        user: stored,
    })
}

pub(in crate::postgres) async fn upsert_password_user(
    store: &super::super::PostgresStore,
    user: DatabaseWrite<AuthUser>,
    credential_account: &dyn crate::DependentAccountPreparer,
) -> Result<crate::DatabaseAccountOwnerWrite, AuthError> {
    let user_model = store.user_model()?;
    let account_model = store.account_model()?;
    let mut transaction = store
        .pool
        .begin()
        .await
        .map_err(super::super::storage_error)?;
    let (stored, user_operation) = match user {
        DatabaseWrite::Create(value) => {
            let (mut user, id) = value.into_parts(store)?;
            user.email = user.email.to_lowercase();
            (
                insert_transaction(&mut transaction, &user_model, user, &id).await?,
                crate::DatabaseWriteOperation::Create,
            )
        }
        DatabaseWrite::Update(mut user) => {
            user.email = user.email.to_lowercase();
            let id = user.id.clone();
            let explicit = PreparedDatabaseId::Value(DatabaseIdValue::String(id.clone()));
            let mut writes = user_writes(&user_model, &user, &explicit)?;
            writes.retain(|write| !matches!(write.logical(), "id" | "createdAt"));
            let mut query = super::super::rows::update_query(&user_model, writes);
            query.push(" WHERE \"id\" = ");
            super::super::rows::push_model_value(&mut query, &user_model, "id", json!(id))?;
            query.push(" RETURNING ").push(user_model.all_projection());
            let row = query
                .build()
                .fetch_optional(&mut *transaction)
                .await
                .map_err(|error| user_insert_error(error, &user_model))?
                .ok_or(AuthError::NotFound)?;
            (
                decode_user(&user_model, &row)?,
                crate::DatabaseWriteOperation::Update,
            )
        }
    };
    let existing_account = super::super::oauth::find_credential_account_transaction(
        &mut transaction,
        &account_model,
        &stored.id,
    )
    .await?;
    let account_write = credential_account
        .prepare_account(crate::DependentAccountContext {
            user: &stored,
            user_operation,
            existing_account: existing_account.as_ref(),
        })
        .await?;
    let (account, account_operation) = write_credential_account(
        store,
        &mut transaction,
        &account_model,
        &stored.id,
        existing_account,
        account_write,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(super::super::storage_error)?;
    Ok(crate::DatabaseAccountOwnerWrite {
        owner: OAuthAccountOwner {
            account,
            user: stored,
        },
        user_operation,
        account_operation,
    })
}

async fn write_credential_account(
    store: &super::super::PostgresStore,
    transaction: &mut Transaction<'_, Postgres>,
    account_model: &super::super::PostgresModel<'_>,
    user_id: &str,
    existing_account: Option<OAuthAccount>,
    account_write: DatabaseWrite<OAuthAccount>,
) -> Result<(OAuthAccount, crate::DatabaseWriteOperation), AuthError> {
    match account_write {
        DatabaseWrite::Create(value) => {
            if existing_account.is_some() {
                return Err(AuthError::UserAlreadyExists);
            }
            let (mut account, id) = value.into_parts(store)?;
            account.user_id = user_id.to_owned();
            account.account_id = user_id.to_owned();
            Ok((
                super::super::oauth::insert_account_transaction(
                    transaction,
                    account_model,
                    &account,
                    &id,
                )
                .await?,
                crate::DatabaseWriteOperation::Create,
            ))
        }
        DatabaseWrite::Update(mut account) => {
            let existing = existing_account.ok_or(AuthError::CredentialAccountNotFound)?;
            if account.id != existing.id {
                return Err(AuthError::Storage(
                    "credential account update changed its database ID".into(),
                ));
            }
            account.user_id = user_id.to_owned();
            account.account_id = user_id.to_owned();
            Ok((
                super::super::oauth::update_account_transaction(
                    transaction,
                    account_model,
                    &account,
                )
                .await?,
                crate::DatabaseWriteOperation::Update,
            ))
        }
    }
}

pub(in crate::postgres) async fn find_password_hash(
    store: &super::super::PostgresStore,
    user_id: &str,
) -> Result<Option<String>, AuthError> {
    let model = store.account_model()?;
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(model.quoted_column("password")?)
        .push(" FROM ")
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("userId")?)
        .push(" = ");
    super::super::rows::push_model_value(&mut query, &model, "userId", json!(user_id))?;
    query
        .push(" AND ")
        .push(model.quoted_column("providerId")?)
        .push(" = ")
        .push_bind("credential".to_owned());
    query
        .build_query_scalar()
        .fetch_optional(&store.pool)
        .await
        .map_err(super::super::storage_error)
}

pub(in crate::postgres) async fn update_password_hash(
    store: &super::super::PostgresStore,
    user_id: &str,
    password_hash: String,
) -> Result<(), AuthError> {
    let account_model = store.account_model()?;
    let user_model = store.user_model()?;
    let now = Utc::now();
    let writes = account_model.encode_fields([
        ("password", Value::String(password_hash)),
        ("updatedAt", json!(now.to_rfc3339())),
    ])?;
    let mut transaction = store
        .pool
        .begin()
        .await
        .map_err(super::super::storage_error)?;
    let mut query = super::super::rows::update_query(&account_model, writes);
    query
        .push(" WHERE ")
        .push(account_model.quoted_column("userId")?)
        .push(" = ");
    super::super::rows::push_model_value(&mut query, &account_model, "userId", json!(user_id))?;
    query
        .push(" AND ")
        .push(account_model.quoted_column("providerId")?)
        .push(" = ")
        .push_bind("credential".to_owned());
    let result = query
        .build()
        .execute(&mut *transaction)
        .await
        .map_err(super::super::storage_error)?;
    if result.rows_affected() == 0 {
        return Err(AuthError::CredentialAccountNotFound);
    }
    super::mutations::touch_user(&mut transaction, &user_model, user_id, now).await?;
    transaction
        .commit()
        .await
        .map_err(super::super::storage_error)
}

pub(in crate::postgres) async fn set_password_hash(
    store: &super::super::PostgresStore,
    account_id: &dyn crate::store::DatabaseIdSupplier,
    user_id: &str,
    password_hash: String,
) -> Result<(), AuthError> {
    let account_model = store.account_model()?;
    let user_model = store.user_model()?;
    let now = Utc::now();
    let mut account = OAuthAccount {
        id: String::new(),
        user_id: user_id.to_owned(),
        issuer: "local:credential".into(),
        account_id: user_id.to_owned(),
        provider_id: "credential".into(),
        access_token: None,
        refresh_token: None,
        id_token: None,
        access_token_expires_at: None,
        refresh_token_expires_at: None,
        scope: None,
        password: Some(password_hash),
        additional_fields: Map::new(),
        created_at: now,
        updated_at: now,
    };
    let mut transaction = store
        .pool
        .begin()
        .await
        .map_err(super::super::storage_error)?;
    let mut existing = QueryBuilder::new("SELECT ");
    existing
        .push(account_model.all_projection())
        .push(" FROM ")
        .push(account_model.quoted_table())
        .push(" WHERE ")
        .push(account_model.quoted_column("issuer")?)
        .push(" = ")
        .push_bind(account.issuer.clone())
        .push(" AND ")
        .push(account_model.quoted_column("accountId")?)
        .push(" = ")
        .push_bind(account.account_id.clone())
        .push(" FOR UPDATE");
    let id = existing
        .build()
        .fetch_optional(&mut *transaction)
        .await
        .map_err(super::super::storage_error)?
        .as_ref()
        .map(|row| super::super::oauth::decode_account(&account_model, row))
        .transpose()?
        .map_or_else(
            || account_id.prepare(),
            |existing| Ok(super::super::rows::explicit_id(existing.id)),
        )?;
    account.id = match &id {
        PreparedDatabaseId::Value(value) => value.clone().into_output_string(),
        PreparedDatabaseId::Deferred | PreparedDatabaseId::DeferredSerial => String::new(),
    };
    super::super::oauth::upsert_account_transaction(
        &mut transaction,
        &account_model,
        &account,
        &id,
    )
    .await?;
    let affected =
        super::mutations::touch_user(&mut transaction, &user_model, user_id, now).await?;
    if affected == 0 {
        return Err(AuthError::NotFound);
    }
    transaction
        .commit()
        .await
        .map_err(super::super::storage_error)
}
