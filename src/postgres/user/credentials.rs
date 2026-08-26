use super::{decode_user, insert_transaction, user_insert_error, user_writes};
use crate::{AuthError, AuthUser, OAuthAccount};
use chrono::Utc;
use serde_json::{Map, Value, json};
use sqlx::QueryBuilder;
use uuid::Uuid;

pub(in crate::postgres) async fn create_password_user(
    store: &super::super::PostgresStore,
    user: AuthUser,
    mut credential_account: OAuthAccount,
) -> Result<AuthUser, AuthError> {
    let user_model = store.user_model()?;
    let account_model = store.account_model()?;
    let mut transaction = store
        .pool
        .begin()
        .await
        .map_err(super::super::storage_error)?;
    let stored = insert_transaction(&mut transaction, &user_model, user).await?;
    credential_account.user_id = stored.id;
    super::super::oauth::insert_account_transaction(
        &mut transaction,
        &account_model,
        &credential_account,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(super::super::storage_error)?;
    Ok(stored)
}

pub(in crate::postgres) async fn upsert_password_user(
    store: &super::super::PostgresStore,
    mut user: AuthUser,
    mut credential_account: OAuthAccount,
) -> Result<AuthUser, AuthError> {
    user.email = user.email.to_lowercase();
    let user_model = store.user_model()?;
    let account_model = store.account_model()?;
    if !user_model.has_field("username") || user.username.is_none() {
        return Err(AuthError::InvalidConfiguration(
            "upserting a password user requires the Better Auth username plugin".into(),
        ));
    }
    let writes = user_writes(&user_model, &user)?;
    let mut transaction = store
        .pool
        .begin()
        .await
        .map_err(super::super::storage_error)?;
    let mut query = super::super::rows::insert_query_prefix(&user_model, writes);
    query
        .push(" ON CONFLICT (")
        .push(user_model.quoted_column("username")?)
        .push(") DO UPDATE SET ");
    let update_fields = ["displayUsername", "name", "email", "role", "updatedAt"];
    let mut wrote = false;
    for logical in update_fields
        .into_iter()
        .chain(user.additional_fields.keys().map(String::as_str))
    {
        if !user_model.has_field(logical) {
            continue;
        }
        if wrote {
            query.push(", ");
        }
        let column = user_model.quoted_column(logical)?;
        query.push(column).push(" = EXCLUDED.").push(column);
        wrote = true;
    }
    query.push(" RETURNING ").push(user_model.all_projection());
    let row = query
        .build()
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| user_insert_error(error, &user_model))?;
    let stored = decode_user(&user_model, &row)?;
    credential_account.user_id = stored.id;
    credential_account.account_id = stored.id.to_string();
    super::super::oauth::upsert_account_transaction(
        &mut transaction,
        &account_model,
        &credential_account,
    )
    .await?;
    transaction
        .commit()
        .await
        .map_err(super::super::storage_error)?;
    Ok(stored)
}

pub(in crate::postgres) async fn find_password_hash(
    store: &super::super::PostgresStore,
    user_id: Uuid,
) -> Result<Option<String>, AuthError> {
    let model = store.account_model()?;
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(model.quoted_column("password")?)
        .push(" FROM ")
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("userId")?)
        .push(" = ")
        .push_bind(user_id)
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
    user_id: Uuid,
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
        .push(" = ")
        .push_bind(user_id)
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
    user_id: Uuid,
    password_hash: String,
) -> Result<(), AuthError> {
    let account_model = store.account_model()?;
    let user_model = store.user_model()?;
    let now = Utc::now();
    let account = OAuthAccount {
        id: Uuid::new_v4(),
        user_id,
        issuer: "local:credential".into(),
        account_id: user_id.to_string(),
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
    super::super::oauth::upsert_account_transaction(&mut transaction, &account_model, &account)
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
