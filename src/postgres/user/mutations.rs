use super::{
    decode_user, is_unique_violation, load_by_id_transaction, user_insert_error, user_writes,
};
use crate::{AuthError, AuthUser, UserProfileUpdate, UsernameError};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use sqlx::{Postgres, QueryBuilder, Transaction};

pub(in crate::postgres) async fn create_without_account(
    store: &super::super::PostgresStore,
    user: crate::store::DatabaseCreate<AuthUser>,
) -> Result<AuthUser, AuthError> {
    let (mut user, id) = user.into_parts(store)?;
    let model = store.user_model()?;
    user.email = user.email.to_lowercase();
    let writes = user_writes(&model, &user, &id)?;
    let mut query = super::super::rows::insert_query(&model, writes);
    let row = query
        .build()
        .fetch_one(&store.pool)
        .await
        .map_err(|error| user_insert_error(error, &model))?;
    decode_user(&model, &row)
}

pub(in crate::postgres) async fn update_profile(
    store: &super::super::PostgresStore,
    user_id: &str,
    update: UserProfileUpdate,
) -> Result<Option<AuthUser>, AuthError> {
    let model = store.user_model()?;
    let mut values = Map::new();
    if let Some(name) = update.name {
        values.insert("name".into(), Value::String(name));
    }
    if let Some(image) = update.image {
        values.insert("image".into(), super::super::rows::optional_string(image));
    }
    if let Some(username) = update.username {
        require_user_field(&model, "username")?;
        values.insert("username".into(), Value::String(username));
    }
    if let Some(display_username) = update.display_username {
        require_user_field(&model, "displayUsername")?;
        values.insert("displayUsername".into(), Value::String(display_username));
    }
    for (logical, value) in update.additional_fields {
        if is_fixed_user_field(&logical) {
            return Err(AuthError::InvalidConfiguration(format!(
                "user additional field '{logical}' collides with a canonical Better Auth field"
            )));
        }
        values.insert(logical, value);
    }
    values.insert("updatedAt".into(), json!(Utc::now().to_rfc3339()));
    let writes = model.encode_fields(
        values
            .iter()
            .map(|(logical, value)| (logical.as_str(), value.clone())),
    )?;
    let mut query = super::super::rows::update_query(&model, writes);
    query.push(" WHERE \"id\" = ");
    super::super::rows::push_model_value(&mut query, &model, "id", json!(user_id))?;
    query.push(" RETURNING ").push(model.all_projection());
    let row = query
        .build()
        .fetch_optional(&store.pool)
        .await
        .map_err(|error| {
            if is_unique_violation(&error) {
                UsernameError::AlreadyTaken.into()
            } else {
                super::super::storage_error(error)
            }
        })?;
    row.as_ref().map(|row| decode_user(&model, row)).transpose()
}

pub(in crate::postgres) async fn update_email(
    store: &super::super::PostgresStore,
    user_id: &str,
    expected_email: &str,
    new_email: &str,
    email_verified: bool,
) -> Result<Option<AuthUser>, AuthError> {
    let model = store.user_model()?;
    let values = [
        ("email", json!(new_email.to_lowercase())),
        ("emailVerified", json!(email_verified)),
        ("updatedAt", json!(Utc::now().to_rfc3339())),
    ];
    let writes = model.encode_fields(values)?;
    let mut query = super::super::rows::update_query(&model, writes);
    query.push(" WHERE \"id\" = ");
    super::super::rows::push_model_value(&mut query, &model, "id", json!(user_id))?;
    query
        .push(" AND LOWER(")
        .push(model.quoted_column("email")?)
        .push(") = LOWER(")
        .push_bind(expected_email.to_owned())
        .push(") RETURNING ")
        .push(model.all_projection());
    let row = query
        .build()
        .fetch_optional(&store.pool)
        .await
        .map_err(|error| {
            if is_unique_violation(&error) {
                AuthError::UserAlreadyExistsEmail
            } else {
                super::super::storage_error(error)
            }
        })?;
    row.as_ref().map(|row| decode_user(&model, row)).transpose()
}

pub(in crate::postgres) async fn promote_email_owner(
    store: &super::super::PostgresStore,
    user_id: &str,
    now: DateTime<Utc>,
) -> Result<Option<AuthUser>, AuthError> {
    let user_model = store.user_model()?;
    let account_model = store.account_model()?;
    let session_model = store.physical_model("session")?;
    let mut transaction = store
        .pool
        .begin()
        .await
        .map_err(super::super::storage_error)?;
    let user = load_by_id_transaction(&mut transaction, &user_model, user_id).await?;
    let Some(user) = user else {
        transaction
            .commit()
            .await
            .map_err(super::super::storage_error)?;
        return Ok(None);
    };
    if user.email_verified {
        transaction
            .commit()
            .await
            .map_err(super::super::storage_error)?;
        return Ok(Some(user));
    }
    delete_for_user(&mut transaction, &account_model, user_id).await?;
    delete_for_user(&mut transaction, &session_model, user_id).await?;
    let writes = user_model.encode_fields([
        ("emailVerified", json!(true)),
        ("updatedAt", json!(now.to_rfc3339())),
    ])?;
    let mut query = super::super::rows::update_query(&user_model, writes);
    query.push(" WHERE \"id\" = ");
    super::super::rows::push_model_value(&mut query, &user_model, "id", json!(user_id))?;
    query.push(" RETURNING ").push(user_model.all_projection());
    let row = query
        .build()
        .fetch_one(&mut *transaction)
        .await
        .map_err(super::super::storage_error)?;
    let user = decode_user(&user_model, &row)?;
    transaction
        .commit()
        .await
        .map_err(super::super::storage_error)?;
    Ok(Some(user))
}

async fn delete_for_user(
    transaction: &mut Transaction<'_, Postgres>,
    model: &super::super::PostgresModel<'_>,
    user_id: &str,
) -> Result<(), AuthError> {
    let mut query = QueryBuilder::new("DELETE FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("userId")?)
        .push(" = ");
    super::super::rows::push_model_value(&mut query, model, "userId", json!(user_id))?;
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map_err(super::super::storage_error)?;
    Ok(())
}

pub(super) async fn touch_user(
    transaction: &mut Transaction<'_, Postgres>,
    model: &super::super::PostgresModel<'_>,
    user_id: &str,
    now: DateTime<Utc>,
) -> Result<u64, AuthError> {
    let writes = model.encode_fields([("updatedAt", json!(now.to_rfc3339()))])?;
    let mut query = super::super::rows::update_query(model, writes);
    query.push(" WHERE \"id\" = ");
    super::super::rows::push_model_value(&mut query, model, "id", json!(user_id))?;
    query
        .build()
        .execute(&mut **transaction)
        .await
        .map(|result| result.rows_affected())
        .map_err(super::super::storage_error)
}

fn require_user_field(
    model: &super::super::PostgresModel<'_>,
    logical: &str,
) -> Result<(), AuthError> {
    if model.has_field(logical) {
        Ok(())
    } else {
        Err(AuthError::InvalidConfiguration(format!(
            "user field '{logical}' is not declared by the Better Auth schema"
        )))
    }
}

fn is_fixed_user_field(logical: &str) -> bool {
    matches!(
        logical,
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
