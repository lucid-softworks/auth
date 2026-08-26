#[cfg(test)]
mod codec_tests;
mod credentials;
mod mutations;
pub(in crate::postgres) mod query;

pub(super) use super::rows::{decode_user, user_writes};
use super::{PostgresModel, PostgresStore, storage_error};
use crate::{AuthError, AuthUser, UsernameError};
pub(super) use credentials::{
    create_password_user, find_password_hash, set_password_hash, update_password_hash,
    upsert_password_user,
};
pub(super) use mutations::{
    create_without_account, promote_email_owner, update_email, update_profile,
};
use sqlx::{Postgres, QueryBuilder, Transaction};
use uuid::Uuid;

impl PostgresStore {
    pub(super) fn user_model(&self) -> Result<PostgresModel<'_>, AuthError> {
        self.physical_model("user")
    }
}

pub(super) async fn load_by_id(
    store: &PostgresStore,
    user_id: Uuid,
) -> Result<Option<AuthUser>, AuthError> {
    let model = store.user_model()?;
    let mut query = super::rows::select_query(&model);
    query.push(" WHERE \"id\" = ").push_bind(user_id);
    fetch_optional(&model, query, &store.pool).await
}

pub(super) async fn load_by_username(
    store: &PostgresStore,
    username: &str,
) -> Result<Option<AuthUser>, AuthError> {
    let model = store.user_model()?;
    let mut query = super::rows::select_query(&model);
    query
        .push(" WHERE ")
        .push(model.quoted_column("username")?)
        .push(" = ")
        .push_bind(username.to_owned());
    fetch_optional(&model, query, &store.pool).await
}

pub(super) async fn load_by_email(
    store: &PostgresStore,
    email: &str,
) -> Result<Option<AuthUser>, AuthError> {
    let model = store.user_model()?;
    let mut query = super::rows::select_query(&model);
    query
        .push(" WHERE LOWER(")
        .push(model.quoted_column("email")?)
        .push(") = LOWER(")
        .push_bind(email.to_owned())
        .push(")");
    fetch_optional(&model, query, &store.pool).await
}

pub(super) async fn load_by_id_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    user_id: Uuid,
) -> Result<Option<AuthUser>, AuthError> {
    let mut query = super::rows::select_query(model);
    query
        .push(" WHERE \"id\" = ")
        .push_bind(user_id)
        .push(" FOR UPDATE");
    let row = query
        .build()
        .fetch_optional(&mut **transaction)
        .await
        .map_err(storage_error)?;
    row.as_ref().map(|row| decode_user(model, row)).transpose()
}

pub(super) async fn email_exists_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    email: &str,
) -> Result<bool, AuthError> {
    let mut query = QueryBuilder::new("SELECT EXISTS(SELECT 1 FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE LOWER(")
        .push(model.quoted_column("email")?)
        .push(") = LOWER(")
        .push_bind(email.to_owned())
        .push("))");
    query
        .build_query_scalar()
        .fetch_one(&mut **transaction)
        .await
        .map_err(storage_error)
}

pub(super) async fn insert_transaction(
    transaction: &mut Transaction<'_, Postgres>,
    model: &PostgresModel<'_>,
    mut user: AuthUser,
) -> Result<AuthUser, AuthError> {
    user.email = user.email.to_lowercase();
    let writes = user_writes(model, &user)?;
    let mut query = super::rows::insert_query(model, writes);
    let row = query
        .build()
        .fetch_one(&mut **transaction)
        .await
        .map_err(|error| user_insert_error(error, model))?;
    decode_user(model, &row)
}

async fn fetch_optional(
    model: &PostgresModel<'_>,
    mut query: QueryBuilder<'static, Postgres>,
    pool: &sqlx::PgPool,
) -> Result<Option<AuthUser>, AuthError> {
    let row = query
        .build()
        .fetch_optional(pool)
        .await
        .map_err(storage_error)?;
    row.as_ref().map(|row| decode_user(model, row)).transpose()
}

pub(super) fn user_insert_error(error: sqlx::Error, model: &PostgresModel<'_>) -> AuthError {
    if is_unique_violation(&error) {
        let username_column = model.column("username").ok();
        if error
            .as_database_error()
            .and_then(|database| database.constraint())
            .is_some_and(|constraint| {
                username_column.is_some_and(|column| constraint.contains(column))
            })
        {
            UsernameError::AlreadyTaken.into()
        } else {
            AuthError::UserAlreadyExists
        }
    } else {
        storage_error(error)
    }
}

pub(super) fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|database| database.is_unique_violation())
}
