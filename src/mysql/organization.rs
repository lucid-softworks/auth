mod codec;
mod create;
mod data;
mod invitation;
mod invitation_acceptance;
mod member;
mod role;
mod team;

use super::{MySqlFilter, MySqlStore};
use crate::{AuthError, PreparedDatabaseId};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sqlx::{MySql, Transaction};

async fn insert<T: Serialize>(
    store: &MySqlStore,
    transaction: &mut Transaction<'_, MySql>,
    schema: &super::schema::MySqlSchema,
    model: &str,
    value: &T,
    id: PreparedDatabaseId,
) -> Result<Map<String, Value>, AuthError> {
    let record = super::codec::create_record(store, model, value, &id)?;
    super::query::execute::insert_required(transaction, schema, model, record).await
}

fn eq(field: &str, value: &str) -> MySqlFilter {
    MySqlFilter::equal(field, json!(value))
}

fn storage(error: sqlx::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}
