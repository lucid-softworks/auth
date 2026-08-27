mod codec;
mod data;
mod invitation;
mod member;
mod role;
mod team;

use super::{SqliteFilter, SqliteStore};
use crate::{AuthError, PreparedDatabaseId};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sqlx::{Sqlite, Transaction};

async fn insert<T: Serialize>(
    store: &SqliteStore,
    transaction: &mut Transaction<'_, Sqlite>,
    schema: &super::schema::SqliteSchema,
    model: &str,
    value: &T,
    id: PreparedDatabaseId,
) -> Result<Map<String, Value>, AuthError> {
    let record = super::codec::create_record(store, model, value, &id)?;
    super::query::execute::insert(transaction, schema, model, record).await
}

fn eq(field: &str, value: &str) -> SqliteFilter {
    SqliteFilter::equal(field, json!(value))
}

fn storage(error: sqlx::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}
