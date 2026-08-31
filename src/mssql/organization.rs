mod codec;
mod create;
mod data;
mod invitation;
mod invitation_acceptance;
mod member;
mod role;
mod team;

use super::{MssqlFilter, MssqlStore};
use crate::{AuthError, PreparedDatabaseId};
use serde::Serialize;
use serde_json::{Map, Value, json};
use crate::mssql::MssqlTransaction;

async fn insert<T: Serialize>(
    store: &MssqlStore,
    transaction: &mut MssqlTransaction,
    schema: &super::schema::MssqlSchema,
    model: &str,
    value: &T,
    id: PreparedDatabaseId,
) -> Result<Map<String, Value>, AuthError> {
    let record = super::codec::create_record(store, model, value, &id)?;
    super::query::execute::insert_required(transaction, schema, model, record).await
}

fn eq(field: &str, value: &str) -> MssqlFilter {
    MssqlFilter::equal(field, json!(value))
}

fn storage(error: impl std::fmt::Display) -> AuthError {
    AuthError::Storage(error.to_string())
}
