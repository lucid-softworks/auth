mod codec;
mod create;
mod data;
mod invitation;
mod invitation_acceptance;
mod member;
mod role;
mod team;

use super::{MongoFilter, MongoStore};
use crate::{AuthError, PreparedDatabaseId};
use serde::Serialize;
use serde_json::{Map, Value, json};

async fn insert<T: Serialize>(
    store: &MongoStore,
    transaction: &mut crate::mongodb::query::MongoTransaction,
    schema: &super::schema::MongoSchema,
    model: &str,
    value: &T,
    id: PreparedDatabaseId,
) -> Result<Map<String, Value>, AuthError> {
    let record = super::codec::create_record(store, model, value, &id)?;
    super::query::execute::insert_required(transaction, schema, model, record).await
}

fn eq(field: &str, value: &str) -> MongoFilter {
    MongoFilter::equal(field, json!(value))
}

fn storage(error: AuthError) -> AuthError {
    AuthError::Storage(error.to_string())
}
