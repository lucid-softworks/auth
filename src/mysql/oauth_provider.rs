mod assertion;
mod client;
mod client_registration;
mod codec;
mod consent;
mod resource;
mod token;
mod token_io;

use super::{MySqlFilter, MySqlStore};
use crate::{AuthError, PreparedDatabaseId};
use serde::Serialize;
use serde_json::{Map, Value, json};

fn record<T: Serialize>(
    store: &MySqlStore,
    model: &str,
    value: &T,
    id: Option<PreparedDatabaseId>,
    extras: impl IntoIterator<Item = (&'static str, Value)>,
) -> Result<Map<String, Value>, AuthError> {
    let mut record = serde_json::to_value(value)
        .map_err(storage)?
        .as_object()
        .cloned()
        .ok_or_else(|| AuthError::Storage("OAuth Provider record is not an object".into()))?;
    record.remove("id");
    if let Some(PreparedDatabaseId::Value(value)) = id {
        record.insert("id".into(), value.to_json()?);
    }
    record.extend(
        extras
            .into_iter()
            .map(|(field, value)| (field.into(), value)),
    );
    let model = store.physical_schema()?.model(model)?;
    record.retain(|field, _| model.has_field(field));
    Ok(record)
}

fn eq(field: &str, value: impl Serialize) -> MySqlFilter {
    MySqlFilter::equal(field, json!(value))
}

fn storage(error: impl std::fmt::Display) -> AuthError {
    AuthError::Storage(error.to_string())
}
