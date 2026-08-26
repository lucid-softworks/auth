use super::{
    PostgresChargebeeStore, rows, schema_error, subscription_error, subscriptions_disabled,
};
use crate::{
    chargebee::{ChargebeeStoreError, ChargebeeSubscription, ChargebeeSubscriptionPatch},
    postgres::{PostgresModel, PostgresWrite},
};
use serde_json::{Value, json};
use sqlx::{Postgres, QueryBuilder};
use uuid::Uuid;

pub(super) async fn create(
    store: &PostgresChargebeeStore,
    value: ChargebeeSubscription,
) -> Result<ChargebeeSubscription, ChargebeeStoreError> {
    let model = store
        .model_if_present("subscription")?
        .ok_or_else(subscriptions_disabled)?;
    let mut query = insert_query(&model, rows::subscription_writes(&model, &value)?);
    query.push(" RETURNING ").push(model.all_projection());
    rows::decode_subscription(
        &model,
        &query
            .build()
            .fetch_one(store.pool())
            .await
            .map_err(subscription_error)?,
    )
}
pub(super) async fn find(
    store: &PostgresChargebeeStore,
    id: Uuid,
) -> Result<Option<ChargebeeSubscription>, ChargebeeStoreError> {
    find_by(store, "id", json!(id.to_string())).await
}
pub(super) async fn find_by_chargebee_id(
    store: &PostgresChargebeeStore,
    id: &str,
) -> Result<Option<ChargebeeSubscription>, ChargebeeStoreError> {
    find_by(store, "chargebeeSubscriptionId", json!(id)).await
}
pub(super) async fn list_by_reference(
    store: &PostgresChargebeeStore,
    id: &str,
) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError> {
    list_by(store, "referenceId", id).await
}
pub(super) async fn list_by_customer(
    store: &PostgresChargebeeStore,
    id: &str,
) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError> {
    list_by(store, "chargebeeCustomerId", id).await
}
pub(super) async fn delete_by_reference(
    store: &PostgresChargebeeStore,
    id: &str,
) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError> {
    delete_by(store, "referenceId", id).await
}
pub(super) async fn delete_by_customer(
    store: &PostgresChargebeeStore,
    id: &str,
) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError> {
    delete_by(store, "chargebeeCustomerId", id).await
}
pub(super) async fn update(
    store: &PostgresChargebeeStore,
    id: Uuid,
    patch: ChargebeeSubscriptionPatch,
) -> Result<Option<ChargebeeSubscription>, ChargebeeStoreError> {
    let Some(model) = store.model_if_present("subscription")? else {
        return Ok(None);
    };
    let Some(mut query) = update_query(&model, id, patch)? else {
        return find(store, id).await;
    };
    query.push(" RETURNING ").push(model.all_projection());
    fetch_optional(store, &model, query).await
}
pub(super) async fn delete(
    store: &PostgresChargebeeStore,
    id: Uuid,
) -> Result<Option<ChargebeeSubscription>, ChargebeeStoreError> {
    let Some(model) = store.model_if_present("subscription")? else {
        return Ok(None);
    };
    let mut query = QueryBuilder::new("DELETE FROM ");
    query.push(model.quoted_table()).push(" WHERE \"id\" = ");
    model
        .encode("id", json!(id.to_string()))
        .map_err(schema_error)?
        .push_bind(&mut query);
    query.push(" RETURNING ").push(model.all_projection());
    fetch_optional(store, &model, query).await
}
async fn find_by(
    store: &PostgresChargebeeStore,
    field: &str,
    value: Value,
) -> Result<Option<ChargebeeSubscription>, ChargebeeStoreError> {
    let Some(model) = store.model_if_present("subscription")? else {
        return Ok(None);
    };
    let mut query = filter_query(&model, field, value)?;
    query.push(" ORDER BY \"id\" LIMIT 1");
    fetch_optional(store, &model, query).await
}
async fn list_by(
    store: &PostgresChargebeeStore,
    field: &str,
    value: &str,
) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError> {
    rows_by(store, field, value, false).await
}
async fn delete_by(
    store: &PostgresChargebeeStore,
    field: &str,
    value: &str,
) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError> {
    rows_by(store, field, value, true).await
}
async fn rows_by(
    store: &PostgresChargebeeStore,
    field: &str,
    value: &str,
    delete: bool,
) -> Result<Vec<ChargebeeSubscription>, ChargebeeStoreError> {
    let Some(model) = store.model_if_present("subscription")? else {
        return Ok(Vec::new());
    };
    let mut query = if delete {
        let mut query = QueryBuilder::new("DELETE FROM ");
        query
            .push(model.quoted_table())
            .push(" WHERE ")
            .push(model.quoted_column(field).map_err(schema_error)?)
            .push(" = ");
        model
            .encode(field, json!(value))
            .map_err(schema_error)?
            .push_bind(&mut query);
        query.push(" RETURNING ").push(model.all_projection());
        query
    } else {
        let mut query = filter_query(&model, field, json!(value))?;
        query.push(" ORDER BY \"id\"");
        query
    };
    query
        .build()
        .fetch_all(store.pool())
        .await
        .map_err(subscription_error)?
        .iter()
        .map(|row| rows::decode_subscription(&model, row))
        .collect()
}
fn filter_query(
    model: &PostgresModel<'_>,
    field: &str,
    value: Value,
) -> Result<QueryBuilder<'static, Postgres>, ChargebeeStoreError> {
    let mut query = select_query(model);
    query
        .push(" WHERE ")
        .push(model.quoted_column(field).map_err(schema_error)?)
        .push(" = ");
    model
        .encode(field, value)
        .map_err(schema_error)?
        .push_bind(&mut query);
    Ok(query)
}
fn update_query(
    model: &PostgresModel<'_>,
    id: Uuid,
    patch: ChargebeeSubscriptionPatch,
) -> Result<Option<QueryBuilder<'static, Postgres>>, ChargebeeStoreError> {
    let mut values = Vec::new();
    push(
        &mut values,
        "referenceId",
        patch.reference_id.map(Value::String),
    );
    push(
        &mut values,
        "chargebeeCustomerId",
        patch.chargebee_customer_id.map(optional_string),
    );
    push(
        &mut values,
        "chargebeeSubscriptionId",
        patch.chargebee_subscription_id.map(optional_string),
    );
    push(
        &mut values,
        "status",
        patch.status.map(|value| json!(value.as_str())),
    );
    push(
        &mut values,
        "periodStart",
        patch.period_start.map(optional_date),
    );
    push(
        &mut values,
        "periodEnd",
        patch.period_end.map(optional_date),
    );
    push(
        &mut values,
        "trialStart",
        patch.trial_start.map(optional_date),
    );
    push(&mut values, "trialEnd", patch.trial_end.map(optional_date));
    push(
        &mut values,
        "canceledAt",
        patch.canceled_at.map(optional_date),
    );
    push(
        &mut values,
        "seats",
        patch.seats.map(optional_number).transpose()?,
    );
    push(&mut values, "metadata", patch.metadata.map(optional_string));
    let writes = model.encode_fields(values).map_err(schema_error)?;
    if writes.is_empty() {
        return Ok(None);
    }
    let mut query = update_prefix(model, writes);
    query.push(" WHERE \"id\" = ");
    model
        .encode("id", json!(id.to_string()))
        .map_err(schema_error)?
        .push_bind(&mut query);
    Ok(Some(query))
}
async fn fetch_optional(
    store: &PostgresChargebeeStore,
    model: &PostgresModel<'_>,
    mut query: QueryBuilder<'static, Postgres>,
) -> Result<Option<ChargebeeSubscription>, ChargebeeStoreError> {
    query
        .build()
        .fetch_optional(store.pool())
        .await
        .map_err(subscription_error)?
        .as_ref()
        .map(|row| rows::decode_subscription(model, row))
        .transpose()
}
fn select_query(model: &PostgresModel<'_>) -> QueryBuilder<'static, Postgres> {
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(model.all_projection())
        .push(" FROM ")
        .push(model.quoted_table());
    query
}
fn insert_query(
    model: &PostgresModel<'_>,
    writes: Vec<PostgresWrite<'_>>,
) -> QueryBuilder<'static, Postgres> {
    let mut query = QueryBuilder::new("INSERT INTO ");
    query.push(model.quoted_table()).push(" (");
    for (i, w) in writes.iter().enumerate() {
        if i > 0 {
            query.push(", ");
        }
        query.push(w.quoted_column());
    }
    query.push(") VALUES (");
    for (i, w) in writes.into_iter().enumerate() {
        if i > 0 {
            query.push(", ");
        }
        w.push_bind(&mut query);
    }
    query.push(")");
    query
}
fn update_prefix(
    model: &PostgresModel<'_>,
    writes: Vec<PostgresWrite<'_>>,
) -> QueryBuilder<'static, Postgres> {
    let mut query = QueryBuilder::new("UPDATE ");
    query.push(model.quoted_table()).push(" SET ");
    for (i, w) in writes.into_iter().enumerate() {
        if i > 0 {
            query.push(", ");
        }
        query.push(w.quoted_column()).push(" = ");
        w.push_bind(&mut query);
    }
    query
}
fn push(values: &mut Vec<(&'static str, Value)>, field: &'static str, value: Option<Value>) {
    if let Some(value) = value {
        values.push((field, value));
    }
}
fn optional_string(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::String)
}
fn optional_date(value: Option<chrono::DateTime<chrono::Utc>>) -> Value {
    value.map_or(Value::Null, |date| json!(date.to_rfc3339()))
}
fn optional_number(value: Option<f64>) -> Result<Value, ChargebeeStoreError> {
    value
        .map(|value| {
            if value.fract() == 0.0 {
                Ok(json!(value as i64))
            } else {
                Err(ChargebeeStoreError::Unavailable(
                    "Chargebee seats must be an integer".into(),
                ))
            }
        })
        .transpose()
        .map(|value| value.unwrap_or(Value::Null))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn subscription_queries_use_catalog_fields_and_no_legacy_timestamps() {
        let store = super::super::test_support::store();
        let model = store.model("subscription").unwrap();
        let filter = filter_query(&model, "referenceId", json!("secret owner")).unwrap();
        assert!(filter.sql().contains("FROM \"chargebee\"\"subscriptions\""));
        assert!(filter.sql().contains("WHERE \"physical referenceId\" = $1"));
        assert!(!filter.sql().contains("secret owner"));
        assert!(!filter.sql().contains("created_at"));
        assert!(!filter.sql().contains("updated_at"));
    }
}
