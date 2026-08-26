use super::{PostgresCreemStore, rows, schema_error, storage_error};
use crate::{
    creem::{CreemStoreError, CreemSubscription, CreemSubscriptionPatch},
    postgres::{PostgresModel, PostgresWrite},
};
use serde_json::{Value, json};
use sqlx::{Postgres, QueryBuilder};
use uuid::Uuid;

pub(super) async fn create(
    store: &PostgresCreemStore,
    value: CreemSubscription,
) -> Result<CreemSubscription, CreemStoreError> {
    let model = store.model("creem_subscription")?;
    let mut query = insert_query(&model, rows::writes(&model, &value)?);
    query.push(" RETURNING ").push(model.all_projection());
    rows::decode(
        &model,
        &query
            .build()
            .fetch_one(store.pool())
            .await
            .map_err(storage_error)?,
    )
}

pub(super) async fn find_by_creem_id(
    store: &PostgresCreemStore,
    id: &str,
) -> Result<Option<CreemSubscription>, CreemStoreError> {
    find_by(store, "creemSubscriptionId", json!(id)).await
}
pub(super) async fn list_by_reference(
    store: &PostgresCreemStore,
    id: &str,
) -> Result<Vec<CreemSubscription>, CreemStoreError> {
    list_by(store, "referenceId", id).await
}
pub(super) async fn list_by_customer(
    store: &PostgresCreemStore,
    id: &str,
) -> Result<Vec<CreemSubscription>, CreemStoreError> {
    list_by(store, "creemCustomerId", id).await
}

pub(super) async fn update(
    store: &PostgresCreemStore,
    id: Uuid,
    patch: CreemSubscriptionPatch,
) -> Result<Option<CreemSubscription>, CreemStoreError> {
    let Some(model) = store.model_if_present("creem_subscription")? else {
        return Ok(None);
    };
    let Some(mut query) = update_query(&model, id, patch)? else {
        return find_by(store, "id", json!(id.to_string())).await;
    };
    query.push(" RETURNING ").push(model.all_projection());
    fetch_optional(store, &model, query).await
}

async fn find_by(
    store: &PostgresCreemStore,
    field: &str,
    value: Value,
) -> Result<Option<CreemSubscription>, CreemStoreError> {
    let Some(model) = store.model_if_present("creem_subscription")? else {
        return Ok(None);
    };
    let mut query = filter_query(&model, field, value)?;
    query.push(" ORDER BY \"id\" LIMIT 1");
    fetch_optional(store, &model, query).await
}

async fn list_by(
    store: &PostgresCreemStore,
    field: &str,
    value: &str,
) -> Result<Vec<CreemSubscription>, CreemStoreError> {
    let Some(model) = store.model_if_present("creem_subscription")? else {
        return Ok(Vec::new());
    };
    let mut query = filter_query(&model, field, json!(value))?;
    query.push(" ORDER BY \"id\"");
    query
        .build()
        .fetch_all(store.pool())
        .await
        .map_err(storage_error)?
        .iter()
        .map(|row| rows::decode(&model, row))
        .collect()
}

fn filter_query(
    model: &PostgresModel<'_>,
    field: &str,
    value: Value,
) -> Result<QueryBuilder<'static, Postgres>, CreemStoreError> {
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
    patch: CreemSubscriptionPatch,
) -> Result<Option<QueryBuilder<'static, Postgres>>, CreemStoreError> {
    let mut values = Vec::new();
    push(&mut values, "status", patch.status.map(Value::String));
    push(
        &mut values,
        "productId",
        patch.product_id.map(Value::String),
    );
    push(
        &mut values,
        "referenceId",
        patch.reference_id.map(Value::String),
    );
    push(
        &mut values,
        "creemCustomerId",
        patch.creem_customer_id.map(optional_string),
    );
    push(
        &mut values,
        "creemSubscriptionId",
        patch.creem_subscription_id.map(optional_string),
    );
    push(
        &mut values,
        "creemOrderId",
        patch.creem_order_id.map(optional_string),
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
    store: &PostgresCreemStore,
    model: &PostgresModel<'_>,
    mut query: QueryBuilder<'static, Postgres>,
) -> Result<Option<CreemSubscription>, CreemStoreError> {
    query
        .build()
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)?
        .as_ref()
        .map(|row| rows::decode(model, row))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn subscription_queries_use_catalog_remaps_and_bound_values() {
        let store = super::super::test_support::store();
        let model = store.model("creem_subscription").unwrap();
        let filter = filter_query(&model, "referenceId", json!("secret owner")).unwrap();
        assert!(filter.sql().contains("FROM \"creem\"\"subscriptionss\""));
        assert!(filter.sql().contains("WHERE \"owner id\" = $1"));
        assert!(!filter.sql().contains("secret owner"));
        let update = update_query(
            &model,
            Uuid::nil(),
            CreemSubscriptionPatch {
                creem_subscription_id: Some(Some("sub_secret".into())),
                period_end: Some(None),
                ..CreemSubscriptionPatch::default()
            },
        )
        .unwrap()
        .unwrap();
        assert!(update.sql().contains("\"provider id\" = $1"));
        assert!(!update.sql().contains("sub_secret"));
    }
}
