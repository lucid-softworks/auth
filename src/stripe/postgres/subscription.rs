use super::{PostgresStripeStore, rows, schema_error, storage_error};
use crate::{
    postgres::{PostgresModel, PostgresWrite},
    stripe::{StripeStoreError, Subscription, SubscriptionPatch},
};
use serde_json::{Value, json};
use sqlx::{Postgres, QueryBuilder};
use uuid::Uuid;

pub(super) async fn create(
    store: &PostgresStripeStore,
    subscription: Subscription,
) -> Result<Subscription, StripeStoreError> {
    let model = store.model("subscription")?;
    let mut query = insert_query(&model, rows::writes(&model, &subscription)?);
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

pub(super) async fn find(
    store: &PostgresStripeStore,
    id: Uuid,
) -> Result<Option<Subscription>, StripeStoreError> {
    let Some(model) = store.model_if_present("subscription")? else {
        return Ok(None);
    };
    fetch_optional(store, &model, filter_query(&model, "id", uuid_value(id))?).await
}

pub(super) async fn find_by_stripe_id(
    store: &PostgresStripeStore,
    stripe_subscription_id: &str,
) -> Result<Option<Subscription>, StripeStoreError> {
    let Some(model) = store.model_if_present("subscription")? else {
        return Ok(None);
    };
    let mut query = filter_query(
        &model,
        "stripeSubscriptionId",
        json!(stripe_subscription_id),
    )?;
    query.push(" ORDER BY \"id\" LIMIT 1");
    fetch_optional(store, &model, query).await
}

pub(super) async fn list(
    store: &PostgresStripeStore,
    reference_id: &str,
) -> Result<Vec<Subscription>, StripeStoreError> {
    list_by(store, "referenceId", reference_id).await
}

pub(super) async fn list_by_customer(
    store: &PostgresStripeStore,
    stripe_customer_id: &str,
) -> Result<Vec<Subscription>, StripeStoreError> {
    list_by(store, "stripeCustomerId", stripe_customer_id).await
}

pub(super) async fn find_active_by_customer(
    store: &PostgresStripeStore,
    stripe_customer_id: &str,
) -> Result<Option<Subscription>, StripeStoreError> {
    let Some(model) = store.model_if_present("subscription")? else {
        return Ok(None);
    };
    let mut query = filter_query(&model, "stripeCustomerId", json!(stripe_customer_id))?;
    query
        .push(" AND ")
        .push(model.quoted_column("status").map_err(schema_error)?)
        .push(" IN (");
    model
        .encode("status", json!("active"))
        .map_err(schema_error)?
        .push_bind(&mut query);
    query.push(", ");
    model
        .encode("status", json!("trialing"))
        .map_err(schema_error)?
        .push_bind(&mut query);
    query.push(") ORDER BY \"id\" LIMIT 1");
    fetch_optional(store, &model, query).await
}

pub(super) async fn update(
    store: &PostgresStripeStore,
    id: Uuid,
    patch: SubscriptionPatch,
) -> Result<Option<Subscription>, StripeStoreError> {
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
    store: &PostgresStripeStore,
    id: Uuid,
) -> Result<Option<Subscription>, StripeStoreError> {
    let Some(model) = store.model_if_present("subscription")? else {
        return Ok(None);
    };
    let mut query = QueryBuilder::new("DELETE FROM ");
    query.push(model.quoted_table()).push(" WHERE \"id\" = ");
    model
        .encode("id", uuid_value(id))
        .map_err(schema_error)?
        .push_bind(&mut query);
    query.push(" RETURNING ").push(model.all_projection());
    fetch_optional(store, &model, query).await
}

async fn list_by(
    store: &PostgresStripeStore,
    field: &str,
    value: &str,
) -> Result<Vec<Subscription>, StripeStoreError> {
    let Some(model) = store.model_if_present("subscription")? else {
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
) -> Result<QueryBuilder<'static, Postgres>, StripeStoreError> {
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
    patch: SubscriptionPatch,
) -> Result<Option<QueryBuilder<'static, Postgres>>, StripeStoreError> {
    let mut values = Vec::new();
    push(&mut values, "plan", patch.plan.map(Value::String));
    push(
        &mut values,
        "stripeCustomerId",
        patch.stripe_customer_id.map(optional_string),
    );
    push(
        &mut values,
        "stripeSubscriptionId",
        patch.stripe_subscription_id.map(optional_string),
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
        "cancelAtPeriodEnd",
        patch.cancel_at_period_end.map(Value::Bool),
    );
    push(&mut values, "cancelAt", patch.cancel_at.map(optional_date));
    push(
        &mut values,
        "canceledAt",
        patch.canceled_at.map(optional_date),
    );
    push(&mut values, "endedAt", patch.ended_at.map(optional_date));
    push(
        &mut values,
        "seats",
        patch.seats.map(optional_number).transpose()?,
    );
    push(
        &mut values,
        "billingInterval",
        patch
            .billing_interval
            .map(|value| optional_string(value.map(|v| v.as_str().to_owned()))),
    );
    push(
        &mut values,
        "stripeScheduleId",
        patch.stripe_schedule_id.map(optional_string),
    );
    let writes = model.encode_fields(values).map_err(schema_error)?;
    if writes.is_empty() {
        return Ok(None);
    }
    let mut query = update_prefix(model, writes);
    query.push(" WHERE \"id\" = ");
    model
        .encode("id", uuid_value(id))
        .map_err(schema_error)?
        .push_bind(&mut query);
    Ok(Some(query))
}

async fn fetch_optional(
    store: &PostgresStripeStore,
    model: &PostgresModel<'_>,
    mut query: QueryBuilder<'static, Postgres>,
) -> Result<Option<Subscription>, StripeStoreError> {
    query
        .build()
        .fetch_optional(store.pool())
        .await
        .map_err(storage_error)?
        .as_ref()
        .map(|row| rows::decode(model, row))
        .transpose()
}

fn insert_query(
    model: &PostgresModel<'_>,
    writes: Vec<PostgresWrite<'_>>,
) -> QueryBuilder<'static, Postgres> {
    let mut query = QueryBuilder::new("INSERT INTO ");
    query.push(model.quoted_table()).push(" (");
    push_writes(&mut query, writes, true);
    query
}

fn update_prefix(
    model: &PostgresModel<'_>,
    writes: Vec<PostgresWrite<'_>>,
) -> QueryBuilder<'static, Postgres> {
    let mut query = QueryBuilder::new("UPDATE ");
    query.push(model.quoted_table()).push(" SET ");
    for (index, write) in writes.into_iter().enumerate() {
        if index > 0 {
            query.push(", ");
        }
        query.push(write.quoted_column()).push(" = ");
        write.push_bind(&mut query);
    }
    query
}

fn push_writes(
    query: &mut QueryBuilder<'static, Postgres>,
    writes: Vec<PostgresWrite<'_>>,
    insert: bool,
) {
    for (index, write) in writes.iter().enumerate() {
        if index > 0 {
            query.push(", ");
        }
        query.push(write.quoted_column());
    }
    if insert {
        query.push(") VALUES (");
    }
    for (index, write) in writes.into_iter().enumerate() {
        if index > 0 {
            query.push(", ");
        }
        write.push_bind(query);
    }
    if insert {
        query.push(")");
    }
}

fn select_query(model: &PostgresModel<'_>) -> QueryBuilder<'static, Postgres> {
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(model.all_projection())
        .push(" FROM ")
        .push(model.quoted_table());
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
fn optional_number(value: Option<f64>) -> Result<Value, StripeStoreError> {
    value
        .map(|value| {
            if value.fract() == 0.0 {
                Ok(json!(value as i64))
            } else {
                Err(StripeStoreError::Unavailable(
                    "Stripe seats must be an integer".into(),
                ))
            }
        })
        .transpose()
        .map(|value| value.unwrap_or(Value::Null))
}
fn uuid_value(value: Uuid) -> Value {
    Value::String(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn subscription_queries_use_hostile_catalog_remaps_and_no_legacy_timestamps() {
        let store = super::super::test_support::store();
        let model = store.model("subscription").unwrap();
        let filter = filter_query(&model, "referenceId", json!("secret owner")).unwrap();
        assert!(filter.sql().contains("FROM \"billing\"\"subscriptionss\""));
        assert!(filter.sql().contains("WHERE \"owner id\" = $1"));
        assert!(!filter.sql().contains("secret owner"));
        assert!(!filter.sql().contains("created_at"));

        let patch = update_query(
            &model,
            Uuid::nil(),
            SubscriptionPatch {
                stripe_subscription_id: Some(Some("sub_secret".into())),
                cancel_at: Some(None),
                ..SubscriptionPatch::default()
            },
        )
        .unwrap()
        .unwrap();
        assert!(patch.sql().contains("\"provider id\" = $1"));
        assert!(!patch.sql().contains("sub_secret"));
        assert!(!patch.sql().contains("updated_at"));

        let plural = super::super::test_support::plural_store();
        assert_eq!(
            plural.model("subscription").unwrap().quoted_table(),
            "\"subscriptions\""
        );
    }
}
