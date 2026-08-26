use crate::{
    AuthError,
    creem::{CreemStoreError, CreemSubscription},
    postgres::{PostgresModel, PostgresWrite},
};
use serde_json::{Map, Value, json};
use sqlx::postgres::PgRow;

pub(super) fn writes<'a>(
    model: &'a PostgresModel<'_>,
    value: &CreemSubscription,
) -> Result<Vec<PostgresWrite<'a>>, CreemStoreError> {
    model
        .encode_fields([
            ("id", json!(value.id.to_string())),
            ("productId", json!(value.product_id)),
            ("referenceId", json!(value.reference_id)),
            (
                "creemCustomerId",
                optional_string(value.creem_customer_id.clone()),
            ),
            (
                "creemSubscriptionId",
                optional_string(value.creem_subscription_id.clone()),
            ),
            (
                "creemOrderId",
                optional_string(value.creem_order_id.clone()),
            ),
            ("status", json!(value.status)),
            ("periodStart", optional_date(value.period_start)),
            ("periodEnd", optional_date(value.period_end)),
            ("cancelAtPeriodEnd", json!(value.cancel_at_period_end)),
        ])
        .map_err(schema_error)
}

pub(super) fn decode(
    model: &PostgresModel<'_>,
    row: &PgRow,
) -> Result<CreemSubscription, CreemStoreError> {
    let mut values = model.decode_all(row).map_err(schema_error)?;
    Ok(CreemSubscription {
        id: uuid::Uuid::parse_str(&required_string(&mut values, "id")?).map_err(unavailable)?,
        product_id: required_string(&mut values, "productId")?,
        reference_id: required_string(&mut values, "referenceId")?,
        creem_customer_id: optional_string_value(&mut values, "creemCustomerId")?,
        creem_subscription_id: optional_string_value(&mut values, "creemSubscriptionId")?,
        creem_order_id: optional_string_value(&mut values, "creemOrderId")?,
        status: required_string(&mut values, "status")?,
        period_start: optional_date_value(&mut values, "periodStart")?,
        period_end: optional_date_value(&mut values, "periodEnd")?,
        cancel_at_period_end: values
            .remove("cancelAtPeriodEnd")
            .and_then(|value| value.as_bool())
            .ok_or_else(|| invalid("cancelAtPeriodEnd"))?,
    })
}

fn required_string(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<String, CreemStoreError> {
    match values.remove(field) {
        Some(Value::String(value)) => Ok(value),
        _ => Err(invalid(field)),
    }
}
fn optional_string_value(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<String>, CreemStoreError> {
    match values.remove(field) {
        Some(Value::String(value)) => Ok(Some(value)),
        Some(Value::Null) => Ok(None),
        _ => Err(invalid(field)),
    }
}
fn optional_date_value(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, CreemStoreError> {
    optional_string_value(values, field)?
        .map(|value| {
            chrono::DateTime::parse_from_rfc3339(&value)
                .map(|date| date.with_timezone(&chrono::Utc))
                .map_err(unavailable)
        })
        .transpose()
}
fn optional_string(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::String)
}
fn optional_date(value: Option<chrono::DateTime<chrono::Utc>>) -> Value {
    value.map_or(Value::Null, |date| json!(date.to_rfc3339()))
}
fn schema_error(error: AuthError) -> CreemStoreError {
    unavailable(error)
}
fn invalid(field: &str) -> CreemStoreError {
    unavailable(format!(
        "invalid canonical Creem subscription field `{field}`"
    ))
}
fn unavailable(error: impl std::fmt::Display) -> CreemStoreError {
    CreemStoreError::Unavailable(error.to_string())
}
