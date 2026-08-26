use crate::{
    AuthError,
    chargebee::{
        ChargebeeItemType, ChargebeeStoreError, ChargebeeSubscription, ChargebeeSubscriptionItem,
        ChargebeeSubscriptionStatus,
    },
    postgres::{PostgresModel, PostgresWrite},
};
use serde_json::{Map, Value, json};
use sqlx::postgres::PgRow;

pub(super) fn subscription_writes<'a>(
    model: &'a PostgresModel<'_>,
    value: &ChargebeeSubscription,
) -> Result<Vec<PostgresWrite<'a>>, ChargebeeStoreError> {
    model
        .encode_fields([
            ("id", json!(value.id.to_string())),
            ("referenceId", json!(value.reference_id)),
            (
                "chargebeeCustomerId",
                optional_string(value.chargebee_customer_id.clone()),
            ),
            (
                "chargebeeSubscriptionId",
                optional_string(value.chargebee_subscription_id.clone()),
            ),
            ("status", json!(value.status.as_str())),
            ("periodStart", optional_date(value.period_start)),
            ("periodEnd", optional_date(value.period_end)),
            ("trialStart", optional_date(value.trial_start)),
            ("trialEnd", optional_date(value.trial_end)),
            ("canceledAt", optional_date(value.canceled_at)),
            ("seats", optional_number(value.seats)?),
            ("metadata", optional_string(value.metadata.clone())),
        ])
        .map_err(schema_error)
}

pub(super) fn decode_subscription(
    model: &PostgresModel<'_>,
    row: &PgRow,
) -> Result<ChargebeeSubscription, ChargebeeStoreError> {
    let mut values = model.decode_all(row).map_err(schema_error)?;
    Ok(ChargebeeSubscription {
        id: required_uuid(&mut values, "id")?,
        reference_id: required_string(&mut values, "referenceId")?,
        chargebee_customer_id: optional_string_value(&mut values, "chargebeeCustomerId")?,
        chargebee_subscription_id: optional_string_value(&mut values, "chargebeeSubscriptionId")?,
        status: required_string(&mut values, "status")?
            .parse::<ChargebeeSubscriptionStatus>()
            .expect("Chargebee status parsing is infallible"),
        period_start: optional_date_value(&mut values, "periodStart")?,
        period_end: optional_date_value(&mut values, "periodEnd")?,
        trial_start: optional_date_value(&mut values, "trialStart")?,
        trial_end: optional_date_value(&mut values, "trialEnd")?,
        canceled_at: optional_date_value(&mut values, "canceledAt")?,
        seats: optional_i64(&mut values, "seats")?.map(|value| value as f64),
        metadata: optional_string_value(&mut values, "metadata")?,
    })
}

pub(super) fn item_writes<'a>(
    model: &'a PostgresModel<'_>,
    value: &ChargebeeSubscriptionItem,
) -> Result<Vec<PostgresWrite<'a>>, ChargebeeStoreError> {
    model
        .encode_fields([
            ("id", json!(value.id.to_string())),
            ("subscriptionId", json!(value.subscription_id.to_string())),
            ("itemPriceId", json!(value.item_price_id)),
            ("itemType", json!(value.item_type.as_str())),
            ("quantity", number(value.quantity)?),
            ("unitPrice", optional_number(value.unit_price)?),
            ("amount", optional_number(value.amount)?),
        ])
        .map_err(schema_error)
}

pub(super) fn decode_item(
    model: &PostgresModel<'_>,
    row: &PgRow,
) -> Result<ChargebeeSubscriptionItem, ChargebeeStoreError> {
    let mut values = model.decode_all(row).map_err(schema_error)?;
    Ok(ChargebeeSubscriptionItem {
        id: required_uuid(&mut values, "id")?,
        subscription_id: required_uuid(&mut values, "subscriptionId")?,
        item_price_id: required_string(&mut values, "itemPriceId")?,
        item_type: required_string(&mut values, "itemType")?
            .parse::<ChargebeeItemType>()
            .expect("Chargebee item parsing is infallible"),
        quantity: required_i64(&mut values, "quantity")? as f64,
        unit_price: optional_i64(&mut values, "unitPrice")?.map(|v| v as f64),
        amount: optional_i64(&mut values, "amount")?.map(|v| v as f64),
    })
}

fn required_uuid(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<uuid::Uuid, ChargebeeStoreError> {
    uuid::Uuid::parse_str(&required_string(values, field)?).map_err(unavailable)
}
fn required_string(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<String, ChargebeeStoreError> {
    match values.remove(field) {
        Some(Value::String(value)) => Ok(value),
        _ => Err(invalid(field)),
    }
}
fn optional_string_value(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<String>, ChargebeeStoreError> {
    match values.remove(field) {
        Some(Value::String(value)) => Ok(Some(value)),
        Some(Value::Null) => Ok(None),
        _ => Err(invalid(field)),
    }
}
fn required_i64(values: &mut Map<String, Value>, field: &str) -> Result<i64, ChargebeeStoreError> {
    values
        .remove(field)
        .and_then(|value| value.as_i64())
        .ok_or_else(|| invalid(field))
}
fn optional_i64(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<i64>, ChargebeeStoreError> {
    match values.remove(field) {
        Some(Value::Number(value)) => value.as_i64().map(Some).ok_or_else(|| invalid(field)),
        Some(Value::Null) => Ok(None),
        _ => Err(invalid(field)),
    }
}
fn optional_date_value(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, ChargebeeStoreError> {
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
fn number(value: f64) -> Result<Value, ChargebeeStoreError> {
    if value.fract() == 0.0 && value >= i32::MIN as f64 && value <= i32::MAX as f64 {
        Ok(json!(value as i32))
    } else {
        Err(unavailable("Chargebee number must be a 32-bit integer"))
    }
}
fn optional_number(value: Option<f64>) -> Result<Value, ChargebeeStoreError> {
    value
        .map(number)
        .transpose()
        .map(|value| value.unwrap_or(Value::Null))
}
fn schema_error(error: AuthError) -> ChargebeeStoreError {
    unavailable(error)
}
fn invalid(field: &str) -> ChargebeeStoreError {
    unavailable(format!("invalid canonical Chargebee field `{field}`"))
}
fn unavailable(error: impl std::fmt::Display) -> ChargebeeStoreError {
    ChargebeeStoreError::Unavailable(error.to_string())
}
