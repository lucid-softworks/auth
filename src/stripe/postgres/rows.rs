use crate::{
    AuthError,
    postgres::{PostgresModel, PostgresWrite},
    stripe::{BillingInterval, StripeStoreError, Subscription},
};
use serde_json::{Map, Value, json};
use sqlx::postgres::PgRow;

pub(super) fn writes<'a>(
    model: &'a PostgresModel<'_>,
    subscription: &Subscription,
) -> Result<Vec<PostgresWrite<'a>>, StripeStoreError> {
    model
        .encode_fields([
            ("id", json!(subscription.id.to_string())),
            ("plan", json!(subscription.plan)),
            ("referenceId", json!(subscription.reference_id)),
            (
                "stripeCustomerId",
                optional_string(subscription.stripe_customer_id.clone()),
            ),
            (
                "stripeSubscriptionId",
                optional_string(subscription.stripe_subscription_id.clone()),
            ),
            ("status", json!(subscription.status.as_str())),
            ("periodStart", optional_date(subscription.period_start)),
            ("periodEnd", optional_date(subscription.period_end)),
            ("trialStart", optional_date(subscription.trial_start)),
            ("trialEnd", optional_date(subscription.trial_end)),
            (
                "cancelAtPeriodEnd",
                json!(subscription.cancel_at_period_end),
            ),
            ("cancelAt", optional_date(subscription.cancel_at)),
            ("canceledAt", optional_date(subscription.canceled_at)),
            ("endedAt", optional_date(subscription.ended_at)),
            ("seats", optional_number(subscription.seats)?),
            (
                "billingInterval",
                optional_string(subscription.billing_interval.map(|v| v.as_str().to_owned())),
            ),
            (
                "stripeScheduleId",
                optional_string(subscription.stripe_schedule_id.clone()),
            ),
        ])
        .map_err(schema_error)
}

pub(super) fn decode(
    model: &PostgresModel<'_>,
    row: &PgRow,
) -> Result<Subscription, StripeStoreError> {
    let mut values = model.decode_all(row).map_err(schema_error)?;
    let status = required_string(&mut values, "status")?;
    Ok(Subscription {
        id: required_uuid(&mut values, "id")?,
        plan: required_string(&mut values, "plan")?,
        reference_id: required_string(&mut values, "referenceId")?,
        stripe_customer_id: optional_string_value(&mut values, "stripeCustomerId")?,
        stripe_subscription_id: optional_string_value(&mut values, "stripeSubscriptionId")?,
        status: status.parse().map_err(unavailable)?,
        period_start: optional_date_value(&mut values, "periodStart")?,
        period_end: optional_date_value(&mut values, "periodEnd")?,
        trial_start: optional_date_value(&mut values, "trialStart")?,
        trial_end: optional_date_value(&mut values, "trialEnd")?,
        cancel_at_period_end: required_bool(&mut values, "cancelAtPeriodEnd")?,
        cancel_at: optional_date_value(&mut values, "cancelAt")?,
        canceled_at: optional_date_value(&mut values, "canceledAt")?,
        ended_at: optional_date_value(&mut values, "endedAt")?,
        seats: optional_i64(&mut values, "seats")?.map(|value| value as f64),
        billing_interval: optional_string_value(&mut values, "billingInterval")?
            .map(|value| parse_billing_interval(&value))
            .transpose()?,
        stripe_schedule_id: optional_string_value(&mut values, "stripeScheduleId")?,
    })
}

fn parse_billing_interval(value: &str) -> Result<BillingInterval, StripeStoreError> {
    match value {
        "day" => Ok(BillingInterval::Day),
        "week" => Ok(BillingInterval::Week),
        "month" => Ok(BillingInterval::Month),
        "year" => Ok(BillingInterval::Year),
        _ => Err(unavailable(format!(
            "invalid persisted Stripe billing interval `{value}`"
        ))),
    }
}

fn required_uuid(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<uuid::Uuid, StripeStoreError> {
    uuid::Uuid::parse_str(&required_string(values, field)?).map_err(unavailable)
}

fn required_string(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<String, StripeStoreError> {
    match values.remove(field) {
        Some(Value::String(value)) => Ok(value),
        _ => Err(invalid_row(field)),
    }
}

fn optional_string_value(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<String>, StripeStoreError> {
    match values.remove(field) {
        Some(Value::String(value)) => Ok(Some(value)),
        Some(Value::Null) => Ok(None),
        _ => Err(invalid_row(field)),
    }
}

fn required_bool(values: &mut Map<String, Value>, field: &str) -> Result<bool, StripeStoreError> {
    values
        .remove(field)
        .and_then(|value| value.as_bool())
        .ok_or_else(|| invalid_row(field))
}

fn optional_i64(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<i64>, StripeStoreError> {
    match values.remove(field) {
        Some(Value::Number(value)) => value.as_i64().map(Some).ok_or_else(|| invalid_row(field)),
        Some(Value::Null) => Ok(None),
        _ => Err(invalid_row(field)),
    }
}

fn optional_date_value(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, StripeStoreError> {
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
    value.map_or(Value::Null, |v| json!(v.to_rfc3339()))
}
fn optional_number(value: Option<f64>) -> Result<Value, StripeStoreError> {
    value
        .map(|value| {
            if value.fract() == 0.0 && value >= i32::MIN as f64 && value <= i32::MAX as f64 {
                Ok(json!(value as i32))
            } else {
                Err(unavailable("Stripe seats must be a 32-bit integer"))
            }
        })
        .transpose()
        .map(|value| value.unwrap_or(Value::Null))
}
fn schema_error(error: AuthError) -> StripeStoreError {
    unavailable(error)
}
fn invalid_row(field: &str) -> StripeStoreError {
    unavailable(format!(
        "invalid canonical Stripe subscription field `{field}`"
    ))
}
fn unavailable(error: impl std::fmt::Display) -> StripeStoreError {
    StripeStoreError::Unavailable(error.to_string())
}
