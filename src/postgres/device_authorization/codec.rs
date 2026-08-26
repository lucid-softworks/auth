use super::super::{PostgresModel, PostgresWrite};
use crate::{AuthError, DeviceCode, DeviceCodeStatus};
use serde_json::{Map, Value, json};
use sqlx::postgres::PgRow;
use std::str::FromStr;

pub(super) fn writes<'a>(
    model: &'a PostgresModel<'a>,
    code: &DeviceCode,
) -> Result<Vec<PostgresWrite<'a>>, AuthError> {
    let mut values = Map::from_iter([
        ("id".into(), json!(code.id.to_string())),
        ("deviceCode".into(), json!(code.device_code)),
        ("userCode".into(), json!(code.user_code)),
        ("userId".into(), optional_string(code.user_id.clone())),
        ("expiresAt".into(), json!(code.expires_at.to_rfc3339())),
        ("status".into(), json!(code.status.as_str())),
        (
            "lastPolledAt".into(),
            code.last_polled_at
                .map(|value| json!(value.to_rfc3339()))
                .unwrap_or(Value::Null),
        ),
        (
            "pollingInterval".into(),
            optional_number(code.polling_interval)?,
        ),
        ("clientId".into(), optional_string(code.client_id.clone())),
        ("scope".into(), optional_string(code.scope.clone())),
    ]);
    if model.has_field("resources") {
        values.insert(
            "resources".into(),
            code.resources
                .clone()
                .map(|resources| json!(resources))
                .unwrap_or(Value::Null),
        );
    }
    if model.has_field("oauthClientId") {
        values.insert(
            "oauthClientId".into(),
            optional_string(code.oauth_client_id.clone()),
        );
    }
    model.encode_fields(
        values
            .iter()
            .map(|(logical, value)| (logical.as_str(), value.clone())),
    )
}

pub(super) fn decode(model: &PostgresModel<'_>, row: &PgRow) -> Result<DeviceCode, AuthError> {
    decode_values(model, model.decode_all(row)?)
}

fn decode_values(
    model: &PostgresModel<'_>,
    mut values: Map<String, Value>,
) -> Result<DeviceCode, AuthError> {
    let id = required_uuid(&mut values, "id")?;
    let device_code = required_string(&mut values, "deviceCode")?;
    let user_code = required_string(&mut values, "userCode")?;
    let user_id = optional_string_value(&mut values, "userId")?;
    let expires_at = required_date(&mut values, "expiresAt")?;
    let status = DeviceCodeStatus::from_str(&required_string(&mut values, "status")?)
        .map_err(|_| invalid_row("status"))?;
    let last_polled_at = optional_date(&mut values, "lastPolledAt")?;
    let polling_interval = optional_number_value(&mut values, "pollingInterval")?;
    let client_id = optional_string_value(&mut values, "clientId")?;
    let scope = optional_string_value(&mut values, "scope")?;
    let resources = if model.has_field("resources") {
        optional_string_array(&mut values, "resources")?
    } else {
        None
    };
    let oauth_client_id = if model.has_field("oauthClientId") {
        optional_string_value(&mut values, "oauthClientId")?
    } else {
        None
    };
    Ok(DeviceCode {
        id,
        device_code,
        user_code,
        user_id,
        expires_at,
        status,
        last_polled_at,
        polling_interval,
        client_id,
        scope,
        resources,
        oauth_client_id,
    })
}

pub(super) fn number_value(value: f64) -> Result<Value, AuthError> {
    if !value.is_finite() || value.fract() != 0.0 {
        return Err(AuthError::Storage(
            "device polling interval must be a finite whole number of milliseconds".into(),
        ));
    }
    let value = value as i64;
    i32::try_from(value).map(|value| json!(value)).map_err(|_| {
        AuthError::Storage("device polling interval exceeds the database range".into())
    })
}

fn optional_number(value: Option<f64>) -> Result<Value, AuthError> {
    value.map_or(Ok(Value::Null), number_value)
}

fn optional_string(value: Option<String>) -> Value {
    value.map(Value::String).unwrap_or(Value::Null)
}

fn required_uuid(values: &mut Map<String, Value>, field: &str) -> Result<uuid::Uuid, AuthError> {
    let value = required_string(values, field)?;
    uuid::Uuid::parse_str(&value).map_err(|_| invalid_row(field))
}

fn required_string(values: &mut Map<String, Value>, field: &str) -> Result<String, AuthError> {
    take(values, field)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid_row(field))
}

fn optional_string_value(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<String>, AuthError> {
    match take(values, field)? {
        Value::Null => Ok(None),
        Value::String(value) => Ok(Some(value)),
        _ => Err(invalid_row(field)),
    }
}

fn required_date(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<chrono::DateTime<chrono::Utc>, AuthError> {
    parse_date(&required_string(values, field)?).ok_or_else(|| invalid_row(field))
}

fn optional_date(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, AuthError> {
    optional_string_value(values, field)?
        .map(|value| parse_date(&value).ok_or_else(|| invalid_row(field)))
        .transpose()
}

fn parse_date(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&chrono::Utc))
}

fn optional_number_value(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<f64>, AuthError> {
    match take(values, field)? {
        Value::Null => Ok(None),
        Value::Number(value) => value.as_f64().map(Some).ok_or_else(|| invalid_row(field)),
        _ => Err(invalid_row(field)),
    }
}

fn optional_string_array(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<Vec<String>>, AuthError> {
    match take(values, field)? {
        Value::Null => Ok(None),
        Value::Array(values) => values
            .into_iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| invalid_row(field))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        _ => Err(invalid_row(field)),
    }
}

fn take(values: &mut Map<String, Value>, field: &str) -> Result<Value, AuthError> {
    values.remove(field).ok_or_else(|| invalid_row(field))
}

fn invalid_row(field: &str) -> AuthError {
    AuthError::Storage(format!(
        "PostgreSQL returned an invalid canonical deviceCode field '{field}'"
    ))
}
