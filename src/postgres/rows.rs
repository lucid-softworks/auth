use super::{PostgresModel, PostgresWrite};
use crate::{AuthError, AuthUser};
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use sqlx::postgres::PgRow;
use uuid::Uuid;

pub(super) use super::user::query::{
    insert_query, insert_query_prefix, select_query, update_query,
};

pub(super) fn user_writes<'a>(
    model: &'a PostgresModel<'_>,
    user: &AuthUser,
) -> Result<Vec<PostgresWrite<'a>>, AuthError> {
    let mut values = Map::new();
    values.insert("id".into(), json!(user.id.to_string()));
    values.insert("name".into(), json!(user.name));
    values.insert("email".into(), json!(user.email));
    values.insert("emailVerified".into(), json!(user.email_verified));
    values.insert("image".into(), optional_string(user.image.clone()));
    values.insert("createdAt".into(), json!(user.created_at.to_rfc3339()));
    values.insert("updatedAt".into(), json!(user.updated_at.to_rfc3339()));
    insert_if_present(
        model,
        &mut values,
        "username",
        optional_string(user.username.clone()),
    );
    insert_if_present(
        model,
        &mut values,
        "displayUsername",
        optional_string(user.display_username.clone()),
    );
    insert_if_present(model, &mut values, "role", json!(user.role));
    insert_if_present(model, &mut values, "isAnonymous", json!(user.is_anonymous));
    insert_if_present(model, &mut values, "banned", json!(user.banned));
    insert_if_present(
        model,
        &mut values,
        "banReason",
        optional_string(user.ban_reason.clone()),
    );
    insert_if_present(
        model,
        &mut values,
        "banExpires",
        optional_date(user.ban_expires),
    );
    for (logical, value) in &user.additional_fields {
        if values.contains_key(logical) {
            return Err(AuthError::InvalidConfiguration(format!(
                "user additional field '{logical}' collides with a canonical Better Auth field"
            )));
        }
        if model.has_field(logical) {
            values.insert(logical.clone(), value.clone());
        }
    }
    model.encode_fields(
        values
            .iter()
            .map(|(logical, value)| (logical.as_str(), value.clone())),
    )
}

pub(super) fn decode_user(model: &PostgresModel<'_>, row: &PgRow) -> Result<AuthUser, AuthError> {
    decode_user_values(model, model.decode_all(row)?)
}

pub(super) fn decode_user_values(
    model: &PostgresModel<'_>,
    mut values: Map<String, Value>,
) -> Result<AuthUser, AuthError> {
    let id = required_uuid(&mut values, "id")?;
    let name = required_string(&mut values, "name")?;
    let email = required_string(&mut values, "email")?;
    let email_verified = required_bool(&mut values, "emailVerified")?;
    let image = optional_string_value(&mut values, "image")?;
    let created_at = required_date(&mut values, "createdAt")?;
    let updated_at = required_date(&mut values, "updatedAt")?;
    let username = optional_plugin_string(model, &mut values, "username")?;
    let display_username = optional_plugin_string(model, &mut values, "displayUsername")?;
    let role = plugin_string(model, &mut values, "role", "user")?;
    let is_anonymous = plugin_bool(model, &mut values, "isAnonymous", false)?;
    let banned = plugin_bool(model, &mut values, "banned", false)?;
    let ban_reason = optional_plugin_string(model, &mut values, "banReason")?;
    let ban_expires = optional_plugin_date(model, &mut values, "banExpires")?;
    values.remove("twoFactorEnabled");
    Ok(AuthUser {
        id,
        username,
        display_username,
        name,
        email,
        email_verified,
        image,
        additional_fields: values,
        role,
        is_anonymous,
        banned,
        ban_reason,
        ban_expires,
        created_at,
        updated_at,
    })
}

fn insert_if_present(
    model: &PostgresModel<'_>,
    values: &mut Map<String, Value>,
    logical: &str,
    value: Value,
) {
    if model.has_field(logical) {
        values.insert(logical.into(), value);
    }
}

pub(super) fn optional_string(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::String)
}

pub(super) fn optional_date(value: Option<DateTime<Utc>>) -> Value {
    value.map_or(Value::Null, |value| Value::String(value.to_rfc3339()))
}

pub(super) fn required_uuid(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Uuid, AuthError> {
    let value = required_string(values, field)?;
    Uuid::parse_str(&value).map_err(|_| invalid_row(field))
}

pub(super) fn required_string(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<String, AuthError> {
    match take(values, field)? {
        Value::String(value) => Ok(value),
        _ => Err(invalid_row(field)),
    }
}

pub(super) fn optional_string_value(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<String>, AuthError> {
    match take(values, field)? {
        Value::Null => Ok(None),
        Value::String(value) => Ok(Some(value)),
        _ => Err(invalid_row(field)),
    }
}

pub(super) fn required_bool(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<bool, AuthError> {
    match take(values, field)? {
        Value::Bool(value) => Ok(value),
        _ => Err(invalid_row(field)),
    }
}

pub(super) fn required_date(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<DateTime<Utc>, AuthError> {
    let value = required_string(values, field)?;
    DateTime::parse_from_rfc3339(&value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| invalid_row(field))
}

pub(super) fn optional_date_value(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<DateTime<Utc>>, AuthError> {
    match take(values, field)? {
        Value::Null => Ok(None),
        Value::String(value) => DateTime::parse_from_rfc3339(&value)
            .map(|value| Some(value.with_timezone(&Utc)))
            .map_err(|_| invalid_row(field)),
        _ => Err(invalid_row(field)),
    }
}

fn optional_plugin_string(
    model: &PostgresModel<'_>,
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<String>, AuthError> {
    if model.has_field(field) {
        optional_string_value(values, field)
    } else {
        Ok(None)
    }
}

fn plugin_string(
    model: &PostgresModel<'_>,
    values: &mut Map<String, Value>,
    field: &str,
    default: &str,
) -> Result<String, AuthError> {
    if model.has_field(field) {
        match take(values, field)? {
            Value::Null => Ok(default.into()),
            Value::String(value) => Ok(value),
            _ => Err(invalid_row(field)),
        }
    } else {
        Ok(default.into())
    }
}

fn plugin_bool(
    model: &PostgresModel<'_>,
    values: &mut Map<String, Value>,
    field: &str,
    default: bool,
) -> Result<bool, AuthError> {
    if model.has_field(field) {
        match take(values, field)? {
            Value::Null => Ok(default),
            Value::Bool(value) => Ok(value),
            _ => Err(invalid_row(field)),
        }
    } else {
        Ok(default)
    }
}

fn optional_plugin_date(
    model: &PostgresModel<'_>,
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<DateTime<Utc>>, AuthError> {
    if model.has_field(field) {
        optional_date_value(values, field)
    } else {
        Ok(None)
    }
}

fn take(values: &mut Map<String, Value>, field: &str) -> Result<Value, AuthError> {
    values.remove(field).ok_or_else(|| invalid_row(field))
}

fn invalid_row(field: &str) -> AuthError {
    AuthError::Storage(format!(
        "PostgreSQL returned an invalid canonical user field '{field}'"
    ))
}
