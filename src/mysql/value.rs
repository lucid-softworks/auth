use crate::{AdditionalFieldType, AuthError, DatabaseIdType};
use chrono::{DateTime, SecondsFormat, Utc};
use serde_json::Value;
use sqlx::{MySql, QueryBuilder, Row, mysql::MySqlRow};

pub(super) enum MySqlValue {
    Text(Option<String>),
    Integer(Option<i64>),
    Double(Option<f64>),
    Date(Option<DateTime<Utc>>),
}

impl MySqlValue {
    pub(super) fn push_bind<'args>(self, query: &mut QueryBuilder<'args, MySql>) {
        match self {
            Self::Text(value) => query.push_bind(value),
            Self::Integer(value) => query.push_bind(value),
            Self::Double(value) => query.push_bind(value),
            Self::Date(value) => query.push_bind(value),
        };
    }
}

pub(super) fn encode_id(id_type: DatabaseIdType, value: Value) -> Result<MySqlValue, AuthError> {
    match id_type {
        DatabaseIdType::String | DatabaseIdType::Uuid => encode_text("id", value),
        DatabaseIdType::Serial => encode_integer("id", value, true),
    }
}

pub(super) fn encode(
    field: &str,
    field_type: AdditionalFieldType,
    bigint: bool,
    reference_id_type: Option<DatabaseIdType>,
    value: Value,
) -> Result<MySqlValue, AuthError> {
    if let Some(id_type) = reference_id_type {
        return encode_id(id_type, value);
    }
    match field_type {
        AdditionalFieldType::String | AdditionalFieldType::StringLiteral(_) => {
            encode_text(field, value)
        }
        AdditionalFieldType::Boolean => match value {
            Value::Null => Ok(MySqlValue::Integer(None)),
            Value::Bool(value) => Ok(MySqlValue::Integer(Some(i64::from(value)))),
            _ => Err(invalid_type(field, "boolean")),
        },
        AdditionalFieldType::Number if bigint => encode_integer(field, value, false),
        AdditionalFieldType::Number => encode_number(field, value),
        AdditionalFieldType::Date => match value {
            Value::Null => Ok(MySqlValue::Date(None)),
            Value::String(value) => parse_date(field, &value).map(|value| MySqlValue::Date(Some(value))),
            _ => Err(invalid_type(field, "ISO date string")),
        },
        AdditionalFieldType::Json
        | AdditionalFieldType::StringArray
        | AdditionalFieldType::NumberArray => match value {
            Value::Null => Ok(MySqlValue::Text(None)),
            value => serde_json::to_string(&value)
                .map(|value| MySqlValue::Text(Some(value)))
                .map_err(|error| AuthError::Storage(error.to_string())),
        },
    }
}

pub(super) fn decode(
    row: &MySqlRow,
    field: &str,
    field_type: AdditionalFieldType,
    bigint: bool,
    reference_id_type: Option<DatabaseIdType>,
) -> Result<Value, AuthError> {
    if let Some(id_type) = reference_id_type {
        return decode_id(row, field, id_type);
    }
    match field_type {
        AdditionalFieldType::String | AdditionalFieldType::StringLiteral(_) => {
            decode_text(row, field)
        }
        AdditionalFieldType::Boolean => row
            .try_get::<Option<i8>, _>(field)
            .map(|value| value.map_or(Value::Null, |value| Value::Bool(value == 1)))
            .map_err(storage),
        AdditionalFieldType::Number if bigint => decode_integer(row, field),
        AdditionalFieldType::Number => decode_number(row, field),
        AdditionalFieldType::Date => row
            .try_get::<Option<DateTime<Utc>>, _>(field)
            .map(|value| {
                value.map_or(Value::Null, |value| {
                    Value::String(value.to_rfc3339_opts(SecondsFormat::Millis, true))
                })
            })
            .map_err(storage),
        AdditionalFieldType::Json
        | AdditionalFieldType::StringArray
        | AdditionalFieldType::NumberArray => {
            decode_text(row, field).and_then(|value| match value {
                Value::Null => Ok(Value::Null),
                Value::String(value) => serde_json::from_str(&value)
                    .map_err(|error| AuthError::Storage(error.to_string())),
                _ => unreachable!("text decoding returns null or string"),
            })
        }
    }
}

pub(super) fn decode_id(
    row: &MySqlRow,
    field: &str,
    id_type: DatabaseIdType,
) -> Result<Value, AuthError> {
    match id_type {
        DatabaseIdType::String | DatabaseIdType::Uuid => decode_text(row, field),
        DatabaseIdType::Serial => row
            .try_get::<Option<i64>, _>(field)
            .map(|value| value.map_or(Value::Null, |value| Value::String(value.to_string())))
            .map_err(storage),
    }
}

fn encode_text(field: &str, value: Value) -> Result<MySqlValue, AuthError> {
    match value {
        Value::Null => Ok(MySqlValue::Text(None)),
        Value::String(value) => Ok(MySqlValue::Text(Some(value))),
        _ => Err(invalid_type(field, "string")),
    }
}

fn encode_integer(field: &str, value: Value, allow_string: bool) -> Result<MySqlValue, AuthError> {
    match value {
        Value::Null => Ok(MySqlValue::Integer(None)),
        Value::Number(value) => value
            .as_i64()
            .map(|value| MySqlValue::Integer(Some(value)))
            .ok_or_else(|| invalid_type(field, "integer")),
        Value::String(value) if allow_string => value
            .parse::<i64>()
            .map(|value| MySqlValue::Integer(Some(value)))
            .map_err(|_| invalid_type(field, "integer")),
        _ => Err(invalid_type(field, "integer")),
    }
}

fn encode_number(field: &str, value: Value) -> Result<MySqlValue, AuthError> {
    match value {
        Value::Null => Ok(MySqlValue::Integer(None)),
        Value::Number(value) if value.as_i64().is_some() => {
            Ok(MySqlValue::Integer(value.as_i64()))
        }
        Value::Number(value) => value
            .as_f64()
            .map(|value| MySqlValue::Double(Some(value)))
            .ok_or_else(|| invalid_type(field, "number")),
        _ => Err(invalid_type(field, "number")),
    }
}

fn decode_text(row: &MySqlRow, field: &str) -> Result<Value, AuthError> {
    row.try_get::<Option<String>, _>(field)
        .map(|value| value.map_or(Value::Null, Value::String))
        .map_err(storage)
}

fn decode_integer(row: &MySqlRow, field: &str) -> Result<Value, AuthError> {
    row.try_get::<Option<i64>, _>(field)
        .map(|value| value.map_or(Value::Null, |value| Value::Number(value.into())))
        .map_err(storage)
}

fn decode_number(row: &MySqlRow, field: &str) -> Result<Value, AuthError> {
    if let Ok(value) = row.try_get::<Option<i64>, _>(field) {
        return Ok(value.map_or(Value::Null, |value| Value::Number(value.into())));
    }
    row.try_get::<Option<f64>, _>(field)
        .map_err(storage)
        .and_then(|value| match value {
            None => Ok(Value::Null),
            Some(value) => serde_json::Number::from_f64(value)
                .map(Value::Number)
                .ok_or_else(|| invalid_type(field, "finite number")),
        })
}

fn parse_date(field: &str, value: &str) -> Result<DateTime<Utc>, AuthError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| invalid_type(field, "ISO date string"))
}

fn invalid_type(field: &str, expected: &str) -> AuthError {
    AuthError::InvalidConfiguration(format!(
        "MySQL field '{field}' requires a {expected} value"
    ))
}

fn storage(error: sqlx::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn booleans_and_structured_values_use_non_native_adapter_forms() {
        assert!(matches!(
            encode(
                "enabled",
                AdditionalFieldType::Boolean,
                false,
                None,
                Value::Bool(true)
            )
            .unwrap(),
            MySqlValue::Integer(Some(1))
        ));
        assert!(matches!(
            encode(
                "data",
                AdditionalFieldType::Json,
                false,
                None,
                serde_json::json!({"ok": true})
            )
            .unwrap(),
            MySqlValue::Text(Some(value)) if value == "{\"ok\":true}"
        ));
    }

    #[test]
    fn dates_bind_as_utc_driver_values() {
        let MySqlValue::Date(Some(value)) = encode(
            "createdAt",
            AdditionalFieldType::Date,
            false,
            None,
            Value::String("2026-08-31T12:34:56.123456+01:00".into()),
        )
        .unwrap()
        else {
            panic!("date should bind as a native driver value");
        };
        assert_eq!(
            value.to_rfc3339_opts(SecondsFormat::Millis, true),
            "2026-08-31T11:34:56.123Z"
        );
    }
}
