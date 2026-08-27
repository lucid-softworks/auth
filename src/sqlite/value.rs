use crate::{AdditionalFieldType, AuthError, DatabaseIdType};
use serde_json::Value;
use sqlx::{QueryBuilder, Row, Sqlite, sqlite::SqliteRow};

pub(super) enum SqliteValue {
    Text(Option<String>),
    Integer(Option<i64>),
    Real(Option<f64>),
}

impl SqliteValue {
    pub(super) fn push_bind<'args>(self, query: &mut QueryBuilder<'args, Sqlite>) {
        match self {
            Self::Text(value) => query.push_bind(value),
            Self::Integer(value) => query.push_bind(value),
            Self::Real(value) => query.push_bind(value),
        };
    }
}

pub(super) fn encode_id(id_type: DatabaseIdType, value: Value) -> Result<SqliteValue, AuthError> {
    match id_type {
        DatabaseIdType::String | DatabaseIdType::Uuid => encode_text("id", value),
        DatabaseIdType::Serial => match value {
            Value::Null => Ok(SqliteValue::Integer(None)),
            Value::Number(number) => number
                .as_i64()
                .map(|value| SqliteValue::Integer(Some(value)))
                .ok_or_else(|| invalid_type("id", "integer")),
            Value::String(value) => value
                .parse::<i64>()
                .map(|value| SqliteValue::Integer(Some(value)))
                .map_err(|_| invalid_type("id", "integer")),
            _ => Err(invalid_type("id", "integer")),
        },
    }
}

pub(super) fn encode(
    field: &str,
    field_type: AdditionalFieldType,
    bigint: bool,
    reference_id_type: Option<DatabaseIdType>,
    value: Value,
) -> Result<SqliteValue, AuthError> {
    if let Some(id_type) = reference_id_type {
        return encode_id(id_type, value);
    }
    match field_type {
        AdditionalFieldType::String | AdditionalFieldType::StringLiteral(_) => {
            encode_text(field, value)
        }
        AdditionalFieldType::Boolean => match value {
            Value::Null => Ok(SqliteValue::Integer(None)),
            Value::Bool(value) => Ok(SqliteValue::Integer(Some(i64::from(value)))),
            _ => Err(invalid_type(field, "boolean")),
        },
        AdditionalFieldType::Number if bigint => encode_integer(field, value),
        AdditionalFieldType::Number => encode_number(field, value),
        AdditionalFieldType::Date => match value {
            Value::Null => Ok(SqliteValue::Text(None)),
            Value::String(value) => parse_date(field, &value).map(|value| {
                SqliteValue::Text(Some(
                    value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
                ))
            }),
            _ => Err(invalid_type(field, "ISO date string")),
        },
        AdditionalFieldType::Json
        | AdditionalFieldType::StringArray
        | AdditionalFieldType::NumberArray => match value {
            Value::Null => Ok(SqliteValue::Text(None)),
            value => serde_json::to_string(&value)
                .map(|value| SqliteValue::Text(Some(value)))
                .map_err(|error| AuthError::Storage(error.to_string())),
        },
    }
}

pub(super) fn decode(
    row: &SqliteRow,
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
            .try_get::<Option<i64>, _>(field)
            .map(|value| value.map_or(Value::Null, |value| Value::Bool(value == 1)))
            .map_err(storage),
        AdditionalFieldType::Number if bigint => row
            .try_get::<Option<i64>, _>(field)
            .map(|value| value.map_or(Value::Null, |value| Value::Number(value.into())))
            .map_err(storage),
        AdditionalFieldType::Number => decode_number(row, field),
        AdditionalFieldType::Date => decode_text(row, field).and_then(|value| match value {
            Value::Null => Ok(Value::Null),
            Value::String(value) => parse_date(field, &value).map(|date| {
                Value::String(date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
            }),
            _ => unreachable!("text decoding returns null or string"),
        }),
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
    row: &SqliteRow,
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

fn encode_text(field: &str, value: Value) -> Result<SqliteValue, AuthError> {
    match value {
        Value::Null => Ok(SqliteValue::Text(None)),
        Value::String(value) => Ok(SqliteValue::Text(Some(value))),
        _ => Err(invalid_type(field, "string")),
    }
}

fn encode_integer(field: &str, value: Value) -> Result<SqliteValue, AuthError> {
    match value {
        Value::Null => Ok(SqliteValue::Integer(None)),
        Value::Number(value) => value
            .as_i64()
            .map(|value| SqliteValue::Integer(Some(value)))
            .ok_or_else(|| invalid_type(field, "integer")),
        _ => Err(invalid_type(field, "integer")),
    }
}

fn encode_number(field: &str, value: Value) -> Result<SqliteValue, AuthError> {
    match value {
        Value::Null => Ok(SqliteValue::Integer(None)),
        Value::Number(value) if value.as_i64().is_some() => {
            Ok(SqliteValue::Integer(value.as_i64()))
        }
        Value::Number(value) => value
            .as_f64()
            .map(|value| SqliteValue::Real(Some(value)))
            .ok_or_else(|| invalid_type(field, "number")),
        _ => Err(invalid_type(field, "number")),
    }
}

fn decode_text(row: &SqliteRow, field: &str) -> Result<Value, AuthError> {
    row.try_get::<Option<String>, _>(field)
        .map(|value| value.map_or(Value::Null, Value::String))
        .map_err(storage)
}

fn decode_number(row: &SqliteRow, field: &str) -> Result<Value, AuthError> {
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

fn parse_date(field: &str, value: &str) -> Result<chrono::DateTime<chrono::Utc>, AuthError> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&chrono::Utc))
        .map_err(|_| invalid_type(field, "ISO date string"))
}

fn invalid_type(field: &str, expected: &str) -> AuthError {
    AuthError::InvalidConfiguration(format!(
        "SQLite field '{field}' requires a {expected} value"
    ))
}

fn storage(error: sqlx::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn date_writes_use_javascript_iso_milliseconds() {
        let SqliteValue::Text(Some(value)) = encode(
            "createdAt",
            AdditionalFieldType::Date,
            false,
            None,
            Value::String("2026-08-27T12:34:56.123456Z".into()),
        )
        .unwrap() else {
            panic!("date should encode as text");
        };
        assert_eq!(value, "2026-08-27T12:34:56.123Z");
    }

    #[test]
    fn json_and_arrays_write_json_text() {
        for (field_type, value, expected) in [
            (
                AdditionalFieldType::Json,
                serde_json::json!({"a": 1}),
                "{\"a\":1}",
            ),
            (
                AdditionalFieldType::StringArray,
                serde_json::json!(["a"]),
                "[\"a\"]",
            ),
            (
                AdditionalFieldType::NumberArray,
                serde_json::json!([1]),
                "[1]",
            ),
        ] {
            let SqliteValue::Text(Some(actual)) =
                encode("value", field_type, false, None, value).unwrap()
            else {
                panic!("structured value should encode as text");
            };
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn serial_ids_bind_as_integers() {
        assert!(matches!(
            encode_id(DatabaseIdType::Serial, Value::String("42".into())).unwrap(),
            SqliteValue::Integer(Some(42))
        ));
        assert!(encode_id(DatabaseIdType::Serial, Value::String("4.2".into())).is_err());
    }
}
