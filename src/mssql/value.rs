use crate::{AdditionalFieldType, AuthError, DatabaseIdType};
use chrono::{DateTime, NaiveDateTime, SecondsFormat, Utc};
use serde_json::Value;
use tiberius::{Query, Row};

pub(super) enum MssqlValue {
    Text(Option<String>),
    SmallInteger(Option<i16>),
    Integer(Option<i64>),
}

impl MssqlValue {
    pub(super) fn bind(self, query: &mut Query<'static>) {
        match self {
            Self::Text(value) => query.bind(value),
            Self::SmallInteger(value) => query.bind(value),
            Self::Integer(value) => query.bind(value),
        }
    }
}

pub(super) fn encode_id(id_type: DatabaseIdType, value: Value) -> Result<MssqlValue, AuthError> {
    match id_type {
        DatabaseIdType::String | DatabaseIdType::Uuid => encode_text("id", value),
        DatabaseIdType::Serial => encode_integer("id", value, true),
    }
}

pub(super) fn encode(
    field: &str,
    field_type: AdditionalFieldType,
    _bigint: bool,
    reference_id_type: Option<DatabaseIdType>,
    value: Value,
) -> Result<MssqlValue, AuthError> {
    if let Some(id_type) = reference_id_type {
        return encode_id(id_type, value);
    }
    match field_type {
        AdditionalFieldType::String | AdditionalFieldType::StringLiteral(_) => {
            encode_text(field, value)
        }
        AdditionalFieldType::Boolean => match value {
            Value::Null => Ok(MssqlValue::SmallInteger(None)),
            Value::Bool(value) => Ok(MssqlValue::SmallInteger(Some(i16::from(value)))),
            _ => Err(invalid_type(field, "boolean")),
        },
        AdditionalFieldType::Number => encode_integer(field, value, false),
        AdditionalFieldType::Date => match value {
            Value::Null => Ok(MssqlValue::Text(None)),
            Value::String(value) => {
                parse_date(field, &value)?;
                Ok(MssqlValue::Text(Some(value)))
            }
            _ => Err(invalid_type(field, "ISO date string")),
        },
        AdditionalFieldType::Json
        | AdditionalFieldType::StringArray
        | AdditionalFieldType::NumberArray => match value {
            Value::Null => Ok(MssqlValue::Text(None)),
            value => serde_json::to_string(&value)
                .map(|value| MssqlValue::Text(Some(value)))
                .map_err(|error| AuthError::Storage(error.to_string())),
        },
    }
}

pub(super) fn decode(
    row: &Row,
    field: &str,
    field_type: AdditionalFieldType,
    _bigint: bool,
    reference_id_type: Option<DatabaseIdType>,
) -> Result<Value, AuthError> {
    if let Some(id_type) = reference_id_type {
        return decode_id(row, field, id_type);
    }
    match field_type {
        AdditionalFieldType::String | AdditionalFieldType::StringLiteral(_) => {
            decode_text(row, field)
        }
        AdditionalFieldType::Boolean => decode_smallint(row, field)
            .map(|value| value.map_or(Value::Null, |value| Value::Bool(value == 1))),
        AdditionalFieldType::Number => decode_integer(row, field)
            .map(|value| value.map_or(Value::Null, |value| Value::Number(value.into()))),
        AdditionalFieldType::Date => row
            .try_get::<NaiveDateTime, _>(field)
            .map(|value| {
                value.map_or(Value::Null, |value| {
                    Value::String(
                        DateTime::<Utc>::from_naive_utc_and_offset(value, Utc)
                            .to_rfc3339_opts(SecondsFormat::Millis, true),
                    )
                })
            })
            .map_err(storage),
        AdditionalFieldType::Json
        | AdditionalFieldType::StringArray
        | AdditionalFieldType::NumberArray => decode_text(row, field).and_then(|value| match value {
            Value::Null => Ok(Value::Null),
            Value::String(value) => serde_json::from_str(&value)
                .map_err(|error| AuthError::Storage(error.to_string())),
            _ => unreachable!("text decoding returns null or string"),
        }),
    }
}

pub(super) fn decode_id(
    row: &Row,
    field: &str,
    id_type: DatabaseIdType,
) -> Result<Value, AuthError> {
    match id_type {
        DatabaseIdType::String | DatabaseIdType::Uuid => decode_text(row, field),
        DatabaseIdType::Serial => decode_integer(row, field)
            .map(|value| value.map_or(Value::Null, |value| Value::String(value.to_string()))),
    }
}

fn encode_text(field: &str, value: Value) -> Result<MssqlValue, AuthError> {
    match value {
        Value::Null => Ok(MssqlValue::Text(None)),
        Value::String(value) => Ok(MssqlValue::Text(Some(value))),
        _ => Err(invalid_type(field, "string")),
    }
}

fn encode_integer(field: &str, value: Value, allow_string: bool) -> Result<MssqlValue, AuthError> {
    match value {
        Value::Null => Ok(MssqlValue::Integer(None)),
        Value::Number(value) => value
            .as_i64()
            .map(|value| MssqlValue::Integer(Some(value)))
            .ok_or_else(|| invalid_type(field, "integer")),
        Value::String(value) if allow_string => value
            .parse::<i64>()
            .map(|value| MssqlValue::Integer(Some(value)))
            .map_err(|_| invalid_type(field, "integer")),
        _ => Err(invalid_type(field, "integer")),
    }
}

fn decode_text(row: &Row, field: &str) -> Result<Value, AuthError> {
    row.try_get::<&str, _>(field)
        .map(|value| value.map_or(Value::Null, |value| Value::String(value.to_owned())))
        .map_err(storage)
}

fn decode_smallint(row: &Row, field: &str) -> Result<Option<i16>, AuthError> {
    row.try_get::<i16, _>(field).map_err(storage)
}

fn decode_integer(row: &Row, field: &str) -> Result<Option<i64>, AuthError> {
    if let Ok(value) = row.try_get::<i64, _>(field) {
        return Ok(value);
    }
    row.try_get::<i32, _>(field)
        .map(|value| value.map(i64::from))
        .map_err(storage)
}

fn parse_date(field: &str, value: &str) -> Result<DateTime<Utc>, AuthError> {
    DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| invalid_type(field, "ISO date string"))
}

fn invalid_type(field: &str, expected: &str) -> AuthError {
    AuthError::InvalidConfiguration(format!(
        "MSSQL field '{field}' requires {expected}"
    ))
}

fn storage(error: tiberius::error::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}
