use super::transport::D1Value;
use crate::{AdditionalFieldType, AuthError, DatabaseIdType};
use serde_json::Value;

pub(super) fn encode_id(id_type: DatabaseIdType, value: Value) -> Result<D1Value, AuthError> {
    match id_type {
        DatabaseIdType::String | DatabaseIdType::Uuid => encode_text("id", value),
        DatabaseIdType::Serial => encode_integer("id", value),
    }
}

pub(super) fn encode(
    field: &str,
    field_type: AdditionalFieldType,
    bigint: bool,
    reference_id_type: Option<DatabaseIdType>,
    value: Value,
) -> Result<D1Value, AuthError> {
    if let Some(id_type) = reference_id_type {
        return encode_id(id_type, value);
    }
    match field_type {
        AdditionalFieldType::String | AdditionalFieldType::StringLiteral(_) => {
            encode_text(field, value)
        }
        AdditionalFieldType::Boolean => match value {
            Value::Null => Ok(D1Value::Null),
            Value::Bool(value) => Ok(D1Value::Integer(i64::from(value))),
            _ => Err(invalid_type(field, "boolean")),
        },
        AdditionalFieldType::Number if bigint => encode_integer(field, value),
        AdditionalFieldType::Number => encode_number(field, value),
        AdditionalFieldType::Date => match value {
            Value::Null => Ok(D1Value::Null),
            Value::String(value) => parse_date(field, &value).map(|value| {
                D1Value::Text(value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
            }),
            _ => Err(invalid_type(field, "ISO date string")),
        },
        AdditionalFieldType::Json
        | AdditionalFieldType::StringArray
        | AdditionalFieldType::NumberArray => match value {
            Value::Null => Ok(D1Value::Null),
            value => serde_json::to_string(&value)
                .map(D1Value::Text)
                .map_err(|error| AuthError::Storage(error.to_string())),
        },
    }
}

pub(super) fn decode_id(
    row: &serde_json::Map<String, Value>,
    field: &str,
    id_type: DatabaseIdType,
) -> Result<Value, AuthError> {
    let value = field_value(row, field)?;
    match id_type {
        DatabaseIdType::String | DatabaseIdType::Uuid => decode_text(field, value),
        DatabaseIdType::Serial => match value {
            Value::Null => Ok(Value::Null),
            Value::Number(number) if number.as_i64().is_some() => {
                Ok(Value::String(number.to_string()))
            }
            Value::String(value) if value.parse::<i64>().is_ok() => {
                Ok(Value::String(value.clone()))
            }
            _ => Err(invalid_result(field, "integer")),
        },
    }
}

pub(super) fn decode(
    row: &serde_json::Map<String, Value>,
    field: &str,
    field_type: AdditionalFieldType,
    bigint: bool,
    reference_id_type: Option<DatabaseIdType>,
) -> Result<Value, AuthError> {
    if let Some(id_type) = reference_id_type {
        return decode_id(row, field, id_type);
    }
    let value = field_value(row, field)?;
    match field_type {
        AdditionalFieldType::String | AdditionalFieldType::StringLiteral(_) => {
            decode_text(field, value)
        }
        AdditionalFieldType::Boolean => match value {
            Value::Null => Ok(Value::Null),
            Value::Bool(value) => Ok(Value::Bool(*value)),
            Value::Number(value) => Ok(Value::Bool(value.as_i64() == Some(1))),
            _ => Err(invalid_result(field, "boolean integer")),
        },
        AdditionalFieldType::Number if bigint => decode_integer(field, value),
        AdditionalFieldType::Number => decode_number(field, value),
        AdditionalFieldType::Date => match decode_text(field, value)? {
            Value::Null => Ok(Value::Null),
            Value::String(value) => parse_date(field, &value).map(|date| {
                Value::String(date.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
            }),
            _ => unreachable!(),
        },
        AdditionalFieldType::Json
        | AdditionalFieldType::StringArray
        | AdditionalFieldType::NumberArray => match decode_text(field, value)? {
            Value::Null => Ok(Value::Null),
            Value::String(value) => {
                serde_json::from_str(&value).map_err(|error| AuthError::Storage(error.to_string()))
            }
            _ => unreachable!(),
        },
    }
}

fn field_value<'a>(
    row: &'a serde_json::Map<String, Value>,
    field: &str,
) -> Result<&'a Value, AuthError> {
    row.get(field)
        .ok_or_else(|| AuthError::Storage(format!("D1 result omitted field '{field}'")))
}

fn encode_text(field: &str, value: Value) -> Result<D1Value, AuthError> {
    match value {
        Value::Null => Ok(D1Value::Null),
        Value::String(value) => Ok(D1Value::Text(value)),
        _ => Err(invalid_type(field, "string")),
    }
}

fn encode_integer(field: &str, value: Value) -> Result<D1Value, AuthError> {
    match value {
        Value::Null => Ok(D1Value::Null),
        Value::Number(value) if value.as_i64().is_some() => {
            Ok(D1Value::Integer(value.as_i64().expect("checked integer")))
        }
        Value::String(value) if value.parse::<i64>().is_ok() => Ok(D1Value::Integer(
            value.parse().expect("checked integer text"),
        )),
        _ => Err(invalid_type(field, "integer")),
    }
}

fn encode_number(field: &str, value: Value) -> Result<D1Value, AuthError> {
    match value {
        Value::Null => Ok(D1Value::Null),
        Value::Number(value) if value.as_i64().is_some() => {
            Ok(D1Value::Integer(value.as_i64().expect("checked integer")))
        }
        Value::Number(value) if value.as_f64().is_some() => {
            Ok(D1Value::Real(value.as_f64().expect("checked number")))
        }
        _ => Err(invalid_type(field, "number")),
    }
}

fn decode_text(field: &str, value: &Value) -> Result<Value, AuthError> {
    match value {
        Value::Null | Value::String(_) => Ok(value.clone()),
        _ => Err(invalid_result(field, "text")),
    }
}

fn decode_integer(field: &str, value: &Value) -> Result<Value, AuthError> {
    match value {
        Value::Null => Ok(Value::Null),
        Value::Number(number) if number.as_i64().is_some() => Ok(value.clone()),
        _ => Err(invalid_result(field, "integer")),
    }
}

fn decode_number(field: &str, value: &Value) -> Result<Value, AuthError> {
    match value {
        Value::Null => Ok(Value::Null),
        Value::Number(number) if number.as_f64().is_some() => Ok(value.clone()),
        _ => Err(invalid_result(field, "number")),
    }
}

fn parse_date(field: &str, value: &str) -> Result<chrono::DateTime<chrono::Utc>, AuthError> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&chrono::Utc))
        .map_err(|_| invalid_type(field, "ISO date string"))
}

fn invalid_type(field: &str, expected: &str) -> AuthError {
    AuthError::InvalidConfiguration(format!("D1 field '{field}' requires a {expected} value"))
}

fn invalid_result(field: &str, expected: &str) -> AuthError {
    AuthError::Storage(format!("D1 field '{field}' did not return {expected}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_match_better_auth_sqlite_encoding() {
        assert_eq!(
            encode(
                "flag",
                AdditionalFieldType::Boolean,
                false,
                None,
                Value::Bool(true)
            )
            .unwrap(),
            D1Value::Integer(1)
        );
        assert_eq!(
            encode(
                "when",
                AdditionalFieldType::Date,
                false,
                None,
                Value::String("2026-08-27T12:34:56.123456Z".into()),
            )
            .unwrap(),
            D1Value::Text("2026-08-27T12:34:56.123Z".into())
        );
    }
}
