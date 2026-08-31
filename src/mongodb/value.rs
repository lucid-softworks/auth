use super::{error::MongoAdapterError, schema::MongoIdEncoding};
use crate::{AdditionalFieldType, AuthError};
use chrono::{DateTime, SecondsFormat, Utc};
use mongodb::bson::{Binary, Bson, DateTime as BsonDateTime, spec::BinarySubtype};
use serde_json::{Number, Value};

pub(super) fn encode_id(
    encoding: MongoIdEncoding,
    value: Value,
) -> Result<Bson, MongoAdapterError> {
    match value {
        Value::Null => Ok(Bson::Null),
        Value::String(value) => match encoding {
            MongoIdEncoding::Custom => Ok(Bson::String(value)),
            MongoIdEncoding::ObjectId => Ok(mongodb::bson::oid::ObjectId::parse_str(&value)
                .map(Bson::ObjectId)
                .unwrap_or(Bson::String(value))),
            MongoIdEncoding::Uuid => uuid::Uuid::parse_str(&value)
                .map(|uuid| {
                    Bson::Binary(Binary {
                        subtype: BinarySubtype::Uuid,
                        bytes: uuid.as_bytes().to_vec(),
                    })
                })
                .or_else(|_| Ok(Bson::String(value))),
        },
        Value::Array(values) => values
            .into_iter()
            .map(|value| encode_id(encoding, value))
            .collect::<Result<Vec<_>, _>>()
            .map(Bson::Array),
        Value::Bool(_) | Value::Number(_) | Value::Object(_) => {
            Err(MongoAdapterError::invalid_id())
        }
    }
}

pub(super) fn encode(
    field: &str,
    field_type: AdditionalFieldType,
    bigint: bool,
    value: Value,
) -> Result<Bson, AuthError> {
    if value.is_null() {
        return Ok(Bson::Null);
    }
    match field_type {
        AdditionalFieldType::String | AdditionalFieldType::StringLiteral(_) => value
            .as_str()
            .map(|value| Bson::String(value.into()))
            .ok_or_else(|| invalid_type(field, "string")),
        AdditionalFieldType::Boolean => value
            .as_bool()
            .map(Bson::Boolean)
            .ok_or_else(|| invalid_type(field, "boolean")),
        AdditionalFieldType::Number if bigint => value
            .as_i64()
            .map(Bson::Int64)
            .ok_or_else(|| invalid_type(field, "integer")),
        AdditionalFieldType::Number => {
            if let Some(value) = value.as_i64() {
                Ok(Bson::Int64(value))
            } else {
                value
                    .as_f64()
                    .map(Bson::Double)
                    .ok_or_else(|| invalid_type(field, "finite number"))
            }
        }
        AdditionalFieldType::Date => value
            .as_str()
            .ok_or_else(|| invalid_type(field, "ISO date string"))
            .and_then(|value| {
                DateTime::parse_from_rfc3339(value)
                    .map(|date| Bson::DateTime(BsonDateTime::from_millis(date.timestamp_millis())))
                    .map_err(|_| invalid_type(field, "ISO date string"))
            }),
        AdditionalFieldType::Json
        | AdditionalFieldType::StringArray
        | AdditionalFieldType::NumberArray => mongodb::bson::to_bson(&value)
            .map_err(|error| AuthError::Storage(error.to_string())),
    }
}

pub(super) fn decode_id(value: Bson) -> Result<Value, AuthError> {
    match value {
        Bson::ObjectId(value) => Ok(Value::String(value.to_hex())),
        Bson::Binary(value)
            if matches!(value.subtype, BinarySubtype::Uuid | BinarySubtype::UuidOld)
                && value.bytes.len() == 16 =>
        {
            uuid::Uuid::from_slice(&value.bytes)
                .map(|value| Value::String(value.to_string()))
                .map_err(|error| AuthError::Storage(error.to_string()))
        }
        Bson::Array(values) => values
            .into_iter()
            .map(decode_id)
            .collect::<Result<Vec<_>, _>>()
            .map(Value::Array),
        value => decode(value),
    }
}

pub(super) fn decode(value: Bson) -> Result<Value, AuthError> {
    match value {
        Bson::Null => Ok(Value::Null),
        Bson::String(value) => Ok(Value::String(value)),
        Bson::Boolean(value) => Ok(Value::Bool(value)),
        Bson::Int32(value) => Ok(Value::Number(value.into())),
        Bson::Int64(value) => Ok(Value::Number(value.into())),
        Bson::Double(value) => Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| AuthError::Storage("MongoDB returned a non-finite number".into())),
        Bson::DateTime(value) => DateTime::<Utc>::from_timestamp_millis(value.timestamp_millis())
            .map(|value| Value::String(value.to_rfc3339_opts(SecondsFormat::Millis, true)))
            .ok_or_else(|| AuthError::Storage("MongoDB returned an invalid date".into())),
        Bson::ObjectId(value) => Ok(Value::String(value.to_hex())),
        Bson::Binary(value)
            if matches!(value.subtype, BinarySubtype::Uuid | BinarySubtype::UuidOld)
                && value.bytes.len() == 16 =>
        {
            uuid::Uuid::from_slice(&value.bytes)
                .map(|value| Value::String(value.to_string()))
                .map_err(|error| AuthError::Storage(error.to_string()))
        }
        other => mongodb::bson::from_bson(other)
            .map_err(|error| AuthError::Storage(error.to_string())),
    }
}

fn invalid_type(field: &str, expected: &str) -> AuthError {
    AuthError::InvalidConfiguration(format!(
        "MongoDB field '{field}' requires a {expected} value"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn object_ids_and_uuids_round_trip_as_strings() {
        let object = mongodb::bson::oid::ObjectId::new();
        let encoded = encode_id(MongoIdEncoding::ObjectId, json!(object.to_hex())).unwrap();
        assert_eq!(decode_id(encoded).unwrap(), json!(object.to_hex()));
        let uuid = uuid::Uuid::new_v4();
        let encoded = encode_id(MongoIdEncoding::Uuid, json!(uuid.to_string())).unwrap();
        assert_eq!(decode_id(encoded).unwrap(), json!(uuid.to_string()));
    }

    #[test]
    fn custom_ids_remain_strings_and_invalid_scalars_are_rejected() {
        assert_eq!(
            encode_id(MongoIdEncoding::Custom, json!("01-custom")).unwrap(),
            Bson::String("01-custom".into())
        );
        assert_eq!(
            encode_id(MongoIdEncoding::ObjectId, json!(7)).unwrap_err().code,
            super::super::MongoAdapterErrorCode::InvalidId
        );
    }
}
