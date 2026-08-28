use super::{LogicalColumn, LogicalModel, PhysicalModel};
use crate::{AdditionalFieldType, AuthError, DatabaseIdType};
use indexmap::IndexMap;
use serde_json::{Map, Value};
use sqlx::{Postgres, QueryBuilder, Row, postgres::PgRow, types::Json};

pub(crate) struct PostgresModel<'a> {
    logical_name: &'a str,
    logical: &'a LogicalModel,
    physical: &'a PhysicalModel,
}

impl<'a> PostgresModel<'a> {
    pub(super) fn new(
        logical_name: &'a str,
        logical: &'a LogicalModel,
        physical: &'a PhysicalModel,
    ) -> Self {
        Self {
            logical_name,
            logical,
            physical,
        }
    }

    #[cfg(test)]
    pub(crate) fn table(&self) -> &str {
        &self.physical.table
    }

    pub(crate) fn quoted_table(&self) -> &str {
        &self.physical.quoted_table
    }

    pub(crate) const fn logical_name(&self) -> &str {
        self.logical_name
    }

    pub(crate) fn has_field(&self, logical: &str) -> bool {
        logical == "id" || self.logical.columns.contains_key(logical)
    }

    pub(crate) fn column(&self, logical: &str) -> Result<&str, AuthError> {
        if logical == "id" {
            return Ok("id");
        }
        self.logical
            .columns
            .get(logical)
            .map(|column| column.physical.as_str())
            .ok_or_else(|| self.unknown_field(logical))
    }

    pub(crate) fn quoted_column(&self, logical: &str) -> Result<&str, AuthError> {
        if logical == "id" {
            return Ok("\"id\"");
        }
        self.logical
            .columns
            .get(logical)
            .map(|column| column.quoted.as_str())
            .ok_or_else(|| self.unknown_field(logical))
    }

    pub(crate) fn projection<'b>(
        &self,
        fields: impl IntoIterator<Item = &'b str>,
    ) -> Result<String, AuthError> {
        fields
            .into_iter()
            .map(|logical| {
                Ok(format!(
                    "{} AS {}",
                    self.quoted_column(logical)?,
                    quote(logical)
                ))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|columns| columns.join(", "))
    }

    pub(crate) fn projection_as(&self, fields: &[(&str, &str)]) -> Result<String, AuthError> {
        fields
            .iter()
            .map(|(logical, alias)| {
                Ok(format!(
                    "{} AS {}",
                    self.quoted_column(logical)?,
                    quote(alias)
                ))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(|columns| columns.join(", "))
    }

    pub(crate) fn all_projection(&self) -> String {
        std::iter::once("\"id\" AS \"id\"".to_owned())
            .chain(
                self.logical
                    .columns
                    .iter()
                    .map(|(logical, column)| format!("{} AS {}", column.quoted, quote(logical))),
            )
            .collect::<Vec<_>>()
            .join(", ")
    }

    #[cfg(test)]
    pub(crate) fn logical_fields(&self) -> impl Iterator<Item = &str> {
        self.logical.columns.keys().map(String::as_str)
    }

    pub(crate) fn encode(&self, logical: &str, value: Value) -> Result<PostgresValue, AuthError> {
        if logical == "id" {
            return encode_id(self.logical.id_type, "id", value);
        }
        encode_column(
            self.logical
                .columns
                .get(logical)
                .ok_or_else(|| self.unknown_field(logical))?,
            value,
        )
    }

    pub(crate) fn encode_fields<'b>(
        &self,
        values: impl IntoIterator<Item = (&'b str, Value)>,
    ) -> Result<Vec<PostgresWrite<'_>>, AuthError> {
        let supplied = values
            .into_iter()
            .map(|(logical, value)| (logical.to_owned(), value))
            .collect::<std::collections::HashMap<_, _>>();
        let mut writes = IndexMap::<String, PostgresWrite<'_>>::new();
        if let Some(value) = supplied.get("id") {
            writes.insert(
                "id".into(),
                PostgresWrite {
                    logical: "id".into(),
                    #[cfg(test)]
                    column: "id",
                    quoted_column: "\"id\"",
                    value: encode_id(self.logical.id_type, "id", value.clone())?,
                },
            );
        }
        for logical in self.logical.columns.keys().map(String::as_str) {
            let Some(value) = supplied.get(logical) else {
                continue;
            };
            let column = self.column(logical)?.to_owned();
            let quoted = self.quoted_column(logical)?;
            let write = PostgresWrite {
                logical: logical.to_owned(),
                #[cfg(test)]
                column: self.column(logical)?,
                quoted_column: quoted,
                value: self.encode(logical, value.clone())?,
            };
            writes.insert(column, write);
        }
        Ok(writes.into_values().collect())
    }

    pub(crate) fn decode_all(&self, row: &PgRow) -> Result<Map<String, Value>, AuthError> {
        let mut values = Map::new();
        values.insert("id".into(), decode_id(row, self.logical.id_type, "id")?);
        for (logical, column) in &self.logical.columns {
            values.insert(logical.clone(), decode_column(row, logical, column)?);
        }
        Ok(values)
    }

    pub(crate) fn decode_id(&self, row: &PgRow, field: &str) -> Result<Option<String>, AuthError> {
        let value = decode_id(row, self.logical.id_type, field)?;
        Ok(value.as_str().map(str::to_owned))
    }

    fn unknown_field(&self, logical: &str) -> AuthError {
        AuthError::InvalidConfiguration(format!(
            "PostgreSQL schema model '{}' has no logical field '{logical}'",
            self.logical_name
        ))
    }
}

pub(crate) enum PostgresValue {
    Uuid(Option<uuid::Uuid>),
    Text(Option<String>),
    Integer(Option<i32>),
    Bigint(Option<i64>),
    Boolean(Option<bool>),
    Date(Option<chrono::DateTime<chrono::Utc>>),
    Json(Option<Json<Value>>),
}

pub(crate) struct PostgresWrite<'a> {
    logical: String,
    #[cfg(test)]
    column: &'a str,
    quoted_column: &'a str,
    value: PostgresValue,
}

impl<'a> PostgresWrite<'a> {
    pub(crate) fn logical(&self) -> &str {
        &self.logical
    }

    #[cfg(test)]
    pub(crate) fn column(&self) -> &str {
        self.column
    }

    pub(crate) fn quoted_column(&self) -> &str {
        self.quoted_column
    }

    #[cfg(test)]
    pub(crate) fn value(&self) -> &PostgresValue {
        &self.value
    }

    pub(crate) fn push_bind<'args>(self, query: &mut QueryBuilder<'args, Postgres>) {
        self.value.push_bind(query);
    }
}

impl PostgresValue {
    pub(crate) fn push_bind<'args>(self, query: &mut QueryBuilder<'args, Postgres>) {
        match self {
            Self::Uuid(value) => query.push_bind(value),
            Self::Text(value) => query.push_bind(value),
            Self::Integer(value) => query.push_bind(value),
            Self::Bigint(value) => query.push_bind(value),
            Self::Boolean(value) => query.push_bind(value),
            Self::Date(value) => query.push_bind(value),
            Self::Json(value) => query.push_bind(value),
        };
    }
}

fn encode_id(
    id_type: DatabaseIdType,
    field: &str,
    value: Value,
) -> Result<PostgresValue, AuthError> {
    match id_type {
        DatabaseIdType::String => match value {
            Value::Null => Ok(PostgresValue::Text(None)),
            Value::String(value) => Ok(PostgresValue::Text(Some(value))),
            _ => Err(invalid_type(field, "string")),
        },
        DatabaseIdType::Serial => match value {
            Value::Null => Ok(PostgresValue::Integer(None)),
            Value::Number(value) => value
                .as_f64()
                .and_then(super::number::serial_i32)
                .map(|value| PostgresValue::Integer(Some(value)))
                .ok_or_else(|| invalid_type(field, "32-bit integer")),
            Value::String(value) => super::number::javascript_number(&value)
                .and_then(super::number::serial_i32)
                .map(|value| PostgresValue::Integer(Some(value)))
                .ok_or_else(|| invalid_type(field, "32-bit integer")),
            _ => Err(invalid_type(field, "32-bit integer")),
        },
        DatabaseIdType::Uuid => match value {
            Value::Null => Ok(PostgresValue::Uuid(None)),
            Value::String(value) => uuid::Uuid::parse_str(&value)
                .map(|value| PostgresValue::Uuid(Some(value)))
                .map_err(|error| invalid_value(field, error)),
            _ => Err(invalid_type(field, "UUID string")),
        },
    }
}

fn encode_column(column: &LogicalColumn, value: Value) -> Result<PostgresValue, AuthError> {
    if let Some(id_type) = column.reference_id_type {
        return encode_id(id_type, &column.physical, value);
    }
    if value.is_null() {
        return Ok(match column.field_type {
            AdditionalFieldType::String | AdditionalFieldType::StringLiteral(_) => {
                PostgresValue::Text(None)
            }
            AdditionalFieldType::Number if column.bigint => PostgresValue::Bigint(None),
            AdditionalFieldType::Number => PostgresValue::Integer(None),
            AdditionalFieldType::Boolean => PostgresValue::Boolean(None),
            AdditionalFieldType::Date => PostgresValue::Date(None),
            AdditionalFieldType::Json
            | AdditionalFieldType::StringArray
            | AdditionalFieldType::NumberArray => PostgresValue::Json(None),
        });
    }
    match column.field_type {
        AdditionalFieldType::String | AdditionalFieldType::StringLiteral(_) => value
            .as_str()
            .map(|value| PostgresValue::Text(Some(value.to_owned())))
            .ok_or_else(|| invalid_type(&column.physical, "string")),
        AdditionalFieldType::Number if column.bigint => value
            .as_i64()
            .map(|value| PostgresValue::Bigint(Some(value)))
            .ok_or_else(|| invalid_type(&column.physical, "integer")),
        AdditionalFieldType::Number => value
            .as_i64()
            .and_then(|value| i32::try_from(value).ok())
            .map(|value| PostgresValue::Integer(Some(value)))
            .ok_or_else(|| invalid_type(&column.physical, "32-bit integer")),
        AdditionalFieldType::Boolean => value
            .as_bool()
            .map(|value| PostgresValue::Boolean(Some(value)))
            .ok_or_else(|| invalid_type(&column.physical, "boolean")),
        AdditionalFieldType::Date => value
            .as_str()
            .ok_or_else(|| invalid_type(&column.physical, "RFC 3339 date string"))
            .and_then(|value| {
                chrono::DateTime::parse_from_rfc3339(value)
                    .map(|value| PostgresValue::Date(Some(value.with_timezone(&chrono::Utc))))
                    .map_err(|error| invalid_value(&column.physical, error))
            }),
        AdditionalFieldType::Json
        | AdditionalFieldType::StringArray
        | AdditionalFieldType::NumberArray => Ok(PostgresValue::Json(Some(Json(value)))),
    }
}

fn decode_id(row: &PgRow, id_type: DatabaseIdType, field: &str) -> Result<Value, AuthError> {
    match id_type {
        DatabaseIdType::String => row
            .try_get::<Option<String>, _>(field)
            .map(|value| value.map_or(Value::Null, Value::String)),
        DatabaseIdType::Serial => row
            .try_get::<Option<i32>, _>(field)
            .map(|value| value.map_or(Value::Null, |value| Value::String(value.to_string()))),
        DatabaseIdType::Uuid => row
            .try_get::<Option<uuid::Uuid>, _>(field)
            .map(|value| value.map_or(Value::Null, |value| Value::String(value.to_string()))),
    }
    .map_err(storage)
}

fn decode_column(row: &PgRow, logical: &str, column: &LogicalColumn) -> Result<Value, AuthError> {
    if let Some(id_type) = column.reference_id_type {
        return decode_id(row, id_type, logical);
    }
    match column.field_type {
        AdditionalFieldType::String | AdditionalFieldType::StringLiteral(_) => row
            .try_get::<Option<String>, _>(logical)
            .map(|value| value.map_or(Value::Null, Value::String)),
        AdditionalFieldType::Number if column.bigint => row
            .try_get::<Option<i64>, _>(logical)
            .map(|value| value.map_or(Value::Null, |value| Value::Number(value.into()))),
        AdditionalFieldType::Number => row
            .try_get::<Option<i32>, _>(logical)
            .map(|value| value.map_or(Value::Null, |value| Value::Number(value.into()))),
        AdditionalFieldType::Boolean => row
            .try_get::<Option<bool>, _>(logical)
            .map(|value| value.map_or(Value::Null, Value::Bool)),
        AdditionalFieldType::Date => row
            .try_get::<Option<chrono::DateTime<chrono::Utc>>, _>(logical)
            .map(|value| value.map_or(Value::Null, |value| Value::String(value.to_rfc3339()))),
        AdditionalFieldType::Json
        | AdditionalFieldType::StringArray
        | AdditionalFieldType::NumberArray => row
            .try_get::<Option<Json<Value>>, _>(logical)
            .map(|value| value.map_or(Value::Null, |value| value.0)),
    }
    .map_err(storage)
}

fn invalid_type(field: &str, expected: &str) -> AuthError {
    AuthError::Storage(format!(
        "PostgreSQL schema field '{field}' requires a {expected} value"
    ))
}

fn invalid_value(field: &str, error: impl std::fmt::Display) -> AuthError {
    AuthError::Storage(format!(
        "invalid PostgreSQL value for schema field '{field}': {error}"
    ))
}

fn storage(error: sqlx::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}

fn quote(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AdditionalField;

    #[test]
    fn projection_aliases_canonical_fields_for_typed_rows() {
        let mut columns = IndexMap::new();
        columns.insert(
            "clientId".into(),
            LogicalColumn {
                physical: "client \"key".into(),
                quoted: "\"client \"\"key\"".into(),
                field_type: AdditionalFieldType::String,
                bigint: false,
                reference_id_type: None,
            },
        );
        let logical = LogicalModel {
            physical: "OAuth Clients".into(),
            id_type: DatabaseIdType::Uuid,
            columns,
        };
        let physical = PhysicalModel {
            table: "OAuth Clients".into(),
            quoted_table: "\"OAuth Clients\"".into(),
            id_type: DatabaseIdType::Uuid,
            columns: IndexMap::from([(
                "client \"key".into(),
                super::super::PhysicalColumn {
                    field: AdditionalField::new(AdditionalFieldType::String),
                    aliases: vec![("oauthClient".into(), "clientId".into())],
                },
            )]),
            disable_migrations: false,
        };
        let model = PostgresModel::new("oauthClient", &logical, &physical);
        assert_eq!(
            model
                .projection_as(&[("id", "id"), ("clientId", "client_id")])
                .unwrap(),
            "\"id\" AS \"id\", \"client \"\"key\" AS \"client_id\""
        );
    }
}
