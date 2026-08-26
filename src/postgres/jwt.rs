use super::{PostgresModel, PostgresStore, storage_error};
use crate::{AuthError, JwkStore, JwtSchema, NewJwk, StoredJwk};
use async_trait::async_trait;
use serde_json::{Map, Value, json};
use sqlx::{Postgres, QueryBuilder, postgres::PgRow};

#[async_trait]
impl JwkStore for PostgresStore {
    async fn list_jwks(&self, _schema: &JwtSchema) -> Result<Vec<StoredJwk>, AuthError> {
        let model = self.physical_model("jwks")?;
        let mut query = list_query(&model)?;
        query
            .build()
            .fetch_all(&self.pool)
            .await
            .map_err(storage_error)?
            .iter()
            .map(|row| decode_jwk(&model, row))
            .collect()
    }

    async fn create_jwk(&self, _schema: &JwtSchema, jwk: NewJwk) -> Result<StoredJwk, AuthError> {
        let model = self.physical_model("jwks")?;
        let values = [
            ("id", json!(uuid::Uuid::new_v4().to_string())),
            ("publicKey", json!(jwk.public_key)),
            ("privateKey", json!(jwk.private_key)),
            ("createdAt", json!(jwk.created_at.to_rfc3339())),
            ("expiresAt", optional_date(jwk.expires_at)),
            ("alg", optional_string(jwk.alg)),
            ("crv", optional_string(jwk.crv)),
        ];
        let writes = model.encode_fields(values)?;
        let mut query = insert_query(&model, writes)?;
        let row = query
            .build()
            .fetch_one(&self.pool)
            .await
            .map_err(storage_error)?;
        decode_jwk(&model, &row)
    }
}

fn list_query(model: &PostgresModel<'_>) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(model.all_projection())
        .push(" FROM ")
        .push(model.quoted_table())
        .push(" ORDER BY ")
        .push(model.quoted_column("createdAt")?)
        .push(" ASC, \"id\" ASC");
    Ok(query)
}

fn insert_query(
    model: &PostgresModel<'_>,
    writes: Vec<super::PostgresWrite<'_>>,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = QueryBuilder::new("INSERT INTO ");
    query.push(model.quoted_table()).push(" (");
    for (index, write) in writes.iter().enumerate() {
        if index > 0 {
            query.push(", ");
        }
        query.push(write.quoted_column());
    }
    query.push(") VALUES (");
    for (index, write) in writes.into_iter().enumerate() {
        if index > 0 {
            query.push(", ");
        }
        write.push_bind(&mut query);
    }
    query.push(") RETURNING ").push(model.all_projection());
    Ok(query)
}

fn decode_jwk(model: &PostgresModel<'_>, row: &PgRow) -> Result<StoredJwk, AuthError> {
    let mut values = model.decode_all(row)?;
    Ok(StoredJwk {
        id: required_string(&mut values, "id")?,
        public_key: required_string(&mut values, "publicKey")?,
        private_key: required_string(&mut values, "privateKey")?,
        created_at: required_date(&mut values, "createdAt")?,
        expires_at: take_optional_date(&mut values, "expiresAt")?,
        alg: take_optional_string(&mut values, "alg")?,
        crv: take_optional_string(&mut values, "crv")?,
    })
}

fn optional_string(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::String)
}

fn optional_date(value: Option<chrono::DateTime<chrono::Utc>>) -> Value {
    value.map_or(Value::Null, |value| Value::String(value.to_rfc3339()))
}

fn required_string(values: &mut Map<String, Value>, field: &str) -> Result<String, AuthError> {
    take(values, field)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid_row(field))
}

fn take_optional_string(
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
    let value = required_string(values, field)?;
    chrono::DateTime::parse_from_rfc3339(&value)
        .map(|value| value.with_timezone(&chrono::Utc))
        .map_err(|_| invalid_row(field))
}

fn take_optional_date(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<chrono::DateTime<chrono::Utc>>, AuthError> {
    match take(values, field)? {
        Value::Null => Ok(None),
        Value::String(value) => chrono::DateTime::parse_from_rfc3339(&value)
            .map(|value| Some(value.with_timezone(&chrono::Utc)))
            .map_err(|_| invalid_row(field)),
        _ => Err(invalid_row(field)),
    }
}

fn take(values: &mut Map<String, Value>, field: &str) -> Result<Value, AuthError> {
    values.remove(field).ok_or_else(|| invalid_row(field))
}

fn invalid_row(field: &str) -> AuthError {
    AuthError::Storage(format!(
        "PostgreSQL JWT row has an invalid canonical '{field}' field"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AdapterSchemaOptions, AdditionalField, AdditionalFieldType, AuthConfig, AuthSchemaCatalog,
        PluginSchemaTable, ResolvedAdapterSchema,
    };
    use std::sync::Arc;

    #[test]
    fn queries_use_catalog_remaps_and_bound_values() {
        let mut table = PluginSchemaTable::new("jwks").model_name("tenant\"jwks");
        for (logical, physical, field_type, required) in [
            (
                "publicKey",
                "public material",
                AdditionalFieldType::String,
                true,
            ),
            (
                "privateKey",
                "private\"material",
                AdditionalFieldType::String,
                true,
            ),
            ("createdAt", "created time", AdditionalFieldType::Date, true),
            (
                "expiresAt",
                "expires time",
                AdditionalFieldType::Date,
                false,
            ),
            ("alg", "algorithm", AdditionalFieldType::String, false),
            ("crv", "curve", AdditionalFieldType::String, false),
        ] {
            let field = AdditionalField::new(field_type).field_name(physical);
            table = table.field(logical, if required { field } else { field.optional() });
        }
        let config = AuthConfig::new([17; 32]).unwrap();
        let catalog = Arc::new(AuthSchemaCatalog::build(&config, [table]).unwrap());
        let resolved =
            ResolvedAdapterSchema::new(catalog, AdapterSchemaOptions::default()).unwrap();
        let physical =
            super::super::physical_schema::PostgresPhysicalSchema::new(&resolved).unwrap();
        let model = physical.model("jwks").unwrap();

        let list = list_query(&model).unwrap();
        assert!(list.sql().contains("FROM \"tenant\"\"jwks\""));
        assert!(
            list.sql()
                .contains("\"private\"\"material\" AS \"privateKey\"")
        );

        let writes = model
            .encode_fields([
                ("id", json!(uuid::Uuid::nil().to_string())),
                ("publicKey", json!("public")),
                ("privateKey", json!("[REDACTED]")),
                ("createdAt", json!(chrono::Utc::now().to_rfc3339())),
                ("expiresAt", Value::Null),
                ("alg", Value::Null),
                ("crv", Value::Null),
            ])
            .unwrap();
        let insert = insert_query(&model, writes).unwrap();
        assert!(insert.sql().contains("INSERT INTO \"tenant\"\"jwks\""));
        assert!(insert.sql().contains("\"public material\""));
        assert_eq!(insert.sql().matches('$').count(), 7);
        assert!(!insert.sql().contains("[REDACTED]"));
    }
}
