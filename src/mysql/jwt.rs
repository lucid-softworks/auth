use super::{MySqlFindOptions, MySqlSort, MySqlSortDirection, MySqlStore};
use crate::{AuthError, JwkStore, JwtSchema, NewJwk, PreparedDatabaseId, StoredJwk};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

#[async_trait]
impl JwkStore for MySqlStore {
    async fn list_jwks(&self, _schema: &JwtSchema) -> Result<Vec<StoredJwk>, AuthError> {
        self.find_records(
            "jwks",
            &[],
            &MySqlFindOptions {
                sort: Some(MySqlSort {
                    field: "createdAt".into(),
                    direction: MySqlSortDirection::Ascending,
                }),
                ..MySqlFindOptions::default()
            },
        )
        .await?
        .into_iter()
        .map(decode)
        .collect()
    }

    async fn create_jwk(
        &self,
        _schema: &JwtSchema,
        jwk: NewJwk,
        id: PreparedDatabaseId,
    ) -> Result<StoredJwk, AuthError> {
        let mut record = Map::from_iter([
            ("publicKey".into(), json!(jwk.public_key)),
            ("privateKey".into(), json!(jwk.private_key)),
            ("createdAt".into(), json!(jwk.created_at)),
            ("expiresAt".into(), json!(jwk.expires_at)),
            ("alg".into(), json!(jwk.alg)),
            ("crv".into(), json!(jwk.crv)),
        ]);
        if let PreparedDatabaseId::Value(value) = id {
            record.insert("id".into(), value.to_json()?);
        }
        decode(self.insert_required_record("jwks", record).await?)
    }
}

fn decode(mut values: Map<String, Value>) -> Result<StoredJwk, AuthError> {
    Ok(StoredJwk {
        id: string(&mut values, "id")?,
        public_key: string(&mut values, "publicKey")?,
        private_key: string(&mut values, "privateKey")?,
        created_at: date(&mut values, "createdAt")?,
        expires_at: optional_date(&mut values, "expiresAt")?,
        alg: optional_string(&mut values, "alg")?,
        crv: optional_string(&mut values, "crv")?,
    })
}

fn string(values: &mut Map<String, Value>, field: &str) -> Result<String, AuthError> {
    match values.remove(field) {
        Some(Value::String(value)) => Ok(value),
        _ => Err(invalid(field)),
    }
}

fn optional_string(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<String>, AuthError> {
    match values.remove(field) {
        Some(Value::String(value)) => Ok(Some(value)),
        Some(Value::Null) => Ok(None),
        _ => Err(invalid(field)),
    }
}

fn date(values: &mut Map<String, Value>, field: &str) -> Result<DateTime<Utc>, AuthError> {
    let value = string(values, field)?;
    DateTime::parse_from_rfc3339(&value)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| invalid(field))
}

fn optional_date(
    values: &mut Map<String, Value>,
    field: &str,
) -> Result<Option<DateTime<Utc>>, AuthError> {
    match values.remove(field) {
        Some(Value::String(value)) => DateTime::parse_from_rfc3339(&value)
            .map(|value| Some(value.with_timezone(&Utc)))
            .map_err(|_| invalid(field)),
        Some(Value::Null) => Ok(None),
        _ => Err(invalid(field)),
    }
}

fn invalid(field: &str) -> AuthError {
    AuthError::Storage(format!("invalid MySQL jwks row: {field}"))
}
