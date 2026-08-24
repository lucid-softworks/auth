use super::{PostgresStore, storage_error};
use crate::{AuthError, JwkStore, JwtSchema, NewJwk, StoredJwk};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use sqlx::FromRow;

#[derive(FromRow)]
struct JwkRow {
    id: String,
    public_key: String,
    private_key: String,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    alg: Option<String>,
    crv: Option<String>,
}

impl From<JwkRow> for StoredJwk {
    fn from(row: JwkRow) -> Self {
        Self {
            id: row.id,
            public_key: row.public_key,
            private_key: row.private_key,
            created_at: row.created_at,
            expires_at: row.expires_at,
            alg: row.alg,
            crv: row.crv,
        }
    }
}

#[async_trait]
impl JwkStore for PostgresStore {
    async fn list_jwks(&self, schema: &JwtSchema) -> Result<Vec<StoredJwk>, AuthError> {
        let query = JwkSql::new(schema).list_query();
        sqlx::query_as::<_, JwkRow>(&query)
            .fetch_all(&self.pool)
            .await
            .map(|rows| rows.into_iter().map(StoredJwk::from).collect())
            .map_err(storage_error)
    }

    async fn create_jwk(&self, schema: &JwtSchema, jwk: NewJwk) -> Result<StoredJwk, AuthError> {
        let query = JwkSql::new(schema).insert_query();
        sqlx::query_as::<_, JwkRow>(&query)
            .bind(uuid::Uuid::new_v4().to_string())
            .bind(jwk.public_key)
            .bind(jwk.private_key)
            .bind(jwk.created_at)
            .bind(jwk.expires_at)
            .bind(jwk.alg)
            .bind(jwk.crv)
            .fetch_one(&self.pool)
            .await
            .map(StoredJwk::from)
            .map_err(storage_error)
    }
}

struct JwkSql {
    table: String,
    public_key: String,
    private_key: String,
    created_at: String,
    expires_at: String,
    alg: String,
    crv: String,
}

impl JwkSql {
    fn new(schema: &JwtSchema) -> Self {
        Self {
            table: quote_identifier(schema.table()),
            public_key: quote_identifier(schema.public_key()),
            private_key: quote_identifier(schema.private_key()),
            created_at: quote_identifier(schema.created_at()),
            expires_at: quote_identifier(schema.expires_at()),
            alg: quote_identifier(schema.alg()),
            crv: quote_identifier(schema.crv()),
        }
    }

    fn columns(&self) -> String {
        format!(
            "id, {} AS public_key, {} AS private_key, {} AS created_at, \
             {} AS expires_at, {} AS alg, {} AS crv",
            self.public_key, self.private_key, self.created_at, self.expires_at, self.alg, self.crv
        )
    }

    fn list_query(&self) -> String {
        format!(
            "SELECT {} FROM {} ORDER BY {} ASC, id ASC",
            self.columns(),
            self.table,
            self.created_at
        )
    }

    fn insert_query(&self) -> String {
        format!(
            "INSERT INTO {} (id, {}, {}, {}, {}, {}, {}) \
             VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {}",
            self.table,
            self.public_key,
            self.private_key,
            self.created_at,
            self.expires_at,
            self.alg,
            self.crv,
            self.columns()
        )
    }
}

fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queries_quote_custom_schema_identifiers() {
        let schema = JwtSchema {
            model_name: Some("tenant\"jwks".into()),
            public_key_field_name: Some("public material".into()),
            private_key_field_name: Some("private\"material".into()),
            created_at_field_name: Some("created time".into()),
            expires_at_field_name: Some("expires time".into()),
            alg_field_name: Some("algorithm".into()),
            crv_field_name: Some("curve".into()),
        };
        let sql = JwkSql::new(&schema);

        assert!(sql.list_query().contains("FROM \"tenant\"\"jwks\""));
        assert!(
            sql.list_query()
                .contains("\"private\"\"material\" AS private_key")
        );
        assert!(
            sql.insert_query()
                .contains("(id, \"public material\", \"private\"\"material\"")
        );
    }

    #[test]
    fn insert_uses_placeholders_for_all_jwk_values() {
        let query = JwkSql::new(&JwtSchema::default()).insert_query();

        assert!(query.contains("VALUES ($1, $2, $3, $4, $5, $6, $7)"));
        assert!(!query.contains("[REDACTED]"));
    }
}
