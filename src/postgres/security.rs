use super::{PostgresModel, PostgresStore, storage_error};
use crate::{
    AuthError, RateLimitOutcome, RateLimitRule, SecurityStore,
    rate_limit::{duration, retry_after},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::json;
use sqlx::{Postgres, QueryBuilder, Row};

#[async_trait]
impl SecurityStore for PostgresStore {
    async fn consume_rate_limit(
        &self,
        id: &dyn crate::store::DatabaseIdSupplier,
        key: &str,
        now: DateTime<Utc>,
        rule: RateLimitRule,
        longest_window: u64,
    ) -> Result<RateLimitOutcome, AuthError> {
        let window = duration(rule.window)?;
        let now_milliseconds = now.timestamp_millis();
        let prune_milliseconds = i64::try_from(longest_window)
            .ok()
            .and_then(|seconds| seconds.checked_mul(1_000))
            .ok_or_else(|| {
                AuthError::InvalidConfiguration("rate-limit window is too large".into())
            })?;
        let mut transaction = self.pool.begin().await.map_err(storage_error)?;
        sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
            .bind(key)
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        let model = self.physical_model("rateLimit")?;
        prune_query(&model, now_milliseconds.saturating_sub(prune_milliseconds))?
            .build()
            .execute(&mut *transaction)
            .await
            .map_err(storage_error)?;
        let current = select_query(&model, key)?
            .build()
            .fetch_optional(&mut *transaction)
            .await
            .map_err(storage_error)?
            .map(|row| {
                Ok::<_, AuthError>((
                    i64::from(row.try_get::<i32, _>("count").map_err(storage_error)?),
                    row.try_get::<i64, _>("lastRequest")
                        .map_err(storage_error)?,
                ))
            })
            .transpose()?;
        let outcome = match current {
            None => {
                insert_query(&model, id.prepare()?, key, now_milliseconds)?
                    .build()
                    .execute(&mut *transaction)
                    .await
                    .map_err(storage_error)?;
                RateLimitOutcome::allowed()
            }
            Some((count, last_request)) => {
                let last =
                    DateTime::<Utc>::from_timestamp_millis(last_request).ok_or_else(|| {
                        AuthError::Storage("rate-limit last request is invalid".into())
                    })?;
                if now - last >= window {
                    update(&mut transaction, &model, key, 1, now_milliseconds).await?;
                    RateLimitOutcome::allowed()
                } else if u64::try_from(count).unwrap_or(u64::MAX) >= u64::from(rule.max) {
                    RateLimitOutcome::denied(retry_after(last, window, now))
                } else {
                    update(
                        &mut transaction,
                        &model,
                        key,
                        count.saturating_add(1),
                        now_milliseconds,
                    )
                    .await?;
                    RateLimitOutcome::allowed()
                }
            }
        };
        transaction.commit().await.map_err(storage_error)?;
        Ok(outcome)
    }
}

async fn update(
    transaction: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    model: &PostgresModel<'_>,
    key: &str,
    count: i64,
    last_request: i64,
) -> Result<(), AuthError> {
    update_query(model, key, count, last_request)?
        .build()
        .execute(&mut **transaction)
        .await
        .map(|_| ())
        .map_err(storage_error)
}

fn prune_query(
    model: &PostgresModel<'_>,
    before: i64,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = QueryBuilder::new("DELETE FROM ");
    query
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("lastRequest")?)
        .push(" < ");
    model
        .encode("lastRequest", json!(before))?
        .push_bind(&mut query);
    Ok(query)
}

fn select_query(
    model: &PostgresModel<'_>,
    key: &str,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut query = QueryBuilder::new("SELECT ");
    query
        .push(model.projection(["count", "lastRequest"])?)
        .push(" FROM ")
        .push(model.quoted_table())
        .push(" WHERE ")
        .push(model.quoted_column("key")?)
        .push(" = ");
    model.encode("key", json!(key))?.push_bind(&mut query);
    query.push(" FOR UPDATE");
    Ok(query)
}

fn insert_query(
    model: &PostgresModel<'_>,
    id: crate::store::PreparedDatabaseId,
    key: &str,
    last_request: i64,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let mut values = serde_json::Map::from_iter([
        ("key".into(), json!(key)),
        ("count".into(), json!(1)),
        ("lastRequest".into(), json!(last_request)),
    ]);
    super::rows::insert_prepared_id(&mut values, &id)?;
    let writes = model.encode_fields(
        values
            .iter()
            .map(|(logical, value)| (logical.as_str(), value.clone())),
    )?;
    Ok(super::rows::insert_query_prefix(model, writes))
}

fn update_query(
    model: &PostgresModel<'_>,
    key: &str,
    count: i64,
    last_request: i64,
) -> Result<QueryBuilder<'static, Postgres>, AuthError> {
    let writes = model.encode_fields([
        ("count", json!(count)),
        ("lastRequest", json!(last_request)),
    ])?;
    let mut query = super::rows::update_query(model, writes);
    query
        .push(" WHERE ")
        .push(model.quoted_column("key")?)
        .push(" = ");
    model.encode("key", json!(key))?.push_bind(&mut query);
    Ok(query)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AuthConfig, AuthSchemaCatalog, RateLimitStorageMode,
        postgres::{PostgresAdapterConfig, PostgresStore},
    };
    use sqlx::postgres::PgPoolOptions;
    use std::sync::Arc;

    fn remapped_store() -> PostgresStore {
        let pool = PgPoolOptions::new()
            .connect_lazy("postgres://localhost/schema_test")
            .unwrap();
        let store = PostgresStore::new(pool, PostgresAdapterConfig { use_plural: true });
        let mut config = AuthConfig::new([31; 32]).unwrap();
        config.rate_limit.storage = RateLimitStorageMode::Database;
        config.rate_limit.model_name = Some("request bucket".into());
        config.rate_limit.fields.key = Some("select".into());
        config.rate_limit.fields.count = Some("hit\"count".into());
        config.rate_limit.fields.last_request = Some("last seen".into());
        store
            .bind_catalog(Arc::new(AuthSchemaCatalog::build(&config, []).unwrap()))
            .unwrap();
        store
    }

    #[tokio::test]
    async fn all_rate_limit_queries_use_bound_plural_table_and_fields() {
        let store = remapped_store();
        let model = store.physical_model("rateLimit").unwrap();
        let sql = [
            prune_query(&model, 1).unwrap().sql().to_owned(),
            select_query(&model, "key").unwrap().sql().to_owned(),
            insert_query(
                &model,
                crate::store::PreparedDatabaseId::Value(crate::store::DatabaseIdValue::String(
                    "rate-id".into(),
                )),
                "key",
                2,
            )
            .unwrap()
            .sql()
            .to_owned(),
            update_query(&model, "key", 2, 3).unwrap().sql().to_owned(),
        ]
        .join("\n");

        assert!(sql.contains("\"request buckets\""));
        assert!(sql.contains("\"select\""));
        assert!(sql.contains("\"hit\"\"count\""));
        assert!(sql.contains("\"last seen\""));
        assert!(!sql.contains("lucid_auth_"));
        assert!(!sql.contains("last_request"));
    }
}
