use super::{MySqlFilter, MySqlFilterOperator, MySqlStore, query::execute};
use crate::{
    AuthError, RateLimitOutcome, RateLimitRule, SecurityStore,
    rate_limit::{duration, retry_after},
    store::{DatabaseIdSupplier, PreparedDatabaseId},
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};

#[async_trait]
impl SecurityStore for MySqlStore {
    async fn consume_rate_limit(
        &self,
        id: &dyn DatabaseIdSupplier,
        key: &str,
        now: DateTime<Utc>,
        rule: RateLimitRule,
        longest_window: u64,
    ) -> Result<RateLimitOutcome, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        let result = consume(&mut transaction, schema, id, key, now, rule, longest_window).await;
        match result {
            Ok(outcome) => {
                transaction.commit().await.map_err(storage)?;
                Ok(outcome)
            }
            Err(error) => {
                let _ = transaction.rollback().await;
                Err(error)
            }
        }
    }
}

async fn consume(
    connection: &mut sqlx::Transaction<'_, sqlx::MySql>,
    schema: &super::schema::MySqlSchema,
    id: &dyn DatabaseIdSupplier,
    key: &str,
    now: DateTime<Utc>,
    rule: RateLimitRule,
    longest_window: u64,
) -> Result<RateLimitOutcome, AuthError> {
    let window = duration(rule.window)?;
    let prune_ms = i64::try_from(longest_window)
        .ok()
        .and_then(|seconds| seconds.checked_mul(1_000))
        .ok_or_else(|| AuthError::InvalidConfiguration("rate-limit window is too large".into()))?;
    let now_ms = now.timestamp_millis();
    let mut expired = MySqlFilter::equal("lastRequest", json!(now_ms.saturating_sub(prune_ms)));
    expired.operator = MySqlFilterOperator::Lt;
    execute::delete_many(connection, schema, "rateLimit", &[expired]).await?;
    let current = execute::find_one_for_update(
        connection,
        schema,
        "rateLimit",
        &[MySqlFilter::equal("key", json!(key))],
        &[],
    )
    .await?;
    let Some(current) = current else {
        let mut record = Map::from_iter([
            ("key".into(), json!(key)),
            ("count".into(), json!(1)),
            ("lastRequest".into(), json!(now_ms)),
        ]);
        insert_id(&mut record, id.prepare()?)?;
        execute::insert_required(connection, schema, "rateLimit", record).await?;
        return Ok(RateLimitOutcome::allowed());
    };
    let count = integer(&current, "count")?;
    let last_ms = integer(&current, "lastRequest")?;
    let last = DateTime::<Utc>::from_timestamp_millis(last_ms)
        .ok_or_else(|| AuthError::Storage("rate-limit last request is invalid".into()))?;
    if now - last >= window {
        update(connection, schema, key, 1, now_ms).await?;
        return Ok(RateLimitOutcome::allowed());
    }
    if u64::try_from(count).unwrap_or(u64::MAX) >= u64::from(rule.max) {
        return Ok(RateLimitOutcome::denied(retry_after(last, window, now)));
    }
    update(connection, schema, key, count.saturating_add(1), now_ms).await?;
    Ok(RateLimitOutcome::allowed())
}

async fn update(
    connection: &mut sqlx::Transaction<'_, sqlx::MySql>,
    schema: &super::schema::MySqlSchema,
    key: &str,
    count: i64,
    last_request: i64,
) -> Result<(), AuthError> {
    execute::update_one(
        connection,
        schema,
        "rateLimit",
        &[MySqlFilter::equal("key", json!(key))],
        Map::from_iter([
            ("count".into(), json!(count)),
            ("lastRequest".into(), json!(last_request)),
        ]),
    )
    .await?
    .ok_or_else(|| AuthError::Storage("MySQL rate-limit row disappeared".into()))?;
    Ok(())
}

fn insert_id(record: &mut Map<String, Value>, id: PreparedDatabaseId) -> Result<(), AuthError> {
    if let PreparedDatabaseId::Value(value) = id {
        record.insert("id".into(), value.to_json()?);
    }
    Ok(())
}

fn integer(record: &Map<String, Value>, field: &str) -> Result<i64, AuthError> {
    record
        .get(field)
        .and_then(Value::as_i64)
        .ok_or_else(|| AuthError::Storage(format!("invalid MySQL rateLimit row: {field}")))
}

fn storage(error: sqlx::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}
