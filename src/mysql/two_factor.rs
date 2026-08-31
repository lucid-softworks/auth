use super::{MySqlFilter, MySqlStore, query::execute};
use crate::{AuthError, DatabaseIdSupplier, PreparedDatabaseId, TwoFactorRecord, TwoFactorStore};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use sqlx::{QueryBuilder, MySql};

#[async_trait]
impl TwoFactorStore for MySqlStore {
    async fn two_factor_enabled(&self, user_id: &str) -> Result<bool, AuthError> {
        Ok(self
            .find_record("user", &[eq("id", user_id)], &["twoFactorEnabled".into()])
            .await?
            .and_then(|record| record.get("twoFactorEnabled").and_then(Value::as_bool))
            .unwrap_or(false))
    }

    async fn set_two_factor_enabled(&self, user_id: &str, enabled: bool) -> Result<(), AuthError> {
        self.update_record(
            "user",
            &[eq("id", user_id)],
            Map::from_iter([("twoFactorEnabled".into(), json!(enabled))]),
        )
        .await?
        .ok_or(AuthError::NotFound)?;
        Ok(())
    }

    async fn find_two_factor(&self, user_id: &str) -> Result<Option<TwoFactorRecord>, AuthError> {
        self.find_record("twoFactor", &[eq("userId", user_id)], &[])
            .await?
            .map(decode)
            .transpose()
    }

    async fn upsert_two_factor(
        &self,
        id: &dyn DatabaseIdSupplier,
        record: TwoFactorRecord,
    ) -> Result<TwoFactorRecord, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        if execute::find_one(
            &mut transaction,
            schema,
            "user",
            &[eq("id", &record.user_id)],
            &[],
        )
        .await?
        .is_none()
        {
            transaction.rollback().await.map_err(storage)?;
            return Err(AuthError::NotFound);
        }
        if let Some(updated) = execute::update_one(
            &mut transaction,
            schema,
            "twoFactor",
            &[eq("userId", &record.user_id)],
            update_values(&record),
        )
        .await?
        {
            transaction.commit().await.map_err(storage)?;
            return decode(updated);
        }
        let mut values = all_values(&record);
        insert_id(&mut values, id.prepare()?)?;
        let inserted = execute::insert_required(&mut transaction, schema, "twoFactor", values).await?;
        transaction.commit().await.map_err(storage)?;
        decode(inserted)
    }

    async fn delete_two_factor(&self, user_id: &str) -> Result<(), AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        execute::delete_many(
            &mut transaction,
            schema,
            "twoFactor",
            &[eq("userId", user_id)],
        )
        .await?;
        execute::update_one(
            &mut transaction,
            schema,
            "user",
            &[eq("id", user_id)],
            Map::from_iter([("twoFactorEnabled".into(), json!(false))]),
        )
        .await?;
        transaction.commit().await.map_err(storage)
    }

    async fn replace_backup_codes(
        &self,
        user_id: &str,
        expected: &str,
        replacement: String,
    ) -> Result<bool, AuthError> {
        Ok(self
            .update_record(
                "twoFactor",
                &[eq("userId", user_id), eq("backupCodes", expected)],
                Map::from_iter([("backupCodes".into(), json!(replacement))]),
            )
            .await?
            .is_some())
    }

    async fn complete_two_factor_enrollment(&self, user_id: &str) -> Result<bool, AuthError> {
        let schema = self.physical_schema()?;
        let mut transaction = self.pool.begin().await.map_err(storage)?;
        let updated = execute::update_one(
            &mut transaction,
            schema,
            "twoFactor",
            &[eq("userId", user_id)],
            Map::from_iter([("verified".into(), json!(true))]),
        )
        .await?
        .is_some();
        if !updated {
            transaction.rollback().await.map_err(storage)?;
            return Ok(false);
        }
        execute::update_one(
            &mut transaction,
            schema,
            "user",
            &[eq("id", user_id)],
            Map::from_iter([("twoFactorEnabled".into(), json!(true))]),
        )
        .await?;
        transaction.commit().await.map_err(storage)?;
        Ok(true)
    }

    async fn record_two_factor_failure(
        &self,
        user_id: &str,
        max_attempts: u32,
        locked_until: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        record_failure(self, user_id, max_attempts, locked_until).await
    }

    async fn reset_two_factor_failures(&self, user_id: &str) -> Result<(), AuthError> {
        self.update_record(
            "twoFactor",
            &[eq("userId", user_id)],
            Map::from_iter([
                ("failedVerificationCount".into(), json!(0)),
                ("lockedUntil".into(), Value::Null),
            ]),
        )
        .await?;
        Ok(())
    }
}

async fn record_failure(
    store: &MySqlStore,
    user_id: &str,
    max_attempts: u32,
    locked_until: DateTime<Utc>,
) -> Result<bool, AuthError> {
    let schema = store.physical_schema()?;
    let model = schema.model("twoFactor")?;
    let failures = model.quoted_column("failedVerificationCount")?;
    let locked = model.quoted_column("lockedUntil")?;
    let mut query = QueryBuilder::<MySql>::new("update ");
    query
        .push(model.quoted_table())
        .push(" set ")
        .push(failures)
        .push(" = ")
        .push(failures)
        .push(" + 1, ")
        .push(locked)
        .push(" = case when ")
        .push(failures)
        .push(" + 1 >= ")
        .push_bind(i64::from(max_attempts))
        .push(" then ");
    model
        .encode("lockedUntil", json!(locked_until))?
        .push_bind(&mut query);
    query.push(" else ").push(locked).push(" end where ");
    query.push(model.quoted_column("userId")?).push(" = ");
    model
        .encode("userId", json!(user_id))?
        .push_bind(&mut query);
    query.push(" returning ").push(failures);
    let mut connection = store.pool.acquire().await.map_err(storage)?;
    let count: Option<i64> = query
        .build_query_scalar()
        .fetch_optional(&mut *connection)
        .await
        .map_err(storage)?;
    Ok(count.is_some_and(|count| count >= i64::from(max_attempts)))
}

fn all_values(record: &TwoFactorRecord) -> Map<String, Value> {
    let mut values = update_values(record);
    values.insert("userId".into(), json!(record.user_id));
    values
}

fn update_values(record: &TwoFactorRecord) -> Map<String, Value> {
    Map::from_iter([
        ("secret".into(), json!(record.encrypted_secret)),
        ("backupCodes".into(), json!(record.encrypted_backup_codes)),
        ("verified".into(), json!(record.verified)),
        (
            "failedVerificationCount".into(),
            json!(record.failed_verification_count),
        ),
        ("lockedUntil".into(), json!(record.locked_until)),
    ])
}

fn decode(mut values: Map<String, Value>) -> Result<TwoFactorRecord, AuthError> {
    Ok(TwoFactorRecord {
        id: string(&mut values, "id")?,
        user_id: string(&mut values, "userId")?,
        encrypted_secret: string(&mut values, "secret")?,
        encrypted_backup_codes: string(&mut values, "backupCodes")?,
        verified: optional_bool(&mut values, "verified", true)?,
        failed_verification_count: optional_u32(&mut values, "failedVerificationCount", 0)?,
        locked_until: optional_date(&mut values, "lockedUntil")?,
    })
}

fn string(values: &mut Map<String, Value>, field: &str) -> Result<String, AuthError> {
    values
        .remove(field)
        .and_then(|value| value.as_str().map(str::to_owned))
        .ok_or_else(|| invalid(field))
}
fn optional_bool(
    values: &mut Map<String, Value>,
    field: &str,
    default: bool,
) -> Result<bool, AuthError> {
    match values.remove(field) {
        Some(Value::Bool(value)) => Ok(value),
        Some(Value::Null) => Ok(default),
        _ => Err(invalid(field)),
    }
}
fn optional_u32(
    values: &mut Map<String, Value>,
    field: &str,
    default: u32,
) -> Result<u32, AuthError> {
    match values.remove(field) {
        Some(Value::Number(value)) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| invalid(field)),
        Some(Value::Null) => Ok(default),
        _ => Err(invalid(field)),
    }
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
fn insert_id(values: &mut Map<String, Value>, id: PreparedDatabaseId) -> Result<(), AuthError> {
    if let PreparedDatabaseId::Value(value) = id {
        values.insert("id".into(), value.to_json()?);
    }
    Ok(())
}
fn eq(field: &str, value: &str) -> MySqlFilter {
    MySqlFilter::equal(field, json!(value))
}
fn invalid(field: &str) -> AuthError {
    AuthError::Storage(format!("invalid MySQL twoFactor row: {field}"))
}
fn storage(error: sqlx::Error) -> AuthError {
    AuthError::Storage(error.to_string())
}
