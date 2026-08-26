use super::super::{PostgresModel, PostgresWrite};
use crate::{ApiKey, AuthError};
use serde_json::{Map, Value, json};
use sqlx::postgres::PgRow;

pub(super) fn api_key_writes<'a>(
    model: &'a PostgresModel<'a>,
    api_key: &ApiKey,
    id: &crate::store::PreparedDatabaseId,
) -> Result<Vec<PostgresWrite<'a>>, AuthError> {
    let mut values = api_key_values(api_key)?;
    values.remove("id");
    super::super::rows::insert_prepared_id(&mut values, id)?;
    model.encode_fields(
        values
            .iter()
            .map(|(field, value)| (field.as_str(), value.clone())),
    )
}

pub(super) fn api_key_update_writes<'a>(
    model: &'a PostgresModel<'a>,
    api_key: &ApiKey,
) -> Result<Vec<PostgresWrite<'a>>, AuthError> {
    let values = api_key_values(api_key)?;
    model.encode_fields(
        [
            "name",
            "refillInterval",
            "refillAmount",
            "lastRefillAt",
            "enabled",
            "rateLimitEnabled",
            "rateLimitTimeWindow",
            "rateLimitMax",
            "requestCount",
            "remaining",
            "lastRequest",
            "expiresAt",
            "permissions",
            "metadata",
            "updatedAt",
        ]
        .into_iter()
        .map(|field| (field, values[field].clone())),
    )
}

pub(super) fn api_key_usage_writes<'a>(
    model: &'a PostgresModel<'a>,
    api_key: &ApiKey,
) -> Result<Vec<PostgresWrite<'a>>, AuthError> {
    let values = api_key_values(api_key)?;
    model.encode_fields(
        [
            "remaining",
            "lastRefillAt",
            "requestCount",
            "lastRequest",
            "updatedAt",
        ]
        .into_iter()
        .map(|field| (field, values[field].clone())),
    )
}

fn api_key_values(api_key: &ApiKey) -> Result<Map<String, Value>, AuthError> {
    let permissions = api_key
        .permissions
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| AuthError::Storage(format!("API-key permissions JSON failed: {error}")))?;
    let metadata = api_key
        .metadata
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|error| AuthError::Storage(format!("API-key metadata JSON failed: {error}")))?;
    Ok(Map::from_iter([
        ("id".into(), json!(api_key.id.to_string())),
        ("configId".into(), json!(api_key.config_id)),
        ("name".into(), optional_string(api_key.name.clone())),
        ("start".into(), optional_string(api_key.start.clone())),
        ("prefix".into(), optional_string(api_key.prefix.clone())),
        ("key".into(), json!(api_key.key_hash)),
        ("referenceId".into(), json!(api_key.reference_id)),
        (
            "refillInterval".into(),
            optional_number(api_key.refill_interval),
        ),
        (
            "refillAmount".into(),
            optional_number(api_key.refill_amount),
        ),
        ("lastRefillAt".into(), optional_date(api_key.last_refill_at)),
        ("enabled".into(), json!(api_key.enabled)),
        ("rateLimitEnabled".into(), json!(api_key.rate_limit_enabled)),
        (
            "rateLimitTimeWindow".into(),
            optional_number(api_key.rate_limit_time_window),
        ),
        (
            "rateLimitMax".into(),
            optional_number(api_key.rate_limit_max),
        ),
        ("requestCount".into(), json!(api_key.request_count)),
        ("remaining".into(), optional_number(api_key.remaining)),
        ("lastRequest".into(), optional_date(api_key.last_request)),
        ("expiresAt".into(), optional_date(api_key.expires_at)),
        ("permissions".into(), optional_string(permissions)),
        ("metadata".into(), optional_string(metadata)),
        ("createdAt".into(), json!(api_key.created_at.to_rfc3339())),
        ("updatedAt".into(), json!(api_key.updated_at.to_rfc3339())),
    ]))
}

pub(super) fn decode_api_key(model: &PostgresModel<'_>, row: &PgRow) -> Result<ApiKey, AuthError> {
    decode_api_key_values(model.decode_all(row)?)
}

fn decode_api_key_values(mut values: Map<String, Value>) -> Result<ApiKey, AuthError> {
    use super::super::rows::{
        optional_date_value, optional_string_value, required_date, required_string,
    };
    let permissions = optional_string_value(&mut values, "permissions")?
        .map(|value| serde_json::from_str(&value))
        .transpose()
        .map_err(|error| invalid_json("permissions", error))?;
    let metadata = optional_string_value(&mut values, "metadata")?
        .map(|value| serde_json::from_str(&value).unwrap_or(Value::String(value)));
    Ok(ApiKey {
        id: required_string(&mut values, "id")?,
        config_id: required_string(&mut values, "configId")?,
        name: optional_string_value(&mut values, "name")?,
        start: optional_string_value(&mut values, "start")?,
        prefix: optional_string_value(&mut values, "prefix")?,
        key_hash: required_string(&mut values, "key")?,
        reference_id: required_string(&mut values, "referenceId")?,
        refill_interval: optional_i64(&mut values, "refillInterval")?,
        refill_amount: optional_i64(&mut values, "refillAmount")?,
        last_refill_at: optional_date_value(&mut values, "lastRefillAt")?,
        enabled: optional_bool(&mut values, "enabled", true)?,
        rate_limit_enabled: optional_bool(&mut values, "rateLimitEnabled", true)?,
        rate_limit_time_window: optional_i64(&mut values, "rateLimitTimeWindow")?,
        rate_limit_max: optional_i64(&mut values, "rateLimitMax")?,
        request_count: optional_i64(&mut values, "requestCount")?.unwrap_or(0),
        remaining: optional_i64(&mut values, "remaining")?,
        last_request: optional_date_value(&mut values, "lastRequest")?,
        expires_at: optional_date_value(&mut values, "expiresAt")?,
        permissions,
        metadata,
        created_at: required_date(&mut values, "createdAt")?,
        updated_at: required_date(&mut values, "updatedAt")?,
    })
}

fn optional_i64(values: &mut Map<String, Value>, field: &str) -> Result<Option<i64>, AuthError> {
    match values.remove(field) {
        Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => value.as_i64().map(Some).ok_or_else(|| invalid(field)),
        _ => Err(invalid(field)),
    }
}

fn optional_bool(
    values: &mut Map<String, Value>,
    field: &str,
    default: bool,
) -> Result<bool, AuthError> {
    match values.remove(field) {
        Some(Value::Null) => Ok(default),
        Some(Value::Bool(value)) => Ok(value),
        _ => Err(invalid(field)),
    }
}

fn optional_string(value: Option<String>) -> Value {
    value.map_or(Value::Null, Value::String)
}
fn optional_number(value: Option<i64>) -> Value {
    value.map_or(Value::Null, |value| json!(value))
}
fn optional_date(value: Option<chrono::DateTime<chrono::Utc>>) -> Value {
    value.map_or(Value::Null, |value| json!(value.to_rfc3339()))
}
fn invalid(field: &str) -> AuthError {
    AuthError::Storage(format!(
        "PostgreSQL returned an invalid canonical API-key field '{field}'"
    ))
}
fn invalid_json(field: &str, error: serde_json::Error) -> AuthError {
    AuthError::Storage(format!(
        "PostgreSQL API-key field '{field}' contains invalid JSON: {error}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AdapterSchemaOptions, ApiKeyConfiguration, ApiKeyOptions, ApiKeyPlugin, AuthConfig,
        AuthPlugin, AuthSchemaCatalog, ResolvedAdapterSchema,
    };
    use chrono::Utc;
    use std::sync::Arc;
    use uuid::Uuid;

    #[test]
    fn hostile_remaps_are_quoted_and_secret_values_stay_bound() {
        let config = AuthConfig::new([42; 32]).unwrap();
        let mut options = ApiKeyOptions::default();
        options.schema.model_name = Some("api\" keys".into());
        options
            .schema
            .fields
            .insert("key".into(), "hashed secret".into());
        let plugin = ApiKeyPlugin::with_options(ApiKeyConfiguration::default(), options);
        let catalog = Arc::new(AuthSchemaCatalog::build(&config, plugin.schema()).unwrap());
        let resolved =
            ResolvedAdapterSchema::new(catalog, AdapterSchemaOptions::default()).unwrap();
        let physical =
            super::super::super::physical_schema::PostgresPhysicalSchema::new(&resolved).unwrap();
        let model = physical.model("apikey").unwrap();
        assert_eq!(
            model.logical_fields().collect::<Vec<_>>(),
            vec![
                "configId",
                "name",
                "start",
                "referenceId",
                "prefix",
                "key",
                "refillInterval",
                "refillAmount",
                "lastRefillAt",
                "enabled",
                "rateLimitEnabled",
                "rateLimitTimeWindow",
                "rateLimitMax",
                "requestCount",
                "remaining",
                "lastRequest",
                "expiresAt",
                "createdAt",
                "updatedAt",
                "permissions",
                "metadata",
            ]
        );
        let now = Utc::now();
        let key = ApiKey {
            id: Uuid::new_v4().to_string(),
            config_id: "default".into(),
            name: None,
            start: None,
            prefix: None,
            key_hash: "hostile' --".into(),
            reference_id: "user".into(),
            refill_interval: None,
            refill_amount: None,
            last_refill_at: None,
            enabled: true,
            rate_limit_enabled: true,
            rate_limit_time_window: Some(1000),
            rate_limit_max: Some(10),
            request_count: 0,
            remaining: None,
            last_request: None,
            expires_at: None,
            permissions: None,
            metadata: None,
            created_at: now,
            updated_at: now,
        };
        let query = super::super::super::rows::insert_query(
            &model,
            api_key_writes(
                &model,
                &key,
                &super::super::super::rows::explicit_id(key.id.clone()),
            )
            .unwrap(),
        );
        let sql = query.sql();
        assert!(sql.contains("\"api\"\" keys\"") && sql.contains("\"hashed secret\""));
        assert!(!sql.contains("hostile") && !sql.contains("lucid_auth_api_keys"));
    }
}
