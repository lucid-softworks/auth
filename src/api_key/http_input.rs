use super::ApiKeyConfiguration;
use crate::{ApiKeyUpdate, AuthError};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct CreateRequest {
    pub config_id: Option<String>,
    pub name: Option<String>,
    pub expires_in: Option<i64>,
    pub prefix: Option<String>,
    pub remaining: Option<i64>,
    pub metadata: Option<Value>,
    pub refill_amount: Option<i64>,
    pub refill_interval: Option<i64>,
    pub rate_limit_time_window: Option<i64>,
    pub rate_limit_max: Option<i64>,
    pub rate_limit_enabled: Option<bool>,
    pub permissions: Option<BTreeMap<String, Vec<String>>>,
    pub user_id: Option<String>,
}

impl CreateRequest {
    pub(super) fn contains_server_only_property(&self) -> bool {
        self.remaining.is_some()
            || self.refill_amount.is_some()
            || self.refill_interval.is_some()
            || self.rate_limit_time_window.is_some()
            || self.rate_limit_max.is_some()
            || self.rate_limit_enabled.is_some()
            || self.permissions.is_some()
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct GetRequest {
    pub config_id: Option<String>,
    pub id: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ListRequest {
    pub config_id: Option<String>,
    pub organization_id: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    pub sort_by: Option<String>,
    pub sort_direction: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DeleteRequest {
    pub config_id: Option<String>,
    pub key_id: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct VerifyRequest {
    pub config_id: Option<String>,
    pub key: String,
    pub permissions: Option<BTreeMap<String, Vec<String>>>,
}

pub(super) fn resolve_configuration<'a>(
    configurations: &'a [ApiKeyConfiguration],
    config_id: Option<&str>,
) -> &'a ApiKeyConfiguration {
    let default = configurations
        .iter()
        .find(|config| config.config_id == "default")
        .expect("validated API-key configuration");
    config_id
        .and_then(|id| configurations.iter().find(|config| config.config_id == id))
        .unwrap_or(default)
}

pub(super) fn client_update(
    input: &Value,
    configuration: &ApiKeyConfiguration,
) -> Result<ApiKeyUpdate, AuthError> {
    Ok(ApiKeyUpdate {
        name: string_field(input, "name")?,
        enabled: bool_field(input, "enabled")?,
        expires_at: optional_seconds(input, "expiresIn")?,
        metadata: configuration
            .enable_metadata
            .then(|| optional_value(input, "metadata"))
            .flatten(),
        ..ApiKeyUpdate::default()
    })
}

pub(super) fn valid_prefix(prefix: &str) -> bool {
    prefix
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
}

fn string_field(input: &Value, field: &str) -> Result<Option<String>, AuthError> {
    input
        .get(field)
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| AuthError::InvalidRequest(format!("{field} must be a string")))
        })
        .transpose()
}

fn bool_field(input: &Value, field: &str) -> Result<Option<bool>, AuthError> {
    input
        .get(field)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| AuthError::InvalidRequest(format!("{field} must be a boolean")))
        })
        .transpose()
}

fn optional_seconds(
    input: &Value,
    field: &str,
) -> Result<Option<Option<chrono::DateTime<Utc>>>, AuthError> {
    let Some(value) = input.get(field) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(Some(None));
    }
    value
        .as_i64()
        .filter(|seconds| *seconds >= 1)
        .map(|seconds| Some(Some(Utc::now() + Duration::seconds(seconds))))
        .ok_or_else(|| AuthError::InvalidRequest(format!("{field} must be a positive number")))
}

fn optional_value(input: &Value, field: &str) -> Option<Option<Value>> {
    input.get(field).map(|value| {
        if value.is_null() {
            None
        } else {
            Some(value.clone())
        }
    })
}
