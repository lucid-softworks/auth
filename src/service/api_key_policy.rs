use super::api_key::{ApiKeySortDirection, ApiKeyUpdate};
use crate::{ApiKey, ApiKeyConfiguration, ApiKeyError, AuthError, NewApiKey};
use chrono::Utc;
use std::{cmp::Ordering, collections::BTreeMap};

pub(super) fn validate_create(
    config: &ApiKeyConfiguration,
    input: &NewApiKey,
) -> Result<(), AuthError> {
    validate_name(config, input.name.as_deref())?;
    validate_prefix(config, input.prefix.as_deref())?;
    validate_expiry(config, input.expires_at)?;
    validate_metadata(config, input.metadata.as_ref())?;
    validate_refill(input.refill_amount, input.refill_interval)
}

pub(super) fn validate_update(
    config: &ApiKeyConfiguration,
    update: &ApiKeyUpdate,
) -> Result<(), AuthError> {
    if update_is_empty(update) {
        return Err(ApiKeyError::NoValuesToUpdate.into());
    }
    if let Some(name) = &update.name {
        validate_name(config, Some(name))?;
    }
    if let Some(expires_at) = update.expires_at {
        validate_expiry(config, expires_at)?;
    }
    if let Some(Some(metadata)) = &update.metadata {
        validate_metadata(config, Some(metadata))?;
    }
    validate_refill(update.refill_amount, update.refill_interval)
}

pub(super) fn apply_update(api_key: &mut ApiKey, update: ApiKeyUpdate) {
    if let Some(name) = update.name {
        api_key.name = Some(name);
    }
    if let Some(enabled) = update.enabled {
        api_key.enabled = enabled;
    }
    if let Some(expires_at) = update.expires_at {
        api_key.expires_at = expires_at;
    }
    if let Some(metadata) = update.metadata {
        api_key.metadata = metadata;
    }
    if let Some(remaining) = update.remaining {
        api_key.remaining = Some(remaining);
    }
    if let Some(amount) = update.refill_amount {
        api_key.refill_amount = Some(amount);
    }
    if let Some(interval) = update.refill_interval {
        api_key.refill_interval = Some(interval);
    }
    if let Some(enabled) = update.rate_limit_enabled {
        api_key.rate_limit_enabled = enabled;
    }
    if let Some(window) = update.rate_limit_time_window {
        api_key.rate_limit_time_window = Some(window);
    }
    if let Some(max) = update.rate_limit_max {
        api_key.rate_limit_max = Some(max);
    }
    if let Some(permissions) = update.permissions {
        api_key.permissions = permissions;
    }
}

pub(super) fn normalize_permissions(permissions: &mut Option<BTreeMap<String, Vec<String>>>) {
    for actions in permissions
        .iter_mut()
        .flat_map(|permissions| permissions.values_mut())
    {
        actions.sort_unstable();
        actions.dedup();
    }
}

pub(super) fn permits_all(api_key: &ApiKey, required: &BTreeMap<String, Vec<String>>) -> bool {
    required.iter().all(|(resource, actions)| {
        actions
            .iter()
            .all(|action| api_key.permits(resource, action))
    })
}

pub(super) fn sort_api_keys(keys: &mut [ApiKey], field: &str, direction: ApiKeySortDirection) {
    keys.sort_by(|left, right| {
        let ordering = match field {
            "createdAt" => left.created_at.cmp(&right.created_at),
            "updatedAt" => left.updated_at.cmp(&right.updated_at),
            "name" => left.name.cmp(&right.name),
            "expiresAt" => left.expires_at.cmp(&right.expires_at),
            "start" => left.start.cmp(&right.start),
            _ => Ordering::Equal,
        };
        match direction {
            ApiKeySortDirection::Ascending => ordering,
            ApiKeySortDirection::Descending => ordering.reverse(),
        }
    });
}

fn validate_name(config: &ApiKeyConfiguration, name: Option<&str>) -> Result<(), AuthError> {
    match name {
        Some("") if config.require_name => Err(ApiKeyError::NameRequired.into()),
        Some("") => Ok(()),
        Some(name)
            if !(config.minimum_name_length..=config.maximum_name_length).contains(&name.len()) =>
        {
            Err(ApiKeyError::InvalidNameLength.into())
        }
        None if config.require_name => Err(ApiKeyError::NameRequired.into()),
        _ => Ok(()),
    }
}

fn validate_prefix(config: &ApiKeyConfiguration, prefix: Option<&str>) -> Result<(), AuthError> {
    let Some(prefix) = prefix else { return Ok(()) };
    if !(config.minimum_prefix_length..=config.maximum_prefix_length).contains(&prefix.len()) {
        return Err(ApiKeyError::InvalidPrefixLength.into());
    }
    Ok(())
}

fn validate_expiry(
    config: &ApiKeyConfiguration,
    expires_at: Option<chrono::DateTime<Utc>>,
) -> Result<(), AuthError> {
    let Some(expires_at) = expires_at else {
        return Ok(());
    };
    if config.expiration.disable_custom_expires {
        return Err(ApiKeyError::ExpirationDisabled.into());
    }
    let days = ((expires_at - Utc::now()).num_seconds() + 1) as f64 / 86_400.0;
    if days < config.expiration.minimum_days {
        return Err(ApiKeyError::ExpiresTooSmall.into());
    }
    if days > config.expiration.maximum_days {
        return Err(ApiKeyError::ExpiresTooLarge.into());
    }
    Ok(())
}

fn validate_metadata(
    config: &ApiKeyConfiguration,
    metadata: Option<&serde_json::Value>,
) -> Result<(), AuthError> {
    if metadata.is_some() && !config.enable_metadata {
        return Err(ApiKeyError::MetadataDisabled.into());
    }
    if metadata.is_some_and(|value| !(value.is_object() || value.is_array() || value.is_null())) {
        return Err(ApiKeyError::InvalidMetadata.into());
    }
    Ok(())
}

fn validate_refill(amount: Option<i64>, interval: Option<i64>) -> Result<(), AuthError> {
    match (amount, interval) {
        (Some(_), None) => Err(ApiKeyError::RefillAmountRequired.into()),
        (None, Some(_)) => Err(ApiKeyError::RefillIntervalRequired.into()),
        _ => Ok(()),
    }
}

fn update_is_empty(update: &ApiKeyUpdate) -> bool {
    update.name.is_none()
        && update.enabled.is_none()
        && update.expires_at.is_none()
        && update.metadata.is_none()
        && update.remaining.is_none()
        && update.refill_amount.is_none()
        && update.refill_interval.is_none()
        && update.rate_limit_enabled.is_none()
        && update.rate_limit_time_window.is_none()
        && update.rate_limit_max.is_none()
        && update.permissions.is_none()
}
