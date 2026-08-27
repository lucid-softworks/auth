use crate::{AuthError, oauth_provider::*};
use chrono::{DateTime, Utc};
use serde_json::Value;
use url::Url;

const RESOURCE_SIGNING_ALGORITHMS: &[&str] = &["EdDSA", "ES256", "ES512", "PS256", "RS256"];

pub(in crate::oauth_provider) async fn identifier_allowed(
    config: &OAuthProviderConfig,
    identifier: &str,
) -> Result<bool, AuthError> {
    if let Some(validator) = &config.callbacks.identifier_validator {
        return validator.validate(identifier).await;
    }
    Ok(Url::parse(identifier).is_ok_and(|url| {
        // Better Auth checks the URL API's `hash` string for truthiness. An
        // empty trailing `#` therefore behaves like no fragment, while a
        // non-empty fragment is rejected.
        url.fragment().is_none_or(str::is_empty)
    }))
}

pub(in crate::oauth_provider) fn resource_from_input(
    mut input: OAuthResourceInput,
    now: DateTime<Utc>,
) -> Result<OAuthProviderResource, AuthError> {
    if input
        .signing_algorithm
        .as_deref()
        .is_some_and(|algorithm| !RESOURCE_SIGNING_ALGORITHMS.contains(&algorithm))
    {
        input.signing_algorithm = None;
    }
    let identifier = input.identifier;
    Ok(OAuthProviderResource {
        id: String::new(),
        name: input.name.unwrap_or_else(|| identifier.clone()),
        identifier,
        access_token_ttl: optional_i64(input.access_token_ttl)?,
        refresh_token_ttl: optional_i64(input.refresh_token_ttl)?,
        signing_algorithm: input.signing_algorithm,
        signing_key_id: input.signing_key_id,
        allowed_scopes: input.allowed_scopes,
        custom_claims: input.custom_claims.map(Value::Object),
        dpop_bound_access_tokens_required: input.dpop_bound_access_tokens_required.unwrap_or(false),
        disabled: input.disabled.unwrap_or(false),
        created_at: Some(now),
        updated_at: Some(now),
        policy_version: 1,
        metadata: input.metadata.map(Value::Object),
    })
}

pub(super) fn merge_resource(
    mut resource: OAuthProviderResource,
    input: OAuthResourceInput,
    now: DateTime<Utc>,
) -> Result<OAuthProviderResource, AuthError> {
    if let Some(value) = input.name {
        resource.name = value;
    }
    merge_optional(&mut resource.access_token_ttl, input.access_token_ttl)?;
    merge_optional(&mut resource.refresh_token_ttl, input.refresh_token_ttl)?;
    if let Some(value) = input.signing_algorithm
        && RESOURCE_SIGNING_ALGORITHMS.contains(&value.as_str())
    {
        resource.signing_algorithm = Some(value);
    }
    replace_some(&mut resource.signing_key_id, input.signing_key_id);
    replace_some(&mut resource.allowed_scopes, input.allowed_scopes);
    replace_some(
        &mut resource.custom_claims,
        input.custom_claims.map(Value::Object),
    );
    if let Some(value) = input.dpop_bound_access_tokens_required {
        resource.dpop_bound_access_tokens_required = value;
    }
    if let Some(value) = input.disabled {
        resource.disabled = value;
    }
    replace_some(&mut resource.metadata, input.metadata.map(Value::Object));
    resource.updated_at = Some(now);
    Ok(resource)
}

fn merge_optional(target: &mut Option<i64>, value: Option<u64>) -> Result<(), AuthError> {
    if let Some(value) = value {
        *target = Some(i64::try_from(value).map_err(|_| {
            AuthError::InvalidConfiguration("OAuth resource TTL exceeds i64::MAX".into())
        })?);
    }
    Ok(())
}

fn replace_some<T>(target: &mut Option<T>, value: Option<T>) {
    if value.is_some() {
        *target = value;
    }
}

fn optional_i64(value: Option<u64>) -> Result<Option<i64>, AuthError> {
    value
        .map(|value| {
            i64::try_from(value).map_err(|_| {
                AuthError::InvalidConfiguration("OAuth resource TTL exceeds i64::MAX".into())
            })
        })
        .transpose()
}
