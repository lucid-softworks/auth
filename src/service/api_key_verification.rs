use super::{AuthService, api_key::stored_key, api_key_policy::permits_all};
use crate::{
    ApiKeyConfiguration, ApiKeyError, ApiKeyReference, ApiKeyUseOutcome, AuthError,
    PluginRequestContext, VerifiedApiKey,
};
use chrono::Utc;
use std::collections::BTreeMap;

#[derive(Clone, Copy)]
struct VerificationMode {
    run_validator: bool,
    load_user: bool,
    migrate_metadata: bool,
}

impl VerificationMode {
    const SERVER: Self = Self {
        run_validator: true,
        load_user: false,
        migrate_metadata: true,
    };
    #[cfg(feature = "axum")]
    const SESSION: Self = Self {
        run_validator: false,
        load_user: true,
        migrate_metadata: false,
    };
}

impl AuthService {
    pub async fn verify_api_key(
        &self,
        key: &str,
        configurations: &[ApiKeyConfiguration],
        expected_config_id: Option<&str>,
        permissions: Option<&BTreeMap<String, Vec<String>>>,
    ) -> Result<VerifiedApiKey, AuthError> {
        let context = PluginRequestContext {
            method: "POST".into(),
            path: "/api-key/verify".into(),
            query: None,
            headers: BTreeMap::new(),
        };
        let verified = self
            .verify_api_key_in_context(
                key,
                configurations,
                expected_config_id,
                permissions,
                &context,
                VerificationMode::SERVER,
            )
            .await?;
        self.schedule_deferred_verification_cleanup(configurations, &verified)?;
        Ok(verified)
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn verify_api_key_after_custom_validation(
        &self,
        key: &str,
        configurations: &[ApiKeyConfiguration],
        expected_config_id: Option<&str>,
        permissions: Option<&BTreeMap<String, Vec<String>>>,
        context: &PluginRequestContext,
    ) -> Result<VerifiedApiKey, AuthError> {
        let verified = self
            .verify_api_key_in_context(
                key,
                configurations,
                expected_config_id,
                permissions,
                context,
                VerificationMode::SESSION,
            )
            .await?;
        self.schedule_api_key_cleanup();
        Ok(verified)
    }

    async fn verify_api_key_in_context(
        &self,
        key: &str,
        configurations: &[ApiKeyConfiguration],
        expected_config_id: Option<&str>,
        permissions: Option<&BTreeMap<String, Vec<String>>>,
        context: &PluginRequestContext,
        mode: VerificationMode,
    ) -> Result<VerifiedApiKey, AuthError> {
        let lookup = resolve_configuration(configurations, expected_config_id)?;
        validate_before_lookup(lookup, expected_config_id, context, key, mode.run_validator)
            .await?;
        let stored = self
            .find_api_key_record_by_hash(lookup, &stored_key(lookup, key))
            .await?
            .ok_or(ApiKeyError::Invalid)?;
        if let Some(expected) = expected_config_id
            && !crate::api_key::config_ids_match(&stored.config_id, expected)
        {
            return Err(ApiKeyError::Invalid.into());
        }
        let configuration = resolve_configuration(configurations, Some(&stored.config_id))?;
        validate_after_lookup(
            configuration,
            expected_config_id,
            context,
            key,
            mode.run_validator,
        )
        .await?;
        if !stored.enabled {
            return Err(ApiKeyError::Disabled.into());
        }
        if stored
            .expires_at
            .is_some_and(|expires_at| expires_at < Utc::now())
        {
            self.delete_invalid_api_key_record(configuration, &stored)
                .await?;
            return Err(ApiKeyError::Expired.into());
        }
        if permissions.is_some_and(|required| !permits_all(&stored, required)) {
            return Err(ApiKeyError::PermissionDenied.into());
        }
        if stored.remaining == Some(0) && stored.refill_amount.is_none() {
            self.delete_invalid_api_key_record(configuration, &stored)
                .await?;
            return Err(ApiKeyError::UsageExceeded.into());
        }
        let mut api_key = match self
            .record_api_key_use_for_config(configuration, &stored)
            .await?
        {
            ApiKeyUseOutcome::Allowed(api_key) => *api_key,
            ApiKeyUseOutcome::Invalid => return Err(ApiKeyError::Invalid.into()),
            ApiKeyUseOutcome::UsageExceeded => {
                if stored.refill_amount.is_none() {
                    self.delete_invalid_api_key_record(configuration, &stored)
                        .await?;
                }
                return Err(ApiKeyError::UsageExceeded.into());
            }
            ApiKeyUseOutcome::RateLimited {
                retry_after_milliseconds,
            } => {
                return Err(ApiKeyError::RateLimited {
                    retry_after_milliseconds,
                }
                .into());
            }
        };
        if mode.migrate_metadata {
            api_key = self.migrate_api_key_metadata(configuration, api_key).await;
        }
        let user = self
            .api_key_user(configuration, &api_key.reference_id, mode.load_user)
            .await?;
        Ok(VerifiedApiKey { api_key, user })
    }

    async fn api_key_user(
        &self,
        configuration: &ApiKeyConfiguration,
        reference_id: &str,
        load_user: bool,
    ) -> Result<Option<crate::AuthUser>, AuthError> {
        if !load_user || configuration.reference != ApiKeyReference::User {
            return Ok(None);
        }
        Ok(Some(
            self.store
                .find_user_by_id(reference_id)
                .await?
                .ok_or(ApiKeyError::InvalidReferenceId)?,
        ))
    }

    fn schedule_deferred_verification_cleanup(
        &self,
        configurations: &[ApiKeyConfiguration],
        verified: &VerifiedApiKey,
    ) -> Result<(), AuthError> {
        if resolve_configuration(configurations, Some(&verified.api_key.config_id))?.defer_updates {
            self.schedule_api_key_cleanup();
        }
        Ok(())
    }
}

async fn validate_before_lookup(
    config: &ApiKeyConfiguration,
    expected_config_id: Option<&str>,
    context: &PluginRequestContext,
    key: &str,
    run: bool,
) -> Result<(), AuthError> {
    if run
        && expected_config_id.is_some()
        && let Some(validator) = &config.key_validator
    {
        let accepted = validator
            .validate(context, key)
            .await
            .map_err(|_| ApiKeyError::VerificationValidatorFailed)?;
        if !accepted {
            return Err(ApiKeyError::VerificationValidatorRejected.into());
        }
    }
    Ok(())
}

async fn validate_after_lookup(
    config: &ApiKeyConfiguration,
    expected_config_id: Option<&str>,
    context: &PluginRequestContext,
    key: &str,
    run: bool,
) -> Result<(), AuthError> {
    if run
        && expected_config_id.is_none()
        && let Some(validator) = &config.key_validator
        && !validator.validate(context, key).await?
    {
        return Err(ApiKeyError::NotFound.into());
    }
    Ok(())
}

fn resolve_configuration<'a>(
    configurations: &'a [ApiKeyConfiguration],
    config_id: Option<&str>,
) -> Result<&'a ApiKeyConfiguration, AuthError> {
    if let Some(config) = config_id
        .filter(|id| !id.is_empty())
        .and_then(|id| configurations.iter().find(|config| config.config_id == id))
    {
        return Ok(config);
    }
    configurations
        .iter()
        .find(|config| crate::api_key::config_ids_match(&config.config_id, "default"))
        .ok_or_else(|| ApiKeyError::NoDefaultConfiguration.into())
}
