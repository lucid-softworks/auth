use super::{
    AuthService,
    api_key_policy::{
        apply_update, normalize_permissions, permits_all, sort_api_keys, validate_create,
        validate_update,
    },
};
use crate::{
    ApiKey, ApiKeyConfiguration, ApiKeyError, ApiKeyReference, ApiKeyUseOutcome, AuthError,
    IssuedApiKey, NewApiKey, SessionWithUser, VerifiedApiKey,
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use rand::RngExt;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, Clone, Default)]
pub struct ApiKeyUpdate {
    pub name: Option<String>,
    pub enabled: Option<bool>,
    pub expires_at: Option<Option<chrono::DateTime<Utc>>>,
    pub metadata: Option<Option<serde_json::Value>>,
    pub remaining: Option<i64>,
    pub refill_amount: Option<i64>,
    pub refill_interval: Option<i64>,
    pub rate_limit_enabled: Option<bool>,
    pub rate_limit_time_window: Option<i64>,
    pub rate_limit_max: Option<i64>,
    pub permissions: Option<Option<BTreeMap<String, Vec<String>>>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeySortDirection {
    Ascending,
    Descending,
}

impl AuthService {
    pub async fn issue_api_key(
        &self,
        actor: &SessionWithUser,
        config: &ApiKeyConfiguration,
        input: NewApiKey,
    ) -> Result<IssuedApiKey, AuthError> {
        self.issue_api_key_for_reference(actor, config, input, None)
            .await
    }

    pub async fn issue_organization_api_key(
        &self,
        actor: &SessionWithUser,
        config: &ApiKeyConfiguration,
        input: NewApiKey,
        organization_id: Uuid,
    ) -> Result<IssuedApiKey, AuthError> {
        self.issue_api_key_for_reference(actor, config, input, Some(organization_id))
            .await
    }

    async fn issue_api_key_for_reference(
        &self,
        actor: &SessionWithUser,
        config: &ApiKeyConfiguration,
        mut input: NewApiKey,
        organization_id: Option<Uuid>,
    ) -> Result<IssuedApiKey, AuthError> {
        self.plugins.authorize_application_access(actor).await?;
        let reference_id = match config.reference {
            ApiKeyReference::User => actor.user.id.clone(),
            ApiKeyReference::Organization => {
                let organization_id = organization_id.ok_or(ApiKeyError::OrganizationIdRequired)?;
                self.authorize_organization_api_key(actor, organization_id, "create")
                    .await?;
                organization_id.to_string()
            }
        };
        validate_create(config, &input)?;
        normalize_permissions(&mut input.permissions);
        let expires_at = input.expires_at.or_else(|| {
            config
                .expiration
                .default_expires_in_seconds
                .map(|seconds| Utc::now() + chrono::Duration::seconds(seconds))
        });
        let remaining = input.remaining.or(input.refill_amount);
        let key = generate_key(config, input.prefix.as_deref()).await?;
        let now = Utc::now();
        let api_key = self.prepare_database_create(
            "apikey",
            crate::DatabaseIdInput::Absent,
            false,
            ApiKey {
                id: String::new(),
                config_id: config.config_id.clone(),
                name: input.name,
                start: config.starting_characters.store.then(|| {
                    key.chars()
                        .take(config.starting_characters.length)
                        .collect()
                }),
                prefix: input.prefix.or_else(|| config.default_prefix.clone()),
                key_hash: hash_key(&key),
                reference_id,
                refill_interval: input.refill_interval,
                refill_amount: input.refill_amount,
                last_refill_at: None,
                enabled: true,
                rate_limit_enabled: input.rate_limit_enabled,
                rate_limit_time_window: input.rate_limit_time_window,
                rate_limit_max: input.rate_limit_max,
                request_count: 0,
                remaining,
                last_request: None,
                expires_at,
                permissions: input
                    .permissions
                    .or_else(|| config.default_permissions.clone()),
                metadata: input.metadata,
                created_at: now,
                updated_at: now,
            },
        )?;
        let api_key = self.store.create_api_key(api_key).await?;
        Ok(IssuedApiKey { api_key, key })
    }

    pub async fn get_api_key(
        &self,
        actor: &SessionWithUser,
        config: &ApiKeyConfiguration,
        api_key_id: &str,
    ) -> Result<ApiKey, AuthError> {
        self.plugins.authorize_application_access(actor).await?;
        self.owned_api_key(actor, config, api_key_id, "read").await
    }

    pub async fn list_api_keys(
        &self,
        actor: &SessionWithUser,
        config_id: Option<&str>,
        sort_by: Option<&str>,
        direction: ApiKeySortDirection,
    ) -> Result<Vec<ApiKey>, AuthError> {
        self.list_api_keys_for_reference(actor, config_id, sort_by, direction, None)
            .await
    }

    pub async fn list_organization_api_keys(
        &self,
        actor: &SessionWithUser,
        config_id: Option<&str>,
        sort_by: Option<&str>,
        direction: ApiKeySortDirection,
        organization_id: Uuid,
    ) -> Result<Vec<ApiKey>, AuthError> {
        self.list_api_keys_for_reference(
            actor,
            config_id,
            sort_by,
            direction,
            Some(organization_id),
        )
        .await
    }

    async fn list_api_keys_for_reference(
        &self,
        actor: &SessionWithUser,
        config_id: Option<&str>,
        sort_by: Option<&str>,
        direction: ApiKeySortDirection,
        organization_id: Option<Uuid>,
    ) -> Result<Vec<ApiKey>, AuthError> {
        self.plugins.authorize_application_access(actor).await?;
        if let Some(organization_id) = organization_id {
            self.authorize_organization_api_key(actor, organization_id, "read")
                .await?;
        }
        let reference_id = organization_id
            .map(|id| id.to_string())
            .unwrap_or_else(|| actor.user.id.clone());
        let mut keys = self.store.list_api_keys(&reference_id, config_id).await?;
        if let Some(sort_by) = sort_by {
            sort_api_keys(&mut keys, sort_by, direction);
        }
        Ok(keys)
    }

    pub async fn update_api_key(
        &self,
        actor: &SessionWithUser,
        config: &ApiKeyConfiguration,
        api_key_id: &str,
        update: ApiKeyUpdate,
    ) -> Result<ApiKey, AuthError> {
        self.plugins.authorize_application_access(actor).await?;
        let mut api_key = self
            .owned_api_key(actor, config, api_key_id, "update")
            .await?;
        validate_update(config, &update)?;
        apply_update(&mut api_key, update);
        api_key.updated_at = Utc::now();
        self.store
            .update_api_key(api_key)
            .await?
            .ok_or_else(|| ApiKeyError::NotFound.into())
    }

    pub async fn delete_api_key(
        &self,
        actor: &SessionWithUser,
        config: &ApiKeyConfiguration,
        api_key_id: &str,
    ) -> Result<(), AuthError> {
        self.plugins.authorize_application_access(actor).await?;
        self.owned_api_key(actor, config, api_key_id, "delete")
            .await?;
        if !self.store.delete_api_key(api_key_id).await? {
            return Err(ApiKeyError::NotFound.into());
        }
        Ok(())
    }

    pub async fn verify_api_key(
        &self,
        key: &str,
        configurations: &[ApiKeyConfiguration],
        expected_config_id: Option<&str>,
        permissions: Option<&BTreeMap<String, Vec<String>>>,
    ) -> Result<VerifiedApiKey, AuthError> {
        let stored = self
            .store
            .find_api_key_by_hash(&hash_key(key))
            .await?
            .ok_or(ApiKeyError::Invalid)?;
        if expected_config_id.is_some_and(|expected| stored.config_id != expected) {
            return Err(ApiKeyError::Invalid.into());
        }
        let configuration = configurations
            .iter()
            .find(|config| config.config_id == stored.config_id)
            .ok_or(ApiKeyError::Invalid)?;
        if !stored.enabled {
            return Err(ApiKeyError::Disabled.into());
        }
        if stored
            .expires_at
            .is_some_and(|expires_at| expires_at < Utc::now())
        {
            self.store.delete_api_key(&stored.id).await?;
            return Err(ApiKeyError::Expired.into());
        }
        if permissions.is_some_and(|required| !permits_all(&stored, required)) {
            return Err(ApiKeyError::PermissionDenied.into());
        }
        let api_key = match self
            .store
            .record_api_key_use(&stored.id, Utc::now())
            .await?
        {
            ApiKeyUseOutcome::Allowed(api_key) => *api_key,
            ApiKeyUseOutcome::Invalid => return Err(ApiKeyError::Invalid.into()),
            ApiKeyUseOutcome::UsageExceeded => {
                if stored.refill_amount.is_none() {
                    self.store.delete_api_key(&stored.id).await?;
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
        let user = if configuration.reference == ApiKeyReference::User {
            Some(
                self.store
                    .find_user_by_id(&api_key.reference_id)
                    .await?
                    .ok_or(ApiKeyError::Invalid)?,
            )
        } else {
            None
        };
        Ok(VerifiedApiKey { api_key, user })
    }

    pub async fn delete_expired_api_keys(&self) -> Result<u64, AuthError> {
        self.store.delete_expired_api_keys(Utc::now()).await
    }

    async fn owned_api_key(
        &self,
        actor: &SessionWithUser,
        config: &ApiKeyConfiguration,
        api_key_id: &str,
        action: &str,
    ) -> Result<ApiKey, AuthError> {
        let api_key = self
            .store
            .find_api_key(api_key_id)
            .await?
            .filter(|api_key| api_key.config_id == config.config_id)
            .ok_or(ApiKeyError::NotFound)?;
        match config.reference {
            ApiKeyReference::User if api_key.reference_id != actor.user.id => {
                Err(ApiKeyError::NotFound.into())
            }
            ApiKeyReference::Organization => {
                let organization_id = api_key
                    .reference_id
                    .parse()
                    .map_err(|_| ApiKeyError::NotFound)?;
                self.authorize_organization_api_key(actor, organization_id, action)
                    .await?;
                Ok(api_key)
            }
            ApiKeyReference::User => Ok(api_key),
        }
    }

    async fn authorize_organization_api_key(
        &self,
        actor: &SessionWithUser,
        organization_id: Uuid,
        action: &str,
    ) -> Result<(), AuthError> {
        let plugin = self
            .plugins
            .find::<crate::OrganizationPlugin>()
            .ok_or(ApiKeyError::OrganizationPluginRequired)?;
        let member = plugin
            .store
            .find_member(organization_id, &actor.user.id)
            .await?
            .ok_or(ApiKeyError::UserNotOrganizationMember)?;
        let required = BTreeMap::from([("apiKey".into(), vec![action.into()])]);
        if self
            .organization_has_permission(&member, &required, true)
            .await?
        {
            Ok(())
        } else {
            Err(ApiKeyError::InsufficientOrganizationPermission.into())
        }
    }
}

async fn generate_key(
    config: &ApiKeyConfiguration,
    requested_prefix: Option<&str>,
) -> Result<String, AuthError> {
    let prefix = requested_prefix.or(config.default_prefix.as_deref());
    if let Some(generator) = &config.key_generator {
        return generator.generate(config.default_key_length, prefix).await;
    }
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let mut rng = rand::rng();
    let value: String = (0..config.default_key_length)
        .map(|_| ALPHABET[rng.random_range(0..ALPHABET.len())] as char)
        .collect();
    Ok(format!("{}{value}", prefix.unwrap_or_default()))
}

fn hash_key(key: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(key.as_bytes()))
}
