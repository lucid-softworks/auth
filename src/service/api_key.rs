use super::{
    AuthService,
    api_key_policy::{
        apply_update, normalize_permissions, permits_all, sort_api_keys, validate_create,
        validate_update,
    },
};
use crate::{
    ApiKey, ApiKeyConfiguration, ApiKeyError, ApiKeyUseOutcome, AuthError, IssuedApiKey, NewApiKey,
    SessionWithUser, VerifiedApiKey,
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
        mut input: NewApiKey,
    ) -> Result<IssuedApiKey, AuthError> {
        require_session(actor)?;
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
        let api_key = self
            .store
            .create_api_key(ApiKey {
                id: Uuid::new_v4(),
                config_id: config.config_id.clone(),
                name: input.name,
                start: config.starting_characters.store.then(|| {
                    key.chars()
                        .take(config.starting_characters.length)
                        .collect()
                }),
                prefix: input.prefix.or_else(|| config.default_prefix.clone()),
                key_hash: hash_key(&key),
                reference_id: actor.user.id.to_string(),
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
            })
            .await?;
        Ok(IssuedApiKey { api_key, key })
    }

    pub async fn get_api_key(
        &self,
        actor: &SessionWithUser,
        config_id: &str,
        api_key_id: Uuid,
    ) -> Result<ApiKey, AuthError> {
        require_session(actor)?;
        self.owned_api_key(actor, config_id, api_key_id).await
    }

    pub async fn list_api_keys(
        &self,
        actor: &SessionWithUser,
        config_id: Option<&str>,
        sort_by: Option<&str>,
        direction: ApiKeySortDirection,
    ) -> Result<Vec<ApiKey>, AuthError> {
        require_session(actor)?;
        let mut keys = self
            .store
            .list_api_keys(&actor.user.id.to_string(), config_id)
            .await?;
        if let Some(sort_by) = sort_by {
            sort_api_keys(&mut keys, sort_by, direction);
        }
        Ok(keys)
    }

    pub async fn update_api_key(
        &self,
        actor: &SessionWithUser,
        config: &ApiKeyConfiguration,
        api_key_id: Uuid,
        update: ApiKeyUpdate,
    ) -> Result<ApiKey, AuthError> {
        require_session(actor)?;
        let mut api_key = self
            .owned_api_key(actor, &config.config_id, api_key_id)
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
        config_id: &str,
        api_key_id: Uuid,
    ) -> Result<(), AuthError> {
        require_session(actor)?;
        self.owned_api_key(actor, config_id, api_key_id).await?;
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
        configurations
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
            self.store.delete_api_key(stored.id).await?;
            return Err(ApiKeyError::Expired.into());
        }
        if permissions.is_some_and(|required| !permits_all(&stored, required)) {
            return Err(ApiKeyError::PermissionDenied.into());
        }
        let api_key = match self.store.record_api_key_use(stored.id, Utc::now()).await? {
            ApiKeyUseOutcome::Allowed(api_key) => *api_key,
            ApiKeyUseOutcome::Invalid => return Err(ApiKeyError::Invalid.into()),
            ApiKeyUseOutcome::UsageExceeded => {
                if stored.refill_amount.is_none() {
                    self.store.delete_api_key(stored.id).await?;
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
        let user_id = api_key
            .reference_id
            .parse()
            .map_err(|_| ApiKeyError::Invalid)?;
        let user = self
            .store
            .find_user_by_id(user_id)
            .await?
            .filter(|user| !user.banned)
            .ok_or(ApiKeyError::Invalid)?;
        Ok(VerifiedApiKey { api_key, user })
    }

    pub async fn delete_expired_api_keys(&self) -> Result<u64, AuthError> {
        self.store.delete_expired_api_keys(Utc::now()).await
    }

    async fn owned_api_key(
        &self,
        actor: &SessionWithUser,
        config_id: &str,
        api_key_id: Uuid,
    ) -> Result<ApiKey, AuthError> {
        self.store
            .find_api_key(api_key_id)
            .await?
            .filter(|api_key| {
                api_key.reference_id == actor.user.id.to_string() && api_key.config_id == config_id
            })
            .ok_or_else(|| ApiKeyError::NotFound.into())
    }
}

fn require_session(actor: &SessionWithUser) -> Result<(), AuthError> {
    if actor.user.banned {
        return Err(ApiKeyError::UnauthorizedSession.into());
    }
    Ok(())
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
