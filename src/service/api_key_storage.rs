use super::{AuthService, api_key_usage};
use crate::{
    ApiKey, ApiKeyConfiguration, ApiKeyError, ApiKeySecondaryStorage, ApiKeySecondaryStorageMode,
    ApiKeyStorage, ApiKeyUseOutcome, AuthError, DatabaseCreate,
};
use chrono::Utc;

impl AuthService {
    pub(super) async fn create_api_key_record(
        &self,
        config: &ApiKeyConfiguration,
        create: DatabaseCreate<ApiKey>,
    ) -> Result<ApiKey, AuthError> {
        match config.storage {
            ApiKeyStorage::Database => self.store.create_api_key(create).await,
            ApiKeyStorage::SecondaryStorage if config.fallback_to_database => {
                let api_key = self.store.create_api_key(create).await?;
                self.api_key_secondary(config)?.set(&api_key).await?;
                Ok(api_key)
            }
            ApiKeyStorage::SecondaryStorage => {
                let mut api_key = create.record;
                api_key.id = self.generate_special_database_id(
                    "apikey",
                    super::context_id::ContextIdFallback::Falsey,
                    32.0,
                )?;
                self.api_key_secondary(config)?.set(&api_key).await?;
                Ok(api_key)
            }
        }
    }

    pub(super) async fn find_api_key_record(
        &self,
        config: &ApiKeyConfiguration,
        id: &str,
    ) -> Result<Option<ApiKey>, AuthError> {
        match config.storage {
            ApiKeyStorage::Database => self.store.find_api_key(id).await,
            ApiKeyStorage::SecondaryStorage if config.fallback_to_database => {
                if let Some(secondary) = self.optional_api_key_secondary(config)
                    && let Some(api_key) = secondary.get_by_id(id).await?
                {
                    Ok(Some(api_key))
                } else {
                    let api_key = self.store.find_api_key(id).await?;
                    if let (Some(api_key), Some(secondary)) =
                        (&api_key, self.optional_api_key_secondary(config))
                    {
                        secondary.set(api_key).await?;
                    }
                    Ok(api_key)
                }
            }
            ApiKeyStorage::SecondaryStorage => match self.optional_api_key_secondary(config) {
                Some(secondary) => secondary.get_by_id(id).await,
                None => Ok(None),
            },
        }
    }

    pub(super) async fn find_api_key_record_by_hash(
        &self,
        config: &ApiKeyConfiguration,
        hash: &str,
    ) -> Result<Option<ApiKey>, AuthError> {
        match config.storage {
            ApiKeyStorage::Database => self.store.find_api_key_by_hash(hash).await,
            ApiKeyStorage::SecondaryStorage if config.fallback_to_database => {
                if let Some(secondary) = self.optional_api_key_secondary(config)
                    && let Some(api_key) = secondary.get_by_hash(hash).await?
                {
                    Ok(Some(api_key))
                } else {
                    let api_key = self.store.find_api_key_by_hash(hash).await?;
                    if let (Some(api_key), Some(secondary)) =
                        (&api_key, self.optional_api_key_secondary(config))
                    {
                        secondary.set(api_key).await?;
                    }
                    Ok(api_key)
                }
            }
            ApiKeyStorage::SecondaryStorage => match self.optional_api_key_secondary(config) {
                Some(secondary) => secondary.get_by_hash(hash).await,
                None => Ok(None),
            },
        }
    }

    pub(super) async fn list_api_key_records(
        &self,
        config: &ApiKeyConfiguration,
        reference_id: &str,
        config_id: Option<&str>,
    ) -> Result<Vec<ApiKey>, AuthError> {
        match config.storage {
            ApiKeyStorage::Database => self.store.list_api_keys(reference_id, config_id).await,
            ApiKeyStorage::SecondaryStorage if config.fallback_to_database => {
                let secondary = self.optional_api_key_secondary(config);
                let cached = match &secondary {
                    Some(secondary) => secondary.list_by_reference(reference_id).await?,
                    None => Vec::new(),
                };
                if !cached.is_empty() {
                    Ok(filter_config(cached, config_id))
                } else {
                    let records = self.store.list_api_keys(reference_id, config_id).await?;
                    if let Some(secondary) = secondary
                        && !records.is_empty()
                    {
                        for api_key in &records {
                            secondary.set(api_key).await?;
                        }
                        let ids = records
                            .iter()
                            .map(|api_key| api_key.id.clone())
                            .collect::<Vec<_>>();
                        secondary.cache_reference_ids(reference_id, &ids).await?;
                    }
                    Ok(records)
                }
            }
            ApiKeyStorage::SecondaryStorage => match self.optional_api_key_secondary(config) {
                Some(secondary) => Ok(filter_config(
                    secondary.list_by_reference(reference_id).await?,
                    config_id,
                )),
                None => Ok(Vec::new()),
            },
        }
    }

    pub(super) async fn update_api_key_record(
        &self,
        config: &ApiKeyConfiguration,
        api_key: ApiKey,
    ) -> Result<Option<ApiKey>, AuthError> {
        match config.storage {
            ApiKeyStorage::Database => self.store.update_api_key(api_key).await,
            ApiKeyStorage::SecondaryStorage if config.fallback_to_database => {
                let updated = self.store.update_api_key(api_key).await?;
                if let Some(api_key) = &updated {
                    self.api_key_secondary(config)?.set(api_key).await?;
                }
                Ok(updated)
            }
            ApiKeyStorage::SecondaryStorage => {
                self.api_key_secondary(config)?.set(&api_key).await?;
                Ok(Some(api_key))
            }
        }
    }

    pub(super) async fn delete_api_key_record(
        &self,
        config: &ApiKeyConfiguration,
        api_key: &ApiKey,
    ) -> Result<bool, AuthError> {
        match config.storage {
            ApiKeyStorage::Database => self.store.delete_api_key(&api_key.id).await,
            ApiKeyStorage::SecondaryStorage if config.fallback_to_database => {
                self.api_key_secondary(config)?.delete(api_key).await?;
                self.store.delete_api_key(&api_key.id).await
            }
            ApiKeyStorage::SecondaryStorage => {
                self.api_key_secondary(config)?.delete(api_key).await?;
                Ok(true)
            }
        }
    }

    pub(super) async fn delete_invalid_api_key_record(
        &self,
        config: &ApiKeyConfiguration,
        api_key: &ApiKey,
    ) -> Result<(), AuthError> {
        if !config.defer_updates {
            self.delete_api_key_record(config, api_key).await?;
            return Ok(());
        }
        let store = self.store.clone();
        let secondary = self.optional_api_key_secondary(config);
        let fallback = config.fallback_to_database;
        let storage = config.storage;
        let api_key = api_key.clone();
        tokio::spawn(async move {
            let result = async {
                match storage {
                    ApiKeyStorage::Database => {
                        store.delete_api_key(&api_key.id).await?;
                    }
                    ApiKeyStorage::SecondaryStorage => {
                        secondary
                            .ok_or_else(missing_secondary_storage)?
                            .delete(&api_key)
                            .await?;
                        if fallback {
                            store.delete_api_key(&api_key.id).await?;
                        }
                    }
                }
                Ok::<_, AuthError>(())
            }
            .await;
            if let Err(error) = result {
                tracing::error!("Deferred update failed: {}", error);
            }
        });
        Ok(())
    }

    pub(super) async fn record_api_key_use_for_config(
        &self,
        config: &ApiKeyConfiguration,
        api_key: &ApiKey,
    ) -> Result<ApiKeyUseOutcome, AuthError> {
        if config.storage == ApiKeyStorage::Database || config.fallback_to_database {
            let outcome = self
                .store
                .record_api_key_use(&api_key.id, Utc::now(), config.rate_limit.enabled)
                .await?;
            if let ApiKeyUseOutcome::Allowed(updated) = &outcome
                && config.storage == ApiKeyStorage::SecondaryStorage
            {
                self.api_key_secondary(config)?.set(updated).await?;
            }
            return Ok(outcome);
        }

        let mutation = match api_key_usage::evaluate(api_key, config, Utc::now()) {
            Ok(mutation) => mutation,
            Err(AuthError::ApiKey(ApiKeyError::UsageExceeded)) => {
                return Ok(ApiKeyUseOutcome::UsageExceeded);
            }
            Err(AuthError::ApiKey(ApiKeyError::RateLimited {
                retry_after_milliseconds,
            })) => {
                return Ok(ApiKeyUseOutcome::RateLimited {
                    retry_after_milliseconds,
                });
            }
            Err(error) => return Err(error),
        };
        let mut optimistic = api_key.clone();
        mutation.clone().apply(&mut optimistic);
        let secondary = self.api_key_secondary(config)?;
        if config.defer_updates {
            let hash = api_key.key_hash.clone();
            tokio::spawn(async move {
                let update = async {
                    if let Some(mut fresh) = secondary.get_by_hash(&hash).await? {
                        mutation.apply(&mut fresh);
                        secondary.set(&fresh).await?;
                    }
                    Ok::<_, AuthError>(())
                };
                if let Err(error) = update.await {
                    tracing::error!(error = %error, "Failed to update API key");
                }
            });
            return Ok(ApiKeyUseOutcome::Allowed(Box::new(optimistic)));
        }
        let mut fresh = secondary
            .get_by_hash(&api_key.key_hash)
            .await?
            .ok_or(ApiKeyError::FailedToUpdate)?;
        mutation.apply(&mut fresh);
        secondary.set(&fresh).await?;
        Ok(ApiKeyUseOutcome::Allowed(Box::new(fresh)))
    }

    fn api_key_secondary(
        &self,
        config: &ApiKeyConfiguration,
    ) -> Result<ApiKeySecondaryStorage, AuthError> {
        let storage = self
            .secondary_storage_for_api_key(config)
            .ok_or_else(missing_secondary_storage)?;
        let mode = if config.fallback_to_database {
            ApiKeySecondaryStorageMode::DatabaseFallback
        } else {
            ApiKeySecondaryStorageMode::SecondaryOnly
        };
        Ok(ApiKeySecondaryStorage::new(storage, mode))
    }

    fn optional_api_key_secondary(
        &self,
        config: &ApiKeyConfiguration,
    ) -> Option<ApiKeySecondaryStorage> {
        let storage = self.secondary_storage_for_api_key(config)?;
        let mode = if config.fallback_to_database {
            ApiKeySecondaryStorageMode::DatabaseFallback
        } else {
            ApiKeySecondaryStorageMode::SecondaryOnly
        };
        Some(ApiKeySecondaryStorage::new(storage, mode))
    }

    fn secondary_storage_for_api_key(
        &self,
        config: &ApiKeyConfiguration,
    ) -> Option<std::sync::Arc<dyn crate::SecondaryStorage>> {
        config
            .custom_storage
            .clone()
            .or_else(|| self.secondary_storage())
    }

    pub(super) async fn migrate_api_key_metadata(
        &self,
        config: &ApiKeyConfiguration,
        mut api_key: ApiKey,
    ) -> ApiKey {
        if !parse_legacy_metadata(&mut api_key) {
            return api_key;
        }
        if (config.storage == ApiKeyStorage::Database || config.fallback_to_database)
            && let Err(error) = self.store.update_api_key(api_key.clone()).await
        {
            tracing::warn!(
                "Failed to migrate double-stringified metadata for API key {}: {}",
                api_key.id,
                error
            );
        }
        api_key
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn migrate_list_api_key_metadata(
        &self,
        configurations: &[ApiKeyConfiguration],
        api_keys: Vec<ApiKey>,
    ) -> Vec<ApiKey> {
        let mut migrated = Vec::with_capacity(api_keys.len());
        let mut updates = tokio::task::JoinSet::new();
        for mut api_key in api_keys {
            let config = configurations.iter().find(|config| {
                crate::api_key::config_ids_match(&config.config_id, &api_key.config_id)
            });
            let Some(config) = config else {
                continue;
            };
            if parse_legacy_metadata(&mut api_key)
                && (config.storage == ApiKeyStorage::Database || config.fallback_to_database)
            {
                let store = self.store.clone();
                let update = api_key.clone();
                updates.spawn(async move {
                    let id = update.id.clone();
                    (id, store.update_api_key(update).await)
                });
            }
            migrated.push(api_key);
        }
        while let Some(result) = updates.join_next().await {
            if let Ok((id, Err(error))) = result {
                tracing::warn!(
                    "Failed to migrate double-stringified metadata for API key {}: {}",
                    id,
                    error
                );
            }
        }
        migrated
    }
}

fn missing_secondary_storage() -> AuthError {
    AuthError::Storage(
        "Secondary storage is required when storage mode is 'secondary-storage'".into(),
    )
}

fn parse_legacy_metadata(api_key: &mut ApiKey) -> bool {
    let Some(serde_json::Value::String(encoded)) = api_key.metadata.as_ref() else {
        return false;
    };
    api_key.metadata = Some(serde_json::from_str(encoded).unwrap_or(serde_json::Value::Null));
    true
}

fn filter_config(records: Vec<ApiKey>, config_id: Option<&str>) -> Vec<ApiKey> {
    records
        .into_iter()
        .filter(|api_key| {
            config_id.is_none_or(|id| crate::api_key::config_ids_match(&api_key.config_id, id))
        })
        .collect()
}
