use super::OAuthProviderRuntimeStore;
use crate::{AuthError, oauth_provider::*};
use chrono::{DateTime, Utc};
use serde_json::Value;
use std::sync::atomic::Ordering;
use url::Url;
use uuid::Uuid;

const RESOURCE_SIGNING_ALGORITHMS: &[&str] = &["EdDSA", "ES256", "ES512", "PS256", "RS256"];

impl OAuthProviderRuntimeStore {
    pub(super) async fn ensure_resources_seeded(&self) -> Result<(), AuthError> {
        if self.seed_complete.load(Ordering::Acquire) {
            return Ok(());
        }
        let _guard = self.seed_lock.lock().await;
        if self.seed_complete.load(Ordering::Acquire) {
            return Ok(());
        }
        self.seed_resources().await?;
        self.seed_complete.store(true, Ordering::Release);
        Ok(())
    }

    async fn seed_resources(&self) -> Result<(), AuthError> {
        for input in &self.config.resources {
            if !identifier_allowed(&self.config, &input.identifier).await? {
                continue;
            }
            self.seed_resource(input.clone()).await?;
        }
        Ok(())
    }

    async fn seed_resource(&self, input: OAuthResourceInput) -> Result<(), AuthError> {
        let existing = self.inner.find_oauth_resource(&input.identifier).await?;
        match (self.config.resource_seed_mode, existing) {
            (_, None) => {
                let resource = resource_from_input(input, Utc::now())?;
                self.inner.create_oauth_resource(resource).await?;
            }
            (OAuthResourceSeedMode::InsertOnly, Some(_)) => {}
            (OAuthResourceSeedMode::Merge, Some(existing)) => {
                let resource = merge_resource(existing, input, Utc::now())?;
                self.persist_seed_update(resource).await?;
            }
            (OAuthResourceSeedMode::Overwrite, Some(existing)) => {
                let mut resource = resource_from_input(input, Utc::now())?;
                resource.id = existing.id;
                resource.created_at = existing.created_at;
                self.persist_seed_update(resource).await?;
            }
        }
        Ok(())
    }

    async fn persist_seed_update(&self, resource: OAuthProviderResource) -> Result<(), AuthError> {
        let retry = resource.clone();
        if self.inner.update_oauth_resource(resource).await?.is_none() {
            self.inner.create_oauth_resource(retry).await?;
        }
        Ok(())
    }
}

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
        id: Uuid::new_v4(),
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

fn merge_resource(
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

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;

    fn input(identifier: &str) -> OAuthResourceInput {
        OAuthResourceInput {
            identifier: identifier.into(),
            name: None,
            access_token_ttl: None,
            refresh_token_ttl: None,
            signing_algorithm: None,
            signing_key_id: None,
            allowed_scopes: None,
            custom_claims: None,
            dpop_bound_access_tokens_required: None,
            disabled: None,
            metadata: None,
        }
    }

    fn existing(identifier: &str) -> OAuthProviderResource {
        OAuthProviderResource {
            id: Uuid::new_v4(),
            identifier: identifier.into(),
            name: "admin name".into(),
            access_token_ttl: Some(900),
            refresh_token_ttl: Some(1800),
            signing_algorithm: Some("RS256".into()),
            signing_key_id: Some("admin-key".into()),
            allowed_scopes: Some(vec!["admin".into()]),
            custom_claims: Some(serde_json::json!({"admin": true})),
            dpop_bound_access_tokens_required: true,
            disabled: true,
            created_at: Some(Utc::now() - chrono::Duration::days(1)),
            updated_at: Some(Utc::now() - chrono::Duration::days(1)),
            policy_version: 7,
            metadata: Some(serde_json::json!({"owner": "admin"})),
        }
    }

    fn runtime(
        mut config: OAuthProviderConfig,
        store: Arc<MemoryOAuthProviderStore>,
    ) -> OAuthProviderRuntimeStore {
        config.login_page = "/login".into();
        config.consent_page = "/consent".into();
        OAuthProviderRuntimeStore::new(Arc::new(config), store)
    }

    #[tokio::test]
    async fn insert_only_seeds_missing_resources_and_preserves_existing_rows() {
        let identifier = "https://api.example.com";
        let store = Arc::new(MemoryOAuthProviderStore::new());
        store
            .create_oauth_resource(existing(identifier))
            .await
            .unwrap();
        let mut configured = input(identifier);
        configured.name = Some("configured name".into());
        let mut second = input("https://new.example.com");
        second.access_token_ttl = Some(300);
        let mut config = OAuthProviderConfig::new("/login", "/consent");
        config.resources = vec![configured, second];
        let runtime = runtime(config, store);

        let resources = runtime.list_oauth_resources().await.unwrap();
        assert_eq!(resources.len(), 2);
        assert_eq!(
            runtime
                .find_oauth_resource(identifier)
                .await
                .unwrap()
                .unwrap()
                .name,
            "admin name"
        );
        assert_eq!(
            runtime
                .find_oauth_resource("https://new.example.com")
                .await
                .unwrap()
                .unwrap()
                .access_token_ttl,
            Some(300)
        );
    }

    #[tokio::test]
    async fn merge_updates_only_fields_present_in_config() {
        let identifier = "https://api.example.com";
        let store = Arc::new(MemoryOAuthProviderStore::new());
        let old = existing(identifier);
        store.create_oauth_resource(old.clone()).await.unwrap();
        let mut configured = input(identifier);
        configured.name = Some("configured name".into());
        configured.access_token_ttl = Some(300);
        configured.signing_algorithm = Some("unsupported".into());
        let mut config = OAuthProviderConfig::new("/login", "/consent");
        config.resources = vec![configured];
        config.resource_seed_mode = OAuthResourceSeedMode::Merge;
        let runtime = runtime(config, store);

        let merged = runtime
            .find_oauth_resource(identifier)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(merged.name, "configured name");
        assert_eq!(merged.access_token_ttl, Some(300));
        assert_eq!(merged.refresh_token_ttl, old.refresh_token_ttl);
        assert_eq!(merged.signing_algorithm, old.signing_algorithm);
        assert_eq!(merged.metadata, old.metadata);
        assert_eq!(merged.disabled, old.disabled);
        assert_eq!(merged.policy_version, 7);
    }

    #[tokio::test]
    async fn overwrite_replaces_omitted_policy_with_upstream_defaults() {
        let identifier = "https://api.example.com";
        let store = Arc::new(MemoryOAuthProviderStore::new());
        let old = existing(identifier);
        store.create_oauth_resource(old.clone()).await.unwrap();
        let mut config = OAuthProviderConfig::new("/login", "/consent");
        config.resources = vec![input(identifier)];
        config.resource_seed_mode = OAuthResourceSeedMode::Overwrite;
        let runtime = runtime(config, store);

        let replaced = runtime
            .find_oauth_resource(identifier)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(replaced.id, old.id);
        assert_eq!(replaced.created_at, old.created_at);
        assert_eq!(replaced.name, identifier);
        assert_eq!(replaced.access_token_ttl, None);
        assert_eq!(replaced.signing_algorithm, None);
        assert_eq!(replaced.metadata, None);
        assert!(!replaced.disabled);
        assert!(!replaced.dpop_bound_access_tokens_required);
        assert_eq!(replaced.policy_version, 1);
    }

    struct CountingValidator {
        calls: AtomicUsize,
        fail_first: bool,
    }

    #[async_trait]
    impl OAuthIdentifierValidator for CountingValidator {
        async fn validate(&self, _identifier: &str) -> Result<bool, AuthError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(10)).await;
            if self.fail_first && call == 0 {
                Err(AuthError::Storage("temporary validator failure".into()))
            } else {
                Ok(true)
            }
        }
    }

    #[tokio::test]
    async fn concurrent_seed_requests_coalesce_to_one_attempt() {
        let validator = Arc::new(CountingValidator {
            calls: AtomicUsize::new(0),
            fail_first: false,
        });
        let mut config = OAuthProviderConfig::new("/login", "/consent");
        config.resources = vec![input("urn:example:api")];
        config.callbacks.identifier_validator = Some(validator.clone());
        let runtime = Arc::new(runtime(config, Arc::new(MemoryOAuthProviderStore::new())));
        let (left, right) = tokio::join!(
            runtime.find_oauth_resource("urn:example:api"),
            runtime.find_oauth_resource("urn:example:api")
        );
        assert!(left.unwrap().is_some());
        assert!(right.unwrap().is_some());
        assert_eq!(validator.calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failed_seed_attempt_is_retried_on_the_next_resource_access() {
        let validator = Arc::new(CountingValidator {
            calls: AtomicUsize::new(0),
            fail_first: true,
        });
        let mut config = OAuthProviderConfig::new("/login", "/consent");
        config.resources = vec![input("urn:example:api")];
        config.callbacks.identifier_validator = Some(validator.clone());
        let runtime = runtime(config, Arc::new(MemoryOAuthProviderStore::new()));
        assert!(
            runtime
                .find_oauth_resource("urn:example:api")
                .await
                .is_err()
        );
        assert!(
            runtime
                .find_oauth_resource("urn:example:api")
                .await
                .unwrap()
                .is_some()
        );
        assert_eq!(validator.calls.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn default_identifier_validation_matches_better_auth_url_rules() {
        let config = OAuthProviderConfig::new("/login", "/consent");

        assert!(
            identifier_allowed(&config, "https://api.example.com")
                .await
                .unwrap()
        );
        assert!(
            identifier_allowed(&config, "urn:example:api")
                .await
                .unwrap()
        );
        assert!(
            identifier_allowed(&config, "https://api.example.com#")
                .await
                .unwrap()
        );
        assert!(
            !identifier_allowed(&config, "https://api.example.com#private")
                .await
                .unwrap()
        );
        assert!(!identifier_allowed(&config, "/relative").await.unwrap());
    }
}
