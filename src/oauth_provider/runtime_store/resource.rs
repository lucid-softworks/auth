use super::OAuthProviderRuntimeStore;
use crate::{AuthError, DatabaseIdSupplier, oauth_provider::*};
use async_trait::async_trait;

#[async_trait]
impl OAuthProviderResourceStore for OAuthProviderRuntimeStore {
    async fn find_oauth_resource(
        &self,
        identifier: &str,
    ) -> Result<Option<OAuthProviderResource>, AuthError> {
        self.ensure_resources_seeded().await?;
        if self.config.cached_resources.contains(identifier)
            && let Some(resource) = self.resource_cache.read().await.get(identifier).cloned()
        {
            return Ok(Some(resource));
        }
        let resource = self.inner.find_oauth_resource(identifier).await?;
        if self.config.cached_resources.contains(identifier)
            && let Some(resource) = &resource
        {
            self.resource_cache
                .write()
                .await
                .insert(identifier.to_owned(), resource.clone());
        }
        Ok(resource)
    }

    async fn list_oauth_resources(&self) -> Result<Vec<OAuthProviderResource>, AuthError> {
        self.ensure_resources_seeded().await?;
        self.inner.list_oauth_resources().await
    }

    async fn create_oauth_resource(
        &self,
        id: &dyn DatabaseIdSupplier,
        resource: OAuthProviderResource,
    ) -> Result<Option<OAuthProviderResource>, AuthError> {
        self.ensure_resources_seeded().await?;
        let identifier = resource.identifier.clone();
        let result = self.inner.create_oauth_resource(id, resource).await?;
        self.resource_cache.write().await.remove(&identifier);
        Ok(result)
    }

    async fn update_oauth_resource(
        &self,
        resource: OAuthProviderResource,
    ) -> Result<Option<OAuthProviderResource>, AuthError> {
        self.ensure_resources_seeded().await?;
        let identifier = resource.identifier.clone();
        let result = self.inner.update_oauth_resource(resource).await?;
        self.resource_cache.write().await.remove(&identifier);
        Ok(result)
    }

    async fn delete_oauth_resource(
        &self,
        identifier: &str,
    ) -> Result<Option<OAuthProviderResource>, AuthError> {
        self.ensure_resources_seeded().await?;
        let result = self.inner.delete_oauth_resource(identifier).await?;
        self.resource_cache.write().await.remove(identifier);
        Ok(result)
    }

    async fn list_oauth_client_resources(
        &self,
        client_id: &str,
    ) -> Result<Vec<OAuthProviderClientResource>, AuthError> {
        self.ensure_resources_seeded().await?;
        self.inner.list_oauth_client_resources(client_id).await
    }

    async fn link_oauth_client_resource(
        &self,
        id: &dyn DatabaseIdSupplier,
        link: OAuthProviderClientResource,
    ) -> Result<OAuthClientResourceLinkOutcome, AuthError> {
        self.ensure_resources_seeded().await?;
        self.inner.link_oauth_client_resource(id, link).await
    }

    async fn unlink_oauth_client_resource(
        &self,
        client_id: &str,
        resource_id: &str,
    ) -> Result<Option<OAuthProviderClientResource>, AuthError> {
        self.ensure_resources_seeded().await?;
        self.inner
            .unlink_oauth_client_resource(client_id, resource_id)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::sync::Arc;
    use uuid::Uuid;

    fn test_id() -> Result<crate::PreparedDatabaseId, AuthError> {
        Ok(crate::PreparedDatabaseId::Value(
            crate::DatabaseIdValue::String(Uuid::new_v4().to_string()),
        ))
    }

    fn resource(identifier: &str, name: &str) -> OAuthProviderResource {
        OAuthProviderResource {
            id: String::new(),
            identifier: identifier.into(),
            name: name.into(),
            access_token_ttl: None,
            refresh_token_ttl: None,
            signing_algorithm: None,
            signing_key_id: None,
            allowed_scopes: None,
            custom_claims: None,
            dpop_bound_access_tokens_required: false,
            disabled: false,
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            policy_version: 1,
            metadata: None,
        }
    }

    #[tokio::test]
    async fn configured_resource_cache_is_read_through_and_write_invalidated() {
        let identifier = "https://cached.example.com";
        let inner = Arc::new(MemoryOAuthProviderStore::new());
        let original = inner
            .create_oauth_resource(&test_id, resource(identifier, "original"))
            .await
            .unwrap()
            .unwrap();
        let mut config = OAuthProviderConfig::new("/login", "/consent");
        config.cached_resources.insert(identifier.into());
        let runtime = OAuthProviderRuntimeStore::new(Arc::new(config), inner.clone());

        assert_eq!(
            runtime
                .find_oauth_resource(identifier)
                .await
                .unwrap()
                .unwrap()
                .name,
            "original"
        );
        let mut external = original.clone();
        external.name = "external".into();
        inner.update_oauth_resource(external).await.unwrap();
        assert_eq!(
            runtime
                .find_oauth_resource(identifier)
                .await
                .unwrap()
                .unwrap()
                .name,
            "original"
        );

        let mut managed = original;
        managed.name = "managed".into();
        runtime.update_oauth_resource(managed).await.unwrap();
        assert_eq!(
            runtime
                .find_oauth_resource(identifier)
                .await
                .unwrap()
                .unwrap()
                .name,
            "managed"
        );

        runtime.delete_oauth_resource(identifier).await.unwrap();
        inner
            .create_oauth_resource(&test_id, resource(identifier, "recreated"))
            .await
            .unwrap();
        assert_eq!(
            runtime
                .find_oauth_resource(identifier)
                .await
                .unwrap()
                .unwrap()
                .name,
            "recreated"
        );
    }

    #[tokio::test]
    async fn resources_outside_cache_membership_are_always_reloaded() {
        let identifier = "https://uncached.example.com";
        let inner = Arc::new(MemoryOAuthProviderStore::new());
        let original = inner
            .create_oauth_resource(&test_id, resource(identifier, "original"))
            .await
            .unwrap()
            .unwrap();
        let runtime = OAuthProviderRuntimeStore::new(
            Arc::new(OAuthProviderConfig::new("/login", "/consent")),
            inner.clone(),
        );
        runtime.find_oauth_resource(identifier).await.unwrap();
        let mut external = original;
        external.name = "external".into();
        inner.update_oauth_resource(external).await.unwrap();
        assert_eq!(
            runtime
                .find_oauth_resource(identifier)
                .await
                .unwrap()
                .unwrap()
                .name,
            "external"
        );
    }
}
