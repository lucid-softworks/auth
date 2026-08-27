use super::{MemoryOAuthProviderStore, create_id};
use crate::{AuthError, DatabaseIdSupplier, oauth_provider::*};
use async_trait::async_trait;

#[async_trait]
impl OAuthProviderResourceStore for MemoryOAuthProviderStore {
    async fn find_oauth_resource(
        &self,
        identifier: &str,
    ) -> Result<Option<OAuthProviderResource>, AuthError> {
        Ok(self.state.read().await.resources.get(identifier).cloned())
    }

    async fn list_oauth_resources(&self) -> Result<Vec<OAuthProviderResource>, AuthError> {
        let mut resources = self
            .state
            .read()
            .await
            .resources
            .values()
            .cloned()
            .collect::<Vec<_>>();
        resources.sort_by(|left, right| left.identifier.cmp(&right.identifier));
        Ok(resources)
    }

    async fn create_oauth_resource(
        &self,
        id: &dyn DatabaseIdSupplier,
        mut resource: OAuthProviderResource,
    ) -> Result<Option<OAuthProviderResource>, AuthError> {
        let mut state = self.state.write().await;
        if state.resources.contains_key(&resource.identifier) {
            return Ok(None);
        }
        resource.id = create_id(&mut state, "oauthResource", id)?;
        state
            .resources
            .insert(resource.identifier.clone(), resource.clone());
        Ok(Some(resource))
    }

    async fn update_oauth_resource(
        &self,
        resource: OAuthProviderResource,
    ) -> Result<Option<OAuthProviderResource>, AuthError> {
        let mut state = self.state.write().await;
        let Some(existing) = state.resources.get(&resource.identifier) else {
            return Ok(None);
        };
        if existing.id != resource.id {
            return Ok(None);
        }
        state
            .resources
            .insert(resource.identifier.clone(), resource.clone());
        Ok(Some(resource))
    }

    async fn delete_oauth_resource(
        &self,
        identifier: &str,
    ) -> Result<Option<OAuthProviderResource>, AuthError> {
        let mut state = self.state.write().await;
        let removed = state.resources.remove(identifier);
        if removed.is_some() {
            state
                .client_resources
                .retain(|(_, resource_id), _| resource_id != identifier);
        }
        Ok(removed)
    }

    async fn list_oauth_client_resources(
        &self,
        client_id: &str,
    ) -> Result<Vec<OAuthProviderClientResource>, AuthError> {
        let mut links = self
            .state
            .read()
            .await
            .client_resources
            .values()
            .filter(|link| link.client_id == client_id)
            .cloned()
            .collect::<Vec<_>>();
        links.sort_by(|left, right| left.resource_id.cmp(&right.resource_id));
        Ok(links)
    }

    async fn link_oauth_client_resource(
        &self,
        id: &dyn DatabaseIdSupplier,
        mut link: OAuthProviderClientResource,
    ) -> Result<OAuthClientResourceLinkOutcome, AuthError> {
        let mut state = self.state.write().await;
        if !state.clients.contains_key(&link.client_id) {
            return Ok(OAuthClientResourceLinkOutcome::ClientNotFound);
        }
        if !state.resources.contains_key(&link.resource_id) {
            return Ok(OAuthClientResourceLinkOutcome::ResourceNotFound);
        }
        let key = (link.client_id.clone(), link.resource_id.clone());
        if let Some(existing) = state.client_resources.get(&key) {
            return Ok(OAuthClientResourceLinkOutcome::AlreadyLinked(
                existing.clone(),
            ));
        }
        link.id = create_id(&mut state, "oauthClientResource", id)?;
        state.client_resources.insert(key, link.clone());
        Ok(OAuthClientResourceLinkOutcome::Linked(link))
    }

    async fn unlink_oauth_client_resource(
        &self,
        client_id: &str,
        resource_id: &str,
    ) -> Result<Option<OAuthProviderClientResource>, AuthError> {
        Ok(self
            .state
            .write()
            .await
            .client_resources
            .remove(&(client_id.to_owned(), resource_id.to_owned())))
    }
}
