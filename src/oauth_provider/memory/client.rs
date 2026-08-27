use super::{MemoryOAuthProviderStore, create_id};
use crate::{AuthError, DatabaseIdSupplier, oauth_provider::*};
use async_trait::async_trait;
use chrono::Utc;

#[async_trait]
impl OAuthProviderClientStore for MemoryOAuthProviderStore {
    async fn find_oauth_client(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuthProviderClient>, AuthError> {
        Ok(self.state.read().await.clients.get(client_id).cloned())
    }

    async fn list_oauth_clients(
        &self,
        user_id: Option<&str>,
        reference_id: Option<&str>,
    ) -> Result<Vec<OAuthProviderClient>, AuthError> {
        let mut clients = self
            .state
            .read()
            .await
            .clients
            .values()
            .filter(|client| {
                user_id.is_some_and(|user_id| client.user_id.as_deref() == Some(user_id))
                    || reference_id.is_some_and(|reference_id| {
                        client.reference_id.as_deref() == Some(reference_id)
                    })
                    || user_id.is_none() && reference_id.is_none()
            })
            .cloned()
            .collect::<Vec<_>>();
        clients.sort_by_key(|client| (client.created_at, client.client_id.clone()));
        Ok(clients)
    }

    async fn persist_oauth_client_registration(
        &self,
        client_id_supplier: &dyn DatabaseIdSupplier,
        link_id_supplier: &dyn DatabaseIdSupplier,
        mut write: OAuthClientRegistrationWrite,
    ) -> Result<OAuthClientRegistrationOutcome, AuthError> {
        let mut state = self.state.write().await;
        if let Some(missing) = write
            .resource_ids
            .iter()
            .find(|identifier| !state.resources.contains_key(*identifier))
        {
            return Ok(OAuthClientRegistrationOutcome::ResourceNotFound(
                missing.clone(),
            ));
        }

        let existing = state.clients.get(&write.client.client_id).cloned();
        let outcome = match (&write.mode, existing.as_ref()) {
            (OAuthClientRegistrationMode::Create, Some(_)) => {
                return Ok(OAuthClientRegistrationOutcome::ClientIdTaken);
            }
            (OAuthClientRegistrationMode::RefreshDiscovered { discovery_id }, Some(existing))
                if existing.client_discovery_id.as_deref() != Some(discovery_id) =>
            {
                return Ok(OAuthClientRegistrationOutcome::DiscoveryOwnershipChanged);
            }
            (OAuthClientRegistrationMode::RefreshDiscovered { discovery_id }, None)
                if write.client.client_discovery_id.as_deref() != Some(discovery_id) =>
            {
                return Ok(OAuthClientRegistrationOutcome::DiscoveryOwnershipChanged);
            }
            (OAuthClientRegistrationMode::RefreshDiscovered { .. }, Some(existing)) => {
                write.client.id = existing.id.clone();
                OAuthClientRegistrationOutcome::Updated(write.client.clone())
            }
            (_, None) => {
                write.client.id = create_id(&mut state, "oauthClient", client_id_supplier)?;
                OAuthClientRegistrationOutcome::Created(write.client.clone())
            }
        };

        let client_id = write.client.client_id.clone();
        let mut new_links = Vec::new();
        for resource_id in write.resource_ids {
            let key = (client_id.clone(), resource_id.clone());
            if !state.client_resources.contains_key(&key) {
                new_links.push((
                    key,
                    OAuthProviderClientResource {
                        id: create_id(&mut state, "oauthClientResource", link_id_supplier)?,
                        client_id: client_id.clone(),
                        resource_id,
                        metadata: None,
                        created_at: Some(Utc::now()),
                    },
                ));
            }
        }
        state.clients.insert(client_id.clone(), write.client);
        for (key, link) in new_links {
            state.client_resources.insert(key, link);
        }
        Ok(outcome)
    }

    async fn update_oauth_client(
        &self,
        client: OAuthProviderClient,
    ) -> Result<Option<OAuthProviderClient>, AuthError> {
        let mut state = self.state.write().await;
        let Some(existing) = state.clients.get(&client.client_id) else {
            return Ok(None);
        };
        if existing.id != client.id {
            return Ok(None);
        }
        state
            .clients
            .insert(client.client_id.clone(), client.clone());
        Ok(Some(client))
    }

    async fn delete_oauth_client(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuthProviderClient>, AuthError> {
        let mut state = self.state.write().await;
        if state
            .access_tokens
            .values()
            .any(|token| token.client_id == client_id)
            || state
                .refresh_tokens
                .values()
                .any(|token| token.client_id == client_id)
            || state
                .consents
                .values()
                .any(|consent| consent.client_id == client_id)
        {
            return Err(AuthError::Storage(
                "OAuth client is still referenced by grants or tokens".into(),
            ));
        }
        let removed = state.clients.remove(client_id);
        if removed.is_some() {
            state
                .client_resources
                .retain(|(linked_client_id, _), _| linked_client_id != client_id);
        }
        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(client_id: &str) -> OAuthProviderClient {
        OAuthProviderClient {
            id: String::new(),
            client_id: client_id.into(),
            client_secret: None,
            client_discovery_id: None,
            disabled: false,
            skip_consent: None,
            enable_end_session: None,
            subject_type: None,
            scopes: None,
            client_credentials_scopes: Vec::new(),
            user_id: None,
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            expires_at: None,
            name: None,
            uri: None,
            icon: None,
            contacts: None,
            tos: None,
            policy: None,
            software_id: None,
            software_version: None,
            software_statement: None,
            redirect_uris: vec!["https://client.example/callback".into()],
            post_logout_redirect_uris: None,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: None,
            token_endpoint_auth_method: Some("none".into()),
            application_type: Some("web".into()),
            jwks: None,
            jwks_uri: None,
            grant_types: Some(vec!["authorization_code".into()]),
            response_types: Some(vec!["code".into()]),
            require_pkce: None,
            dpop_bound_access_tokens: false,
            reference_id: None,
            metadata: None,
        }
    }

    #[tokio::test]
    async fn registration_does_not_partially_write_missing_resource_links() {
        let store = MemoryOAuthProviderStore::new();
        let unexpected_id = || -> Result<crate::PreparedDatabaseId, AuthError> {
            panic!("a rejected registration must not allocate an id")
        };
        let outcome = store
            .persist_oauth_client_registration(
                &unexpected_id,
                &unexpected_id,
                OAuthClientRegistrationWrite {
                    client: client("client"),
                    resource_ids: vec!["https://missing.example".into()],
                    mode: OAuthClientRegistrationMode::Create,
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            OAuthClientRegistrationOutcome::ResourceNotFound(_)
        ));
        assert!(store.find_oauth_client("client").await.unwrap().is_none());
    }
}
