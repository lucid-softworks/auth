use super::OAuthProviderRuntimeStore;
use crate::{AuthError, DatabaseIdSupplier, oauth_provider::*};
use async_trait::async_trait;
use chrono::Utc;
#[cfg(test)]
use uuid::Uuid;

#[async_trait]
impl OAuthProviderClientStore for OAuthProviderRuntimeStore {
    async fn find_oauth_client(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuthProviderClient>, AuthError> {
        if self.config.cached_trusted_clients.contains(client_id) {
            let cached = self.client_cache.read().await.get(client_id).cloned();
            if let Some(client) = cached {
                if client
                    .expires_at
                    .is_none_or(|expires| expires >= Utc::now())
                    && client.client_discovery_id.is_none()
                {
                    return Ok(Some(client));
                }
                self.client_cache.write().await.remove(client_id);
            }
        }
        let client = self.inner.find_oauth_client(client_id).await?;
        if self.config.cached_trusted_clients.contains(client_id)
            && let Some(client) = client
                .as_ref()
                .filter(|client| client.client_discovery_id.is_none())
        {
            self.client_cache
                .write()
                .await
                .insert(client_id.to_owned(), client.clone());
        }
        Ok(client)
    }

    async fn list_oauth_clients(
        &self,
        user_id: Option<&str>,
        reference_id: Option<&str>,
    ) -> Result<Vec<OAuthProviderClient>, AuthError> {
        self.inner.list_oauth_clients(user_id, reference_id).await
    }

    async fn persist_oauth_client_registration(
        &self,
        client_id_supplier: &dyn DatabaseIdSupplier,
        link_id_supplier: &dyn DatabaseIdSupplier,
        write: OAuthClientRegistrationWrite,
    ) -> Result<OAuthClientRegistrationOutcome, AuthError> {
        let client_id = write.client.client_id.clone();
        let outcome = self
            .inner
            .persist_oauth_client_registration(client_id_supplier, link_id_supplier, write)
            .await?;
        self.client_cache.write().await.remove(&client_id);
        Ok(outcome)
    }

    async fn update_oauth_client(
        &self,
        client: OAuthProviderClient,
    ) -> Result<Option<OAuthProviderClient>, AuthError> {
        let client_id = client.client_id.clone();
        let result = self.inner.update_oauth_client(client).await?;
        self.client_cache.write().await.remove(&client_id);
        Ok(result)
    }

    async fn delete_oauth_client(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuthProviderClient>, AuthError> {
        let result = self.inner.delete_oauth_client(client_id).await?;
        self.client_cache.write().await.remove(client_id);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use std::sync::Arc;

    fn test_id() -> Result<crate::PreparedDatabaseId, AuthError> {
        Ok(crate::PreparedDatabaseId::Value(
            crate::DatabaseIdValue::String(Uuid::new_v4().to_string()),
        ))
    }

    fn client(client_id: &str, expires_at: Option<chrono::DateTime<Utc>>) -> OAuthProviderClient {
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
            expires_at,
            name: Some("original".into()),
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

    async fn insert(
        store: &MemoryOAuthProviderStore,
        client: OAuthProviderClient,
    ) -> OAuthProviderClient {
        match store
            .persist_oauth_client_registration(
                &test_id,
                &test_id,
                OAuthClientRegistrationWrite {
                    client,
                    resource_ids: Vec::new(),
                    mode: OAuthClientRegistrationMode::Create,
                },
            )
            .await
            .unwrap()
        {
            OAuthClientRegistrationOutcome::Created(client) => client,
            outcome => panic!("expected a created client, got {outcome:?}"),
        }
    }

    #[tokio::test]
    async fn only_configured_trusted_clients_are_cached() {
        let inner = Arc::new(MemoryOAuthProviderStore::new());
        let trusted = insert(&inner, client("trusted", None)).await;
        let ordinary = insert(&inner, client("ordinary", None)).await;
        let mut config = OAuthProviderConfig::new("/login", "/consent");
        config.cached_trusted_clients.insert("trusted".into());
        let runtime = OAuthProviderRuntimeStore::new(Arc::new(config), inner.clone());
        runtime.find_oauth_client("trusted").await.unwrap();
        runtime.find_oauth_client("ordinary").await.unwrap();

        let mut changed = trusted;
        changed.name = Some("external trusted".into());
        inner.update_oauth_client(changed).await.unwrap();
        let mut changed = ordinary;
        changed.name = Some("external ordinary".into());
        inner.update_oauth_client(changed).await.unwrap();
        assert_eq!(
            runtime
                .find_oauth_client("trusted")
                .await
                .unwrap()
                .unwrap()
                .name,
            Some("original".into())
        );
        assert_eq!(
            runtime
                .find_oauth_client("ordinary")
                .await
                .unwrap()
                .unwrap()
                .name,
            Some("external ordinary".into())
        );
    }

    #[tokio::test]
    async fn trusted_client_cache_entries_expire_with_the_client_secret() {
        let inner = Arc::new(MemoryOAuthProviderStore::new());
        let original = insert(
            &inner,
            client("trusted", Some(Utc::now() + Duration::milliseconds(20))),
        )
        .await;
        let mut config = OAuthProviderConfig::new("/login", "/consent");
        config.cached_trusted_clients.insert("trusted".into());
        let runtime = OAuthProviderRuntimeStore::new(Arc::new(config), inner.clone());
        runtime.find_oauth_client("trusted").await.unwrap();
        let mut changed = original;
        changed.name = Some("reloaded".into());
        inner.update_oauth_client(changed).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert_eq!(
            runtime
                .find_oauth_client("trusted")
                .await
                .unwrap()
                .unwrap()
                .name,
            Some("reloaded".into())
        );
    }
}
