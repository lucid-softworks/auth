use super::{MemoryOAuthProviderStore, create_id};
use crate::{AuthError, DatabaseIdSupplier, oauth_provider::*};
use async_trait::async_trait;

#[async_trait]
impl OAuthProviderConsentStore for MemoryOAuthProviderStore {
    async fn find_oauth_consent(
        &self,
        id: &str,
    ) -> Result<Option<OAuthProviderConsent>, AuthError> {
        Ok(self.state.read().await.consents.get(id).cloned())
    }

    async fn find_oauth_consent_for_grant(
        &self,
        client_id: &str,
        user_id: &str,
        reference_id: Option<&str>,
    ) -> Result<Option<OAuthProviderConsent>, AuthError> {
        Ok(self
            .state
            .read()
            .await
            .consents
            .values()
            .find(|consent| {
                consent.client_id == client_id
                    && consent.user_id.as_deref() == Some(user_id)
                    && consent.reference_id.as_deref() == reference_id
            })
            .cloned())
    }

    async fn list_oauth_consents(
        &self,
        user_id: &str,
    ) -> Result<Vec<OAuthProviderConsent>, AuthError> {
        let mut consents = self
            .state
            .read()
            .await
            .consents
            .values()
            .filter(|consent| consent.user_id.as_deref() == Some(user_id))
            .cloned()
            .collect::<Vec<_>>();
        consents.sort_by_key(|consent| (consent.created_at, consent.id.clone()));
        Ok(consents)
    }

    async fn upsert_oauth_consent(
        &self,
        id: &dyn DatabaseIdSupplier,
        mut consent: OAuthProviderConsent,
    ) -> Result<OAuthProviderConsent, AuthError> {
        let mut state = self.state.write().await;
        let existing_id = state
            .consents
            .values()
            .find(|existing| {
                existing.client_id == consent.client_id
                    && existing.user_id == consent.user_id
                    && existing.reference_id == consent.reference_id
            })
            .map(|existing| existing.id.clone());
        if let Some(existing_id) = existing_id {
            consent.id = existing_id;
        } else {
            consent.id = create_id(&mut state, "oauthConsent", id)?;
        }
        state.consents.insert(consent.id.clone(), consent.clone());
        Ok(consent)
    }

    async fn delete_oauth_consent(
        &self,
        id: &str,
    ) -> Result<Option<OAuthProviderConsent>, AuthError> {
        Ok(self.state.write().await.consents.remove(id))
    }
}
