use super::MemoryOAuthProviderStore;
use crate::{AuthError, oauth_provider::*};
use async_trait::async_trait;
use uuid::Uuid;

#[async_trait]
impl OAuthProviderConsentStore for MemoryOAuthProviderStore {
    async fn find_oauth_consent(
        &self,
        id: Uuid,
    ) -> Result<Option<OAuthProviderConsent>, AuthError> {
        Ok(self.state.read().await.consents.get(&id).cloned())
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
        consents.sort_by_key(|consent| (consent.created_at, consent.id));
        Ok(consents)
    }

    async fn upsert_oauth_consent(
        &self,
        consent: OAuthProviderConsent,
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
            .map(|existing| existing.id);
        let mut consent = consent;
        if let Some(existing_id) = existing_id {
            consent.id = existing_id;
        }
        state.consents.insert(consent.id, consent.clone());
        Ok(consent)
    }

    async fn delete_oauth_consent(
        &self,
        id: Uuid,
    ) -> Result<Option<OAuthProviderConsent>, AuthError> {
        Ok(self.state.write().await.consents.remove(&id))
    }
}
