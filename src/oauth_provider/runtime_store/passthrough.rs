use super::OAuthProviderRuntimeStore;
use crate::{AuthError, oauth_provider::*};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use uuid::Uuid;

#[async_trait]
impl OAuthProviderConsentStore for OAuthProviderRuntimeStore {
    async fn find_oauth_consent(
        &self,
        id: Uuid,
    ) -> Result<Option<OAuthProviderConsent>, AuthError> {
        self.inner.find_oauth_consent(id).await
    }

    async fn find_oauth_consent_for_grant(
        &self,
        client_id: &str,
        user_id: Uuid,
        reference_id: Option<&str>,
    ) -> Result<Option<OAuthProviderConsent>, AuthError> {
        self.inner
            .find_oauth_consent_for_grant(client_id, user_id, reference_id)
            .await
    }

    async fn list_oauth_consents(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<OAuthProviderConsent>, AuthError> {
        self.inner.list_oauth_consents(user_id).await
    }

    async fn upsert_oauth_consent(
        &self,
        consent: OAuthProviderConsent,
    ) -> Result<OAuthProviderConsent, AuthError> {
        self.inner.upsert_oauth_consent(consent).await
    }

    async fn delete_oauth_consent(
        &self,
        id: Uuid,
    ) -> Result<Option<OAuthProviderConsent>, AuthError> {
        self.inner.delete_oauth_consent(id).await
    }
}

#[async_trait]
impl OAuthProviderTokenStore for OAuthProviderRuntimeStore {
    async fn find_oauth_access_token(
        &self,
        token: &str,
    ) -> Result<Option<OAuthProviderAccessToken>, AuthError> {
        self.inner.find_oauth_access_token(token).await
    }

    async fn find_oauth_refresh_token(
        &self,
        token: &str,
    ) -> Result<Option<OAuthProviderRefreshToken>, AuthError> {
        self.inner.find_oauth_refresh_token(token).await
    }

    async fn issue_oauth_tokens(&self, issuance: OAuthTokenIssuance) -> Result<(), AuthError> {
        self.inner.issue_oauth_tokens(issuance).await
    }

    async fn rotate_oauth_refresh_token(
        &self,
        rotation: OAuthRefreshRotation,
    ) -> Result<OAuthRefreshRotationOutcome, AuthError> {
        self.inner.rotate_oauth_refresh_token(rotation).await
    }

    async fn store_oauth_refresh_rotation_replay(
        &self,
        refresh_id: Uuid,
        response: String,
    ) -> Result<bool, AuthError> {
        self.inner
            .store_oauth_refresh_rotation_replay(refresh_id, response)
            .await
    }

    async fn delete_oauth_access_token(
        &self,
        id: Uuid,
    ) -> Result<Option<OAuthProviderAccessToken>, AuthError> {
        self.inner.delete_oauth_access_token(id).await
    }

    async fn revoke_oauth_refresh_token(
        &self,
        id: Uuid,
        revoked_at: DateTime<Utc>,
    ) -> Result<bool, AuthError> {
        self.inner.revoke_oauth_refresh_token(id, revoked_at).await
    }

    async fn revoke_oauth_refresh_family(
        &self,
        client_id: &str,
        user_id: Uuid,
    ) -> Result<OAuthTokenRevocationCount, AuthError> {
        self.inner
            .revoke_oauth_refresh_family(client_id, user_id)
            .await
    }

    async fn revoke_oauth_tokens_for_authorization_code(
        &self,
        authorization_code_id: &str,
    ) -> Result<OAuthTokenRevocationCount, AuthError> {
        self.inner
            .revoke_oauth_tokens_for_authorization_code(authorization_code_id)
            .await
    }

    async fn revoke_oauth_tokens_for_session(
        &self,
        session_id: Uuid,
        revoked_at: DateTime<Utc>,
        preserve_offline_access: bool,
    ) -> Result<OAuthTokenRevocationCount, AuthError> {
        self.inner
            .revoke_oauth_tokens_for_session(session_id, revoked_at, preserve_offline_access)
            .await
    }

    async fn prepare_oauth_session_logout(
        &self,
        session_id: Uuid,
    ) -> Result<OAuthSessionLogoutPlan, AuthError> {
        self.inner.prepare_oauth_session_logout(session_id).await
    }

    async fn apply_oauth_session_logout(
        &self,
        plan: &OAuthSessionLogoutPlan,
        revoked_at: DateTime<Utc>,
    ) -> Result<OAuthTokenRevocationCount, AuthError> {
        self.inner
            .apply_oauth_session_logout(plan, revoked_at)
            .await
    }
}

#[async_trait]
impl OAuthProviderAssertionStore for OAuthProviderRuntimeStore {
    async fn reserve_oauth_client_assertion(
        &self,
        assertion: OAuthProviderClientAssertion,
    ) -> Result<bool, AuthError> {
        self.inner.reserve_oauth_client_assertion(assertion).await
    }

    async fn delete_expired_oauth_client_assertions(
        &self,
        now: DateTime<Utc>,
    ) -> Result<u64, AuthError> {
        self.inner.delete_expired_oauth_client_assertions(now).await
    }
}
