use super::AuthService;
use crate::{AuthError, AuthSession, AuthUser};
use chrono::Utc;

impl AuthService {
    pub(crate) fn oauth_provider_plugin(&self) -> Option<&crate::OAuthProviderPlugin> {
        self.plugins.oauth_provider()
    }

    pub(crate) fn oauth_provider_extensions(
        &self,
    ) -> Vec<std::sync::Arc<dyn crate::OAuthProviderExtension>> {
        self.plugins
            .plugins()
            .iter()
            .flat_map(|plugin| plugin.oauth_provider_extensions())
            .collect()
    }

    pub(crate) async fn auth_user_by_id(
        &self,
        user_id: &str,
    ) -> Result<Option<AuthUser>, AuthError> {
        self.store.find_user_by_id(user_id).await
    }

    pub(crate) async fn auth_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<AuthUser>, AuthError> {
        self.store.find_user_by_email(email).await
    }

    pub(crate) async fn oauth_provider_session_by_id(
        &self,
        session_id: &str,
    ) -> Result<Option<AuthSession>, AuthError> {
        Ok(self
            .find_stored_session_by_id(session_id)
            .await?
            .map(|(_, session)| session)
            .filter(|session| session.expires_at > Utc::now()))
    }

    pub(crate) fn encrypt_oauth_provider_secret(&self, plaintext: &[u8]) -> Result<String, ()> {
        crate::symmetric_crypto::encrypt_versioned(
            &self.config.secret,
            self.config.versioned_secrets(),
            plaintext,
        )
    }

    pub(crate) fn decrypt_oauth_provider_secret(&self, envelope: &str) -> Result<Vec<u8>, ()> {
        crate::symmetric_crypto::decrypt_versioned(
            &self.config.secret,
            self.config.versioned_secrets(),
            self.config.legacy_secret(),
            envelope,
        )
    }

    pub(crate) fn configured_base_url(&self) -> Option<&url::Url> {
        self.config.base_url()
    }

    pub(crate) fn sign_oauth_provider_value(&self, value: &[u8]) -> String {
        self.sign(value)
    }
}
