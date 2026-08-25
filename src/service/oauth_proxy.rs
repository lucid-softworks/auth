use super::{AuthService, SignInResult, oauth_identity::OAuthSignInPolicy};
use crate::{AuthError, OAuthTokens, OAuthUserInfo};
use chrono::Utc;

impl AuthService {
    pub(crate) fn oauth_proxy_plugin(&self) -> Option<&crate::OAuthProxyPlugin> {
        self.plugins.find::<crate::OAuthProxyPlugin>()
    }

    pub(crate) fn oauth_proxy_default_secret(&self) -> crate::OAuthProxySecret {
        if self.config.versioned_secrets().is_empty() {
            return crate::OAuthProxySecret::Plain(self.config.secret.clone());
        }
        crate::OAuthProxySecret::Versioned(crate::OAuthProxyVersionedSecret {
            current_version: self.config.versioned_secrets()[0].version,
            keys: self
                .config
                .versioned_secrets()
                .iter()
                .map(|secret| (secret.version, secret.value.clone()))
                .collect(),
            legacy_secret: self.config.legacy_secret().map(ToOwned::to_owned),
        })
    }

    pub(crate) fn oauth_proxy_default_error_url(&self) -> String {
        self.config.base_url.as_ref().map_or_else(
            || "/api/auth/error".into(),
            |url| format!("{}/api/auth/error", url.as_str().trim_end_matches('/')),
        )
    }

    pub(crate) async fn validate_and_consume_oauth_proxy_state(
        &self,
        state_token: &str,
        cookie_value: Option<&str>,
    ) -> Result<(), AuthError> {
        let state = self
            .oauth_state(state_token, cookie_value)
            .await
            .map_err(|_| AuthError::OAuthStateMismatch)?;
        if state.oauth_state.as_deref() != Some(state_token)
            || state.expires_at < Utc::now().timestamp_millis()
        {
            return Err(AuthError::OAuthStateMismatch);
        }
        self.consume_oauth_state(state_token)
            .await
            .map_err(|_| AuthError::OAuthStateMismatch)
    }

    pub(crate) async fn finish_oauth_proxy_sign_in(
        &self,
        provider_id: String,
        tokens: OAuthTokens,
        user_info: OAuthUserInfo,
        disable_sign_up: bool,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(SignInResult, bool), AuthError> {
        let require_email_verification = self
            .social_provider(&provider_id)
            .is_some_and(|provider| provider.require_email_verification());
        self.finish_oauth_sign_in_with_policy(
            &OAuthSignInPolicy {
                provider_id,
                disable_implicit_sign_up: false,
                disable_sign_up,
                require_email_verification,
                override_user_info: false,
            },
            tokens,
            user_info,
            false,
            ip_address,
            user_agent,
        )
        .await
    }
}
