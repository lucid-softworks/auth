use super::{authorization, profile, token, types::GenericOAuthConfig};
use crate::{
    AuthError, AuthorizationRequest, OAuthRefreshContext, OAuthTokens, OAuthUserInfo, OidcConfig,
    SocialProvider,
};
use async_trait::async_trait;
use serde_json::Value;
use url::Url;

#[derive(Clone)]
pub(super) struct GenericOAuthProvider {
    pub(super) config: GenericOAuthConfig,
    name: String,
    pub(super) issuer: Option<String>,
    pub(super) is_oidc: bool,
    pub(super) oidc: Option<OidcConfig>,
}

impl GenericOAuthProvider {
    pub(super) fn new(
        config: GenericOAuthConfig,
        issuer: Option<String>,
        is_oidc: bool,
        oidc: Option<OidcConfig>,
    ) -> Self {
        let name = config
            .name
            .clone()
            .unwrap_or_else(|| config.provider_id.clone());
        Self {
            config,
            name,
            issuer,
            is_oidc,
            oidc,
        }
    }
}

#[async_trait]
impl SocialProvider for GenericOAuthProvider {
    fn id(&self) -> &str {
        &self.config.provider_id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    fn requires_id_token_nonce(&self) -> bool {
        self.oidc.as_ref().is_some_and(|oidc| oidc.requires_nonce)
    }

    fn disable_implicit_sign_up(&self) -> bool {
        self.config.disable_implicit_sign_up
    }

    fn disable_sign_up(&self) -> bool {
        self.config.disable_sign_up
    }

    fn require_email_verification(&self) -> bool {
        self.config.require_email_verification
    }

    fn override_user_info(&self) -> bool {
        self.config.override_user_info
    }

    fn allow_idp_initiated(&self) -> bool {
        self.config.allow_idp_initiated
    }

    fn supports_id_token_sign_in(&self) -> bool {
        self.oidc.is_some()
    }

    fn supports_token_refresh(&self) -> bool {
        true
    }

    fn validate_configuration(&self) -> Result<(), AuthError> {
        Ok(())
    }

    fn create_authorization_url(&self, request: &AuthorizationRequest) -> Result<Url, AuthError> {
        authorization::create_url(self, request)
    }

    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
        device_id: Option<&str>,
    ) -> Result<OAuthTokens, AuthError> {
        token::exchange_code(self, code, code_verifier, redirect_uri, device_id).await
    }

    async fn get_user_info(
        &self,
        tokens: &OAuthTokens,
        expected_nonce: Option<&str>,
        _provider_user: Option<&Value>,
    ) -> Result<OAuthUserInfo, AuthError> {
        profile::get_user_info(self, tokens, expected_nonce).await
    }

    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuthTokens, AuthError> {
        token::refresh(self, refresh_token, &OAuthRefreshContext::default()).await
    }

    async fn refresh_access_token_with_context(
        &self,
        refresh_token: &str,
        context: &OAuthRefreshContext,
    ) -> Result<OAuthTokens, AuthError> {
        token::refresh(self, refresh_token, context).await
    }

    async fn create_end_session_url(
        &self,
        id_token: Option<&str>,
        post_logout_redirect_uri: Option<&str>,
        state: Option<&str>,
        base_url: &Url,
    ) -> Result<Option<Url>, AuthError> {
        if self.config.disable_provider_logout {
            return Ok(None);
        }
        let Some(endpoint) = self.config.end_session_endpoint.as_deref() else {
            return Ok(None);
        };
        let mut url = Url::parse(endpoint).map_err(|_| {
            AuthError::InvalidConfiguration("invalid OAuth end-session endpoint".into())
        })?;
        if let Some(id_token) = id_token.filter(|token| !token.is_empty()) {
            set_query_pair(&mut url, "id_token_hint", id_token);
        }
        let configured_redirect = post_logout_redirect_uri
            .or(self.config.post_logout_redirect_uri.as_deref())
            .filter(|redirect| !redirect.is_empty());
        let redirect = configured_redirect
            .map(|redirect| base_url.join(redirect))
            .transpose()
            .map_err(|_| {
                AuthError::InvalidConfiguration("invalid post-logout redirect URI".into())
            })?;
        if let Some(redirect) = redirect {
            set_query_pair(&mut url, "post_logout_redirect_uri", redirect.as_str());
            set_query_pair(&mut url, "client_id", &self.config.client_id);
            if let Some(state) = state {
                set_query_pair(&mut url, "state", state);
            }
        } else if id_token.is_none_or(str::is_empty) {
            set_query_pair(&mut url, "client_id", &self.config.client_id);
        }
        Ok(Some(url))
    }
}

fn set_query_pair(url: &mut Url, name: &str, value: &str) {
    let mut pairs = url
        .query_pairs()
        .filter(|(key, _)| key != name)
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    pairs.push((name.into(), value.into()));
    url.set_query(None);
    url.query_pairs_mut().extend_pairs(pairs);
}
