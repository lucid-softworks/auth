use super::{
    AuthService,
    oauth::{SocialSignInInput, SocialSignInResult},
};
use crate::{AuthError, OAuthTokens};

impl AuthService {
    pub async fn sign_in_social(
        &self,
        input: SocialSignInInput,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SocialSignInResult, AuthError> {
        self.sign_in_social_with_source(input, ip_address, user_agent, None)
            .await
    }

    pub(crate) async fn sign_in_social_with_source(
        &self,
        input: SocialSignInInput,
        ip_address: Option<String>,
        user_agent: Option<String>,
        source: Option<crate::SessionWithUser>,
    ) -> Result<SocialSignInResult, AuthError> {
        let provider = self
            .social_provider(&input.provider)
            .ok_or(AuthError::OAuthProviderNotFound)?;
        if input
            .additional_params
            .keys()
            .any(|name| crate::oauth::authorization_parameter_is_reserved(name))
        {
            return Err(AuthError::InvalidRequest(
                "OAuth authorization parameters contain a reserved name".into(),
            ));
        }
        if input.id_token.is_some() {
            let result = self
                .sign_in_social_id_token(provider.as_ref(), input, ip_address, user_agent)
                .await?;
            if let (Some(source), SocialSignInResult::Session(session)) = (&source, &result) {
                self.complete_anonymous_upgrade(source, session).await?;
            }
            return Ok(result);
        }
        let anonymous_user_id = source
            .filter(|source| source.user.is_anonymous)
            .map(|source| source.user.id);
        self.start_social_authorization(provider.as_ref(), input, None, anonymous_user_id)
            .await
    }

    async fn sign_in_social_id_token(
        &self,
        provider: &dyn crate::SocialProvider,
        input: SocialSignInInput,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SocialSignInResult, AuthError> {
        if !provider.supports_id_token_sign_in() {
            return Err(AuthError::OAuthIdTokenNotSupported);
        }
        let id_token = input.id_token.ok_or(AuthError::OAuthInvalidToken)?;
        let tokens = OAuthTokens {
            access_token: id_token.access_token,
            refresh_token: id_token.refresh_token,
            id_token: Some(id_token.token),
            access_token_expires_at: None,
            ..OAuthTokens::default()
        };
        let user_info = provider
            .get_user_info(&tokens, id_token.nonce.as_deref(), id_token.user.as_ref())
            .await?;
        let (session, _) = self
            .finish_oauth_sign_in(
                provider,
                tokens,
                user_info,
                input.request_sign_up,
                ip_address,
                user_agent,
            )
            .await?;
        Ok(SocialSignInResult::Session(Box::new(session)))
    }
}
