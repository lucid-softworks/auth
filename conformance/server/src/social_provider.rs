use async_trait::async_trait;
use lucid_auth::{
    AuthError, AuthorizationRequest, OAuthTokens, OAuthUserInfo, SocialProvider,
};
use serde_json::Value;
use url::Url;

pub(crate) struct ConformanceSocialProvider;

#[async_trait]
impl SocialProvider for ConformanceSocialProvider {
    fn id(&self) -> &str {
        "conformance-oauth"
    }

    fn issuer(&self) -> Option<&str> {
        Some("https://issuer.conformance.invalid")
    }

    fn requires_id_token_nonce(&self) -> bool {
        true
    }

    fn disable_implicit_sign_up(&self) -> bool {
        false
    }

    fn disable_sign_up(&self) -> bool {
        false
    }

    fn require_email_verification(&self) -> bool {
        false
    }

    fn create_authorization_url(
        &self,
        request: &AuthorizationRequest,
    ) -> Result<Url, AuthError> {
        let mut url = Url::parse("https://provider.conformance.invalid/authorize").unwrap();
        url.query_pairs_mut()
            .append_pair("state", &request.state)
            .append_pair("redirect_uri", &request.redirect_uri)
            .append_pair("code_challenge_method", "S256")
            .append_pair("nonce", request.id_token_nonce.as_deref().unwrap());
        Ok(url)
    }

    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
        _device_id: Option<&str>,
    ) -> Result<OAuthTokens, AuthError> {
        if code != "official-client-code"
            || code_verifier.len() != 128
            || !redirect_uri.ends_with("/api/auth/callback/conformance-oauth")
        {
            return Err(AuthError::OAuthInvalidCode);
        }
        Ok(OAuthTokens {
            access_token: Some("official-client-access-token".into()),
            refresh_token: Some("official-client-refresh-token".into()),
            scopes: vec!["openid".into(), "email".into()],
            ..OAuthTokens::default()
        })
    }

    async fn get_user_info(
        &self,
        _tokens: &OAuthTokens,
        expected_nonce: Option<&str>,
        _provider_user: Option<&Value>,
    ) -> Result<OAuthUserInfo, AuthError> {
        if expected_nonce.is_none() {
            return Err(AuthError::OAuthInvalidToken);
        }
        Ok(OAuthUserInfo {
            account_id: "official-client-subject".into(),
            issuer: "https://issuer.conformance.invalid".into(),
            name: "Official Social User".into(),
            email: "official-social@example.com".into(),
            email_verified: true,
            image: Some("https://provider.conformance.invalid/avatar.png".into()),
            profile: serde_json::Map::new(),
        })
    }
}
