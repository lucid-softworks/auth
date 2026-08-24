use async_trait::async_trait;
use lucid_auth::{
    AuthError, AuthorizationRequest, GenericOAuthTokenExchange, GenericOAuthTokenRequest,
    GenericOAuthUserInfo, OAuthTokens, OAuthUserInfo, SocialProvider,
};
use serde_json::Value;
use url::Url;

pub(crate) struct ConformanceSocialProvider;

pub(crate) async fn register(config: &mut lucid_auth::AuthConfig) {
    config
        .add_social_provider(ConformanceSocialProvider)
        .expect("unique social provider");
    let mut generic = lucid_auth::GenericOAuthConfig::new(
        "generic-conformance",
        "generic-conformance-client",
    );
    generic.account_issuer = Some("https://generic.conformance.invalid".into());
    generic.authorization_url = Some("https://generic.conformance.invalid/authorize".into());
    generic.scopes = vec!["profile".into()];
    generic.get_token = Some(std::sync::Arc::new(GenericConformanceToken));
    generic.get_user_info = Some(std::sync::Arc::new(GenericConformanceUser));
    config
        .add_plugin(
            lucid_auth::GenericOAuthPlugin::initialize(vec![generic])
                .await
                .expect("generic OAuth fixture initialization"),
        )
        .expect("unique generic OAuth plugin");
}

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

    fn supports_id_token_sign_in(&self) -> bool {
        true
    }

    fn supports_token_refresh(&self) -> bool {
        true
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
        tokens: &OAuthTokens,
        expected_nonce: Option<&str>,
        _provider_user: Option<&Value>,
    ) -> Result<OAuthUserInfo, AuthError> {
        if tokens.id_token.as_deref() == Some("official-link-id-token") {
            if expected_nonce.is_some_and(|nonce| nonce != "official-link-nonce") {
                return Err(AuthError::OAuthInvalidToken);
            }
            return Ok(OAuthUserInfo {
                account_id: "official-linked-subject".into(),
                issuer: "https://issuer.conformance.invalid".into(),
                name: "Luna Linked".into(),
                email: "luna@example.com".into(),
                email_verified: true,
                image: Some("https://provider.conformance.invalid/linked.png".into()),
                additional_fields: serde_json::Map::new(),
                profile: serde_json::Map::from_iter([(
                    "fixture".into(),
                    Value::String("linked-account".into()),
                )]),
            });
        }
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
            additional_fields: serde_json::Map::new(),
            profile: serde_json::Map::new(),
        })
    }

    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuthTokens, AuthError> {
        if !matches!(
            refresh_token,
            "official-link-refresh-token" | "official-refreshed-refresh-token"
        ) {
            return Err(AuthError::OAuthInvalidToken);
        }
        Ok(OAuthTokens {
            access_token: Some("official-refreshed-access-token".into()),
            refresh_token: Some("official-refreshed-refresh-token".into()),
            access_token_expires_at: Some(chrono::Utc::now() + chrono::Duration::hours(1)),
            ..OAuthTokens::default()
        })
    }
}

pub(crate) struct GenericConformanceToken;

#[async_trait]
impl GenericOAuthTokenExchange for GenericConformanceToken {
    async fn exchange(&self, request: GenericOAuthTokenRequest) -> Result<OAuthTokens, AuthError> {
        if request.code != "generic-official-code"
            || request.code_verifier.as_deref().is_none_or(|value| value.len() != 128)
            || !request
                .redirect_uri
                .ends_with("/api/auth/callback/generic-conformance")
        {
            return Err(AuthError::OAuthInvalidCode);
        }
        Ok(OAuthTokens {
            access_token: Some("generic-official-access".into()),
            refresh_token: Some("generic-official-refresh".into()),
            scopes: vec!["profile".into(), "email".into()],
            ..OAuthTokens::default()
        })
    }
}

pub(crate) struct GenericConformanceUser;

#[async_trait]
impl GenericOAuthUserInfo for GenericConformanceUser {
    async fn user_info(&self, tokens: &OAuthTokens) -> Result<Option<Value>, AuthError> {
        if tokens.access_token.as_deref() != Some("generic-official-access") {
            return Ok(None);
        }
        Ok(Some(serde_json::json!({
            "id": "generic-official-subject",
            "name": "Generic Official User",
            "email": "generic-official@example.com",
            "emailVerified": true,
            "image": "https://generic.conformance.invalid/avatar.png"
        })))
    }
}
