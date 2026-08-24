use super::{
    AuthorizationRequest, OAuthProviderConfig, OAuthTokens, OAuthUserInfo, OidcConfig,
    SocialProvider,
};
use crate::AuthError;
use async_trait::async_trait;
use chrono::Duration;
use url::Url;

/// Better Auth 1.7.1's complete built-in social-provider vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BuiltinProviderKind {
    Apple,
    Atlassian,
    Cognito,
    Discord,
    Dropbox,
    Facebook,
    Figma,
    Github,
    Gitlab,
    Google,
    Huggingface,
    Kakao,
    Kick,
    Line,
    Linear,
    Linkedin,
    Microsoft,
    Naver,
    Notion,
    Paybin,
    Paypal,
    Polar,
    Railway,
    Reddit,
    Roblox,
    Salesforce,
    Slack,
    Spotify,
    Tiktok,
    Twitch,
    Twitter,
    Vercel,
    Vk,
    Wechat,
    Zoom,
}

impl BuiltinProviderKind {
    pub const ALL: [Self; 35] = [
        Self::Apple,
        Self::Atlassian,
        Self::Cognito,
        Self::Discord,
        Self::Dropbox,
        Self::Facebook,
        Self::Figma,
        Self::Github,
        Self::Gitlab,
        Self::Google,
        Self::Huggingface,
        Self::Kakao,
        Self::Kick,
        Self::Line,
        Self::Linear,
        Self::Linkedin,
        Self::Microsoft,
        Self::Naver,
        Self::Notion,
        Self::Paybin,
        Self::Paypal,
        Self::Polar,
        Self::Railway,
        Self::Reddit,
        Self::Roblox,
        Self::Salesforce,
        Self::Slack,
        Self::Spotify,
        Self::Tiktok,
        Self::Twitch,
        Self::Twitter,
        Self::Vercel,
        Self::Vk,
        Self::Wechat,
        Self::Zoom,
    ];

    pub const fn id(self) -> &'static str {
        match self {
            Self::Apple => "apple",
            Self::Atlassian => "atlassian",
            Self::Cognito => "cognito",
            Self::Discord => "discord",
            Self::Dropbox => "dropbox",
            Self::Facebook => "facebook",
            Self::Figma => "figma",
            Self::Github => "github",
            Self::Gitlab => "gitlab",
            Self::Google => "google",
            Self::Huggingface => "huggingface",
            Self::Kakao => "kakao",
            Self::Kick => "kick",
            Self::Line => "line",
            Self::Linear => "linear",
            Self::Linkedin => "linkedin",
            Self::Microsoft => "microsoft",
            Self::Naver => "naver",
            Self::Notion => "notion",
            Self::Paybin => "paybin",
            Self::Paypal => "paypal",
            Self::Polar => "polar",
            Self::Railway => "railway",
            Self::Reddit => "reddit",
            Self::Roblox => "roblox",
            Self::Salesforce => "salesforce",
            Self::Slack => "slack",
            Self::Spotify => "spotify",
            Self::Tiktok => "tiktok",
            Self::Twitch => "twitch",
            Self::Twitter => "twitter",
            Self::Vercel => "vercel",
            Self::Vk => "vk",
            Self::Wechat => "wechat",
            Self::Zoom => "zoom",
        }
    }
}

#[derive(Debug, Clone)]
pub struct BuiltinProvider {
    pub(crate) kind: BuiltinProviderKind,
    pub(crate) config: OAuthProviderConfig,
}

impl BuiltinProvider {
    pub fn new(
        kind: BuiltinProviderKind,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            config: super::builtin_catalog::provider_config(
                kind,
                client_id.into(),
                Some(client_secret.into()),
            ),
        }
    }

    pub fn public_client(kind: BuiltinProviderKind, client_id: impl Into<String>) -> Self {
        Self {
            kind,
            config: super::builtin_catalog::provider_config(kind, client_id.into(), None),
        }
    }

    pub fn kind(&self) -> BuiltinProviderKind {
        self.kind
    }

    pub fn config_mut(&mut self) -> &mut OAuthProviderConfig {
        &mut self.config
    }

    pub fn cognito(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        domain: &str,
        region: &str,
        user_pool_id: &str,
    ) -> Result<Self, AuthError> {
        let domain = domain
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .trim_end_matches('/');
        if domain.is_empty() || region.trim().is_empty() || user_pool_id.trim().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "Cognito requires domain, region, and user pool id".into(),
            ));
        }
        let mut provider = Self::new(BuiltinProviderKind::Cognito, client_id, client_secret);
        let issuer = format!("https://cognito-idp.{region}.amazonaws.com/{user_pool_id}");
        provider.config.authorization_endpoint = format!("https://{domain}/oauth2/authorize");
        provider.config.token_endpoint = format!("https://{domain}/oauth2/token");
        provider.config.user_info_endpoint = Some(format!("https://{domain}/oauth2/userinfo"));
        provider.config.issuer = Some(issuer.clone());
        provider.config.oidc = Some(oidc(
            &provider,
            format!("{issuer}/.well-known/jwks.json"),
            vec![issuer],
            None,
        ));
        Ok(provider)
    }

    pub fn gitlab(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        base_url: &str,
    ) -> Result<Self, AuthError> {
        let base = Url::parse(base_url)
            .map_err(|_| AuthError::InvalidConfiguration("GitLab issuer URL is invalid".into()))?;
        let mut provider = Self::new(BuiltinProviderKind::Gitlab, client_id, client_secret);
        let base = base.as_str().trim_end_matches('/');
        provider.config.authorization_endpoint = format!("{base}/oauth/authorize");
        provider.config.token_endpoint = format!("{base}/oauth/token");
        provider.config.user_info_endpoint = Some(format!("{base}/api/v4/user"));
        Ok(provider)
    }

    pub fn microsoft(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        tenant_id: &str,
    ) -> Result<Self, AuthError> {
        if tenant_id.trim().is_empty() || tenant_id.contains('/') {
            return Err(AuthError::InvalidConfiguration(
                "Microsoft tenant id is invalid".into(),
            ));
        }
        let mut provider = Self::new(BuiltinProviderKind::Microsoft, client_id, client_secret);
        let base = format!("https://login.microsoftonline.com/{tenant_id}");
        provider.config.authorization_endpoint = format!("{base}/oauth2/v2.0/authorize");
        provider.config.token_endpoint = format!("{base}/oauth2/v2.0/token");
        let issuers = if matches!(tenant_id, "common" | "organizations" | "consumers") {
            Vec::new()
        } else {
            vec![format!("{base}/v2.0")]
        };
        provider.config.oidc = Some(oidc(
            &provider,
            format!("{base}/discovery/v2.0/keys"),
            issuers,
            Some("https://login.microsoftonline.com/{tid}/v2.0".into()),
        ));
        Ok(provider)
    }

    pub fn map_profile_fixture(
        &self,
        profile: serde_json::Value,
    ) -> Result<OAuthUserInfo, AuthError> {
        super::map_profile(&self.config, profile)
    }
}

fn oidc(
    provider: &BuiltinProvider,
    jwks_url: String,
    issuers: Vec<String>,
    dynamic_issuer_template: Option<String>,
) -> OidcConfig {
    OidcConfig {
        jwks_url,
        issuers,
        audiences: vec![provider.config.client_id.clone()],
        algorithms: vec!["RS256".into()],
        requires_nonce: false,
        nonce_sha256_fallback: false,
        maximum_age: Some(Duration::hours(1)),
        dynamic_issuer_template,
    }
}

#[async_trait]
impl SocialProvider for BuiltinProvider {
    fn id(&self) -> &str {
        self.config.id()
    }
    fn issuer(&self) -> Option<&str> {
        self.config.issuer()
    }
    fn requires_id_token_nonce(&self) -> bool {
        self.config.requires_id_token_nonce()
    }
    fn disable_implicit_sign_up(&self) -> bool {
        self.config.disable_implicit_sign_up()
    }
    fn disable_sign_up(&self) -> bool {
        self.config.disable_sign_up()
    }
    fn require_email_verification(&self) -> bool {
        self.config.require_email_verification()
    }
    fn id_token_audiences(&self) -> &[String] {
        self.config.id_token_audiences()
    }
    fn hosted_domain(&self) -> Option<&str> {
        self.config.hosted_domain()
    }
    fn supports_id_token_sign_in(&self) -> bool {
        self.kind == BuiltinProviderKind::Line || self.config.supports_id_token_sign_in()
    }
    fn supports_token_refresh(&self) -> bool {
        true
    }
    fn validate_configuration(&self) -> Result<(), AuthError> {
        self.config.validate_configuration()?;
        if self.kind == BuiltinProviderKind::Cognito
            && self
                .config
                .authorization_endpoint
                .contains("CHANGE-ME.invalid")
        {
            return Err(AuthError::InvalidConfiguration(
                "configure Cognito with BuiltinProvider::cognito".into(),
            ));
        }
        Ok(())
    }
    fn create_authorization_url(&self, request: &AuthorizationRequest) -> Result<Url, AuthError> {
        super::builtin_http::authorization_url(self, request)
    }
    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
        device_id: Option<&str>,
    ) -> Result<OAuthTokens, AuthError> {
        super::builtin_http::exchange_code(self, code, code_verifier, redirect_uri, device_id).await
    }
    async fn get_user_info(
        &self,
        tokens: &OAuthTokens,
        expected_nonce: Option<&str>,
        provider_user: Option<&serde_json::Value>,
    ) -> Result<OAuthUserInfo, AuthError> {
        super::builtin_http::user_info(self, tokens, expected_nonce, provider_user).await
    }
    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuthTokens, AuthError> {
        super::builtin_http::refresh_access_token(self, refresh_token).await
    }
}
