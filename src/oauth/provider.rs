use crate::AuthError;
use async_trait::async_trait;
use chrono::{Duration, Utc};
use serde_json::Value;
use std::collections::BTreeMap;
use url::Url;

const RESERVED_AUTHORIZATION_PARAMETERS: [&str; 9] = [
    "state",
    "client_id",
    "redirect_uri",
    "response_type",
    "response_mode",
    "code_challenge",
    "code_challenge_method",
    "nonce",
    "scope",
];

pub(crate) fn authorization_parameter_is_reserved(name: &str) -> bool {
    RESERVED_AUTHORIZATION_PARAMETERS.contains(&name)
}

#[derive(Debug, Clone)]
pub struct AuthorizationRequest {
    pub state: String,
    pub code_verifier: String,
    pub id_token_nonce: Option<String>,
    pub redirect_uri: String,
    pub scopes: Option<Vec<String>>,
    pub login_hint: Option<String>,
    pub additional_params: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default)]
pub struct OAuthTokens {
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub id_token: Option<String>,
    pub access_token_expires_at: Option<chrono::DateTime<Utc>>,
    pub refresh_token_expires_at: Option<chrono::DateTime<Utc>>,
    pub scopes: Vec<String>,
    pub extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone)]
pub struct OAuthUserInfo {
    pub account_id: String,
    pub issuer: String,
    pub name: String,
    pub email: String,
    pub email_verified: bool,
    pub image: Option<String>,
    pub profile: serde_json::Map<String, Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenEndpointAuth {
    ClientSecretPost,
    ClientSecretBasic,
    None,
}

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub jwks_url: String,
    pub issuers: Vec<String>,
    pub audiences: Vec<String>,
    pub algorithms: Vec<jsonwebtoken::Algorithm>,
    pub requires_nonce: bool,
    pub nonce_sha256_fallback: bool,
    pub maximum_age: Duration,
    /// Optional issuer template for multi-tenant tokens. `{tid}` is replaced
    /// with the signed token's tenant claim and compared exactly to `iss`.
    pub dynamic_issuer_template: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ProfileMap {
    pub subject: Vec<String>,
    pub issuer: Vec<String>,
    pub email: Vec<String>,
    pub name: Vec<String>,
    pub image: Vec<String>,
    pub email_verified: Vec<String>,
    pub profile_root: Option<String>,
    pub synthetic_email_domain: Option<String>,
    pub join_name_fields: bool,
    pub require_all_email_verified_fields: bool,
}

impl ProfileMap {
    pub fn oidc() -> Self {
        Self {
            subject: vec!["/sub".into()],
            issuer: vec!["/iss".into()],
            email: vec!["/email".into()],
            name: vec!["/name".into(), "/preferred_username".into()],
            image: vec!["/picture".into()],
            email_verified: vec!["/email_verified".into()],
            profile_root: None,
            synthetic_email_domain: None,
            join_name_fields: false,
            require_all_email_verified_fields: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OAuthProviderConfig {
    pub id: String,
    pub name: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub user_info_endpoint: Option<String>,
    pub issuer: Option<String>,
    pub scopes: Vec<String>,
    pub token_endpoint_auth: TokenEndpointAuth,
    pub authorization_client_id_parameter: String,
    pub token_client_id_parameter: String,
    pub scope_separator: String,
    pub use_pkce: bool,
    pub send_code_verifier: bool,
    pub response_type: String,
    pub response_mode: Option<String>,
    pub oidc: Option<OidcConfig>,
    pub profile: ProfileMap,
    pub disable_implicit_sign_up: bool,
    pub disable_sign_up: bool,
    pub require_email_verification: bool,
    /// Google hosted-domain restriction (`hd`). Ignored by providers that do
    /// not issue a hosted-domain claim.
    pub hosted_domain: Option<String>,
}

#[async_trait]
pub trait SocialProvider: Send + Sync {
    fn id(&self) -> &str;
    fn issuer(&self) -> Option<&str>;
    fn requires_id_token_nonce(&self) -> bool;
    fn disable_implicit_sign_up(&self) -> bool;
    fn disable_sign_up(&self) -> bool;
    fn require_email_verification(&self) -> bool;
    fn id_token_audiences(&self) -> &[String] {
        &[]
    }
    fn hosted_domain(&self) -> Option<&str> {
        None
    }
    fn supports_id_token_sign_in(&self) -> bool {
        false
    }
    fn supports_token_refresh(&self) -> bool {
        false
    }
    fn validate_configuration(&self) -> Result<(), AuthError> {
        Ok(())
    }

    fn create_authorization_url(&self, request: &AuthorizationRequest) -> Result<Url, AuthError>;

    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
        device_id: Option<&str>,
    ) -> Result<OAuthTokens, AuthError>;

    async fn get_user_info(
        &self,
        tokens: &OAuthTokens,
        expected_nonce: Option<&str>,
        provider_user: Option<&Value>,
    ) -> Result<OAuthUserInfo, AuthError>;

    async fn refresh_access_token(&self, _refresh_token: &str) -> Result<OAuthTokens, AuthError> {
        Err(AuthError::OAuthTokenRefreshNotSupported(self.id().into()))
    }
}
