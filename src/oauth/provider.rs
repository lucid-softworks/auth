use crate::AuthError;
use async_trait::async_trait;
use base64::Engine;
use chrono::{Duration, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use url::Url;

use super::provider_data::{map_profile, parse_token_response, verify_id_token};

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
}

#[async_trait]
pub trait SocialProvider: Send + Sync {
    fn id(&self) -> &str;
    fn issuer(&self) -> Option<&str>;
    fn requires_id_token_nonce(&self) -> bool;
    fn disable_implicit_sign_up(&self) -> bool;
    fn disable_sign_up(&self) -> bool;
    fn require_email_verification(&self) -> bool;
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

#[async_trait]
impl SocialProvider for OAuthProviderConfig {
    fn id(&self) -> &str {
        &self.id
    }

    fn issuer(&self) -> Option<&str> {
        self.issuer.as_deref()
    }

    fn requires_id_token_nonce(&self) -> bool {
        self.oidc.as_ref().is_some_and(|oidc| oidc.requires_nonce)
    }

    fn disable_implicit_sign_up(&self) -> bool {
        self.disable_implicit_sign_up
    }

    fn disable_sign_up(&self) -> bool {
        self.disable_sign_up
    }

    fn require_email_verification(&self) -> bool {
        self.require_email_verification
    }

    fn supports_id_token_sign_in(&self) -> bool {
        self.oidc.is_some()
    }

    fn supports_token_refresh(&self) -> bool {
        true
    }

    fn validate_configuration(&self) -> Result<(), AuthError> {
        if self.id.trim().is_empty() || self.client_id.trim().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "OAuth provider id and client id must not be empty".into(),
            ));
        }
        for (label, endpoint) in [
            ("authorization", self.authorization_endpoint.as_str()),
            ("token", self.token_endpoint.as_str()),
        ] {
            let url = Url::parse(endpoint).map_err(|_| {
                AuthError::InvalidConfiguration(format!(
                    "provider '{}' has an invalid {label} endpoint",
                    self.id
                ))
            })?;
            if !matches!(url.scheme(), "http" | "https") || url.host_str().is_none() {
                return Err(AuthError::InvalidConfiguration(format!(
                    "provider '{}' has an invalid {label} endpoint",
                    self.id
                )));
            }
        }
        Ok(())
    }

    fn create_authorization_url(&self, request: &AuthorizationRequest) -> Result<Url, AuthError> {
        let mut url = Url::parse(&self.authorization_endpoint).map_err(|_| {
            AuthError::InvalidConfiguration(format!(
                "provider '{}' has an invalid authorization endpoint",
                self.id
            ))
        })?;
        {
            let mut query = url.query_pairs_mut();
            query.append_pair(&self.authorization_client_id_parameter, &self.client_id);
            query.append_pair("redirect_uri", &request.redirect_uri);
            query.append_pair("response_type", &self.response_type);
            query.append_pair("state", &request.state);
            let mut scopes = self.scopes.clone();
            if let Some(requested) = &request.scopes {
                scopes.extend(requested.iter().cloned());
            }
            if !scopes.is_empty() {
                query.append_pair("scope", &scopes.join(&self.scope_separator));
            }
            if self.use_pkce {
                let challenge = Sha256::digest(request.code_verifier.as_bytes());
                query.append_pair(
                    "code_challenge",
                    &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
                );
                query.append_pair("code_challenge_method", "S256");
            }
            if let Some(nonce) = &request.id_token_nonce {
                query.append_pair("nonce", nonce);
            }
            if let Some(login_hint) = &request.login_hint {
                query.append_pair("login_hint", login_hint);
            }
            if let Some(response_mode) = &self.response_mode {
                query.append_pair("response_mode", response_mode);
            }
            for (name, value) in &request.additional_params {
                if !authorization_parameter_is_reserved(name) {
                    query.append_pair(name, value);
                }
            }
        }
        Ok(url)
    }

    async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
        device_id: Option<&str>,
    ) -> Result<OAuthTokens, AuthError> {
        let client = reqwest::Client::new();
        let mut form = vec![
            ("grant_type", "authorization_code".to_owned()),
            ("code", code.to_owned()),
            ("redirect_uri", redirect_uri.to_owned()),
            (&self.token_client_id_parameter, self.client_id.clone()),
        ];
        if self.send_code_verifier {
            form.push(("code_verifier", code_verifier.to_owned()));
        }
        if let Some(device_id) = device_id {
            form.push(("device_id", device_id.to_owned()));
        }
        if self.token_endpoint_auth == TokenEndpointAuth::ClientSecretPost
            && let Some(secret) = &self.client_secret
        {
            form.push(("client_secret", secret.clone()));
        }
        let encoded = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();
        let mut request = client
            .post(&self.token_endpoint)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(encoded);
        if self.token_endpoint_auth == TokenEndpointAuth::ClientSecretBasic {
            request = request.basic_auth(&self.client_id, self.client_secret.as_deref());
        }
        let response = request
            .send()
            .await
            .map_err(|_| AuthError::OAuthInvalidCode)?;
        if !response.status().is_success() {
            return Err(AuthError::OAuthInvalidCode);
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| AuthError::OAuthInvalidCode)?;
        let value: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            Value::Object(
                url::form_urlencoded::parse(&bytes)
                    .map(|(key, value)| (key.into_owned(), Value::String(value.into_owned())))
                    .collect(),
            )
        });
        parse_token_response(value)
    }

    async fn get_user_info(
        &self,
        tokens: &OAuthTokens,
        expected_nonce: Option<&str>,
        _provider_user: Option<&Value>,
    ) -> Result<OAuthUserInfo, AuthError> {
        let profile = if let Some(oidc) = &self.oidc {
            let token = tokens
                .id_token
                .as_deref()
                .ok_or(AuthError::OAuthUserInfoUnavailable)?;
            verify_id_token(token, oidc, expected_nonce).await?
        } else {
            let endpoint = self
                .user_info_endpoint
                .as_deref()
                .ok_or(AuthError::OAuthUserInfoUnavailable)?;
            let access_token = tokens
                .access_token
                .as_deref()
                .ok_or(AuthError::OAuthUserInfoUnavailable)?;
            let response = reqwest::Client::new()
                .get(endpoint)
                .bearer_auth(access_token)
                .header(reqwest::header::USER_AGENT, "lucid-auth")
                .send()
                .await
                .map_err(|_| AuthError::OAuthUserInfoUnavailable)?;
            if !response.status().is_success() {
                return Err(AuthError::OAuthUserInfoUnavailable);
            }
            response
                .text()
                .await
                .ok()
                .and_then(|body| serde_json::from_str::<Value>(&body).ok())
                .ok_or(AuthError::OAuthUserInfoUnavailable)?
        };
        map_profile(self, profile)
    }

    async fn refresh_access_token(&self, refresh_token: &str) -> Result<OAuthTokens, AuthError> {
        let mut form = vec![
            ("grant_type", "refresh_token".to_owned()),
            ("refresh_token", refresh_token.to_owned()),
            (&self.token_client_id_parameter, self.client_id.clone()),
        ];
        if self.token_endpoint_auth == TokenEndpointAuth::ClientSecretPost
            && let Some(secret) = &self.client_secret
        {
            form.push(("client_secret", secret.clone()));
        }
        let encoded = url::form_urlencoded::Serializer::new(String::new())
            .extend_pairs(form)
            .finish();
        let mut request = reqwest::Client::new()
            .post(&self.token_endpoint)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(encoded);
        if self.token_endpoint_auth == TokenEndpointAuth::ClientSecretBasic {
            request = request.basic_auth(&self.client_id, self.client_secret.as_deref());
        }
        let response = request
            .send()
            .await
            .map_err(|_| AuthError::OAuthFailedToRefreshToken)?;
        if !response.status().is_success() {
            return Err(AuthError::OAuthFailedToRefreshToken);
        }
        let value = response
            .json::<Value>()
            .await
            .map_err(|_| AuthError::OAuthFailedToRefreshToken)?;
        parse_token_response(value).map_err(|_| AuthError::OAuthFailedToRefreshToken)
    }
}
