use super::super::{
    OAuthProviderClient, OAuthProviderConfig, OAuthProviderError, OAuthProviderRefreshToken,
    OAuthProviderStore, OAuthStoredTokenType,
};
use super::token;
use crate::AuthService;
use ::axum::http::{HeaderMap, HeaderName, HeaderValue};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, sync::Arc};

/// Request data binding the native OAuth Provider capability facade.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthProviderApiRequest {
    pub endpoint: String,
    pub headers: BTreeMap<String, String>,
    pub parameters: BTreeMap<String, Vec<String>>,
}

impl OAuthProviderApiRequest {
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            endpoint: endpoint.into(),
            headers: BTreeMap::new(),
            parameters: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthProviderApiAuthenticationRequest {
    pub scopes: Vec<String>,
    pub require_credentials: bool,
}

impl Default for OAuthProviderApiAuthenticationRequest {
    fn default() -> Self {
        Self {
            scopes: Vec::new(),
            require_credentials: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct OAuthProviderAuthenticatedClient {
    pub client_id: String,
    pub client: OAuthProviderClient,
    pub method: Option<String>,
    pub confirmation: Option<Value>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OAuthProviderClientAssertionInput {
    pub namespace: String,
    pub payload: Map<String, Value>,
    pub expected_audience: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OAuthProviderApiTokenIssueInput {
    pub client: OAuthProviderClient,
    pub scopes: Vec<String>,
    pub user_id: Option<String>,
    pub reference_id: Option<String>,
    pub session_id: Option<String>,
    pub nonce: Option<String>,
    pub refresh_token: Option<OAuthProviderRefreshToken>,
    pub auth_time: Option<i64>,
    pub resources: Option<Vec<String>>,
    pub original_resources: Option<Vec<String>>,
    pub requested_user_info_claims: Vec<String>,
    pub verification_value: Option<Value>,
    pub access_token_claims: Map<String, Value>,
    pub id_token_claims: Map<String, Value>,
    pub token_response: Map<String, Value>,
    pub confirmation: Option<Value>,
}

impl OAuthProviderApiTokenIssueInput {
    pub fn new(client: OAuthProviderClient, scopes: Vec<String>) -> Self {
        Self {
            client,
            scopes,
            user_id: None,
            reference_id: None,
            session_id: None,
            nonce: None,
            refresh_token: None,
            auth_time: None,
            resources: None,
            original_resources: None,
            requested_user_info_claims: Vec::new(),
            verification_value: None,
            access_token_claims: Map::new(),
            id_token_claims: Map::new(),
            token_response: Map::new(),
            confirmation: None,
        }
    }
}

/// Native equivalent of Better Auth's request-bound `getOAuthProviderApi`.
#[derive(Clone)]
pub struct OAuthProviderApi {
    service: Arc<AuthService>,
    config: Arc<OAuthProviderConfig>,
    store: Arc<dyn OAuthProviderStore>,
    request: OAuthProviderApiRequest,
    headers: HeaderMap,
    grant_type: Option<String>,
}

impl OAuthProviderApi {
    pub(in crate::oauth_provider) fn new(
        service: Arc<AuthService>,
        config: Arc<OAuthProviderConfig>,
        store: Arc<dyn OAuthProviderStore>,
        request: OAuthProviderApiRequest,
        grant_type: Option<String>,
    ) -> Result<Self, OAuthProviderError> {
        url::Url::parse(&request.endpoint).map_err(|_| {
            OAuthProviderError::InvalidRequest(
                "provider API endpoint must be an absolute URL".into(),
            )
        })?;
        let mut headers = HeaderMap::new();
        for (name, value) in &request.headers {
            let name = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                OAuthProviderError::InvalidRequest("provider API header name is invalid".into())
            })?;
            let value = HeaderValue::from_str(value).map_err(|_| {
                OAuthProviderError::InvalidRequest("provider API header value is invalid".into())
            })?;
            headers.append(name, value);
        }
        Ok(Self {
            service,
            config,
            store,
            request,
            headers,
            grant_type,
        })
    }

    pub async fn get_client(
        &self,
        client_id: &str,
    ) -> Result<Option<OAuthProviderClient>, OAuthProviderError> {
        token::provider_api_get_client(&self.config, self.store.as_ref(), &self.headers, client_id)
            .await
    }

    pub fn get_issuer(&self) -> String {
        token::provider_api_get_issuer(&self.service, &self.config, &self.headers)
    }

    pub async fn authenticate_client(
        &self,
        request: OAuthProviderApiAuthenticationRequest,
    ) -> Result<OAuthProviderAuthenticatedClient, OAuthProviderError> {
        token::provider_api_authenticate_client(
            &self.service,
            &self.config,
            self.store.as_ref(),
            &self.headers,
            &self.request.parameters,
            &self.request.endpoint,
            self.grant_type.as_deref(),
            request,
        )
        .await
    }

    pub async fn issue_tokens(
        &self,
        input: OAuthProviderApiTokenIssueInput,
    ) -> Result<Value, OAuthProviderError> {
        let grant_type = self.grant_type.as_deref().ok_or_else(|| {
            OAuthProviderError::ServerError(
                "issue_tokens requires a grant type bound to provider_api".into(),
            )
        })?;
        token::provider_api_issue_tokens(
            &self.service,
            &self.config,
            self.store.as_ref(),
            &self.headers,
            &self.request.endpoint,
            grant_type,
            input,
        )
        .await
    }

    pub(crate) async fn load_user(
        &self,
        user_id: &str,
    ) -> Result<Option<crate::AuthUser>, OAuthProviderError> {
        self.service
            .auth_user_by_id(user_id)
            .await
            .map_err(|error| OAuthProviderError::ServerError(error.to_string()))
    }

    /// Validates scopes and RFC 8707 resource policy without consuming grant state.
    pub(crate) async fn validate_resource_policy(
        &self,
        client: &OAuthProviderClient,
        scopes: &[String],
        resources: Option<&[String]>,
    ) -> Result<(), OAuthProviderError> {
        token::provider_api_validate_resource_policy(
            &self.service,
            &self.config,
            self.store.as_ref(),
            &self.headers,
            client,
            scopes,
            resources,
        )
        .await
    }

    pub async fn hash_token(
        &self,
        token_value: &str,
        token_type: OAuthStoredTokenType,
    ) -> Result<String, OAuthProviderError> {
        token::provider_api_hash_token(&self.config, token_value, token_type).await
    }

    pub async fn validate_access_token(
        &self,
        token_value: &str,
        client_id: Option<&str>,
    ) -> Result<Map<String, Value>, OAuthProviderError> {
        token::provider_api_validate_access_token(
            &self.service,
            &self.config,
            self.store.as_ref(),
            &self.headers,
            token_value,
            client_id,
        )
        .await
    }

    pub async fn require_active_access_token(
        &self,
        token_value: &str,
        client_id: Option<&str>,
    ) -> Result<Map<String, Value>, OAuthProviderError> {
        let payload = self.validate_access_token(token_value, client_id).await?;
        if payload.get("active").and_then(Value::as_bool) == Some(true) {
            Ok(payload)
        } else {
            Err(OAuthProviderError::InvalidToken(
                "The access token is invalid or expired".into(),
            ))
        }
    }

    pub async fn consume_client_assertion(
        &self,
        input: OAuthProviderClientAssertionInput,
    ) -> Result<(), OAuthProviderError> {
        token::provider_api_consume_client_assertion(&self.config, self.store.as_ref(), input).await
    }
}
