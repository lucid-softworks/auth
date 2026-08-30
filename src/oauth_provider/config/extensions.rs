#[derive(Debug, Clone)]
pub struct OAuthExtensionClientAuthenticationInput {
    pub method: String,
    pub client_id: Option<String>,
    pub endpoint: String,
    pub headers: BTreeMap<String, String>,
    pub parameters: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OAuthExtensionClientAuthentication {
    pub client_id: String,
    pub confirmation: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthExtensionClientAuthenticationMethod {
    pub method: String,
    pub assertion_types: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthClientMetadataResourceResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthProviderMetadataDocument {
    AuthorizationServer,
    OpenIdConnect,
}

#[cfg(feature = "axum")]
#[derive(Clone)]
pub struct OAuthExtensionGrantInput {
    pub grant_type: String,
    pub endpoint: String,
    pub headers: BTreeMap<String, String>,
    pub parameters: BTreeMap<String, Vec<String>>,
    pub provider: super::OAuthProviderApi,
}

#[async_trait]
pub trait OAuthProviderExtension: Send + Sync {
    /// Binds a companion discovery extension to the effective provider runtime.
    fn bind_oauth_provider(
        &self,
        _service: &crate::AuthService,
        _config: Arc<super::OAuthProviderConfig>,
        _store: Arc<dyn super::OAuthProviderStore>,
    ) {
    }

    fn grant_types(&self) -> Vec<String> {
        Vec::new()
    }

    fn client_authentication_methods(&self) -> Vec<OAuthExtensionClientAuthenticationMethod> {
        Vec::new()
    }

    fn client_discovery_ids(&self) -> Vec<String> {
        Vec::new()
    }

    /// Additional dynamic-registration metadata keys owned by this extension.
    /// Undeclared request keys are stripped to match Better Auth's Zod schemas.
    fn client_registration_metadata_fields(&self) -> Vec<String> {
        Vec::new()
    }

    /// Metadata advertised by this extension's client discovery sources.
    /// Later discovery entries replace earlier entries, while provider-owned
    /// metadata fields always take precedence over discovery contributions.
    fn client_discovery_metadata(&self) -> Map<String, Value> {
        Map::new()
    }

    async fn validate_client_metadata(
        &self,
        _metadata: &Value,
        _context: &OAuthCallbackContext,
    ) -> Result<(), AuthError> {
        Ok(())
    }

    async fn authenticate_client(
        &self,
        _input: &OAuthExtensionClientAuthenticationInput,
    ) -> Result<Option<OAuthExtensionClientAuthentication>, AuthError> {
        Ok(None)
    }

    async fn discover_client(
        &self,
        _client_id: &str,
        _stored_client: Option<&super::OAuthProviderClient>,
        _context: &OAuthCallbackContext,
    ) -> Result<Option<super::OAuthProviderClient>, AuthError> {
        Ok(None)
    }

    /// Fetches metadata-owned resources (for example a discovered client's
    /// `jwks_uri`). The discovery implementation owns the network trust
    /// boundary, including DNS pinning and redirect refusal.
    async fn fetch_client_metadata_resource(
        &self,
        _discovery_id: &str,
        _uri: &str,
    ) -> Result<Option<OAuthClientMetadataResourceResponse>, AuthError> {
        Ok(None)
    }

    #[cfg(feature = "axum")]
    async fn token_grant(
        &self,
        _input: &OAuthExtensionGrantInput,
    ) -> Result<Value, super::OAuthProviderError> {
        Err(super::OAuthProviderError::UnsupportedGrantType(
            "extension grant has no handler".into(),
        ))
    }

    async fn claims(
        &self,
        _target: OAuthClaimTarget,
        _context: &OAuthCallbackContext,
        _protocol: &Value,
    ) -> Result<Map<String, Value>, AuthError> {
        Ok(Map::new())
    }

    fn server_metadata(
        &self,
        _document: OAuthProviderMetadataDocument,
        _base: &Map<String, Value>,
    ) -> Map<String, Value> {
        Map::new()
    }

    fn client_metadata(
        &self,
        _client: &super::OAuthProviderClient,
        _base: &Map<String, Value>,
    ) -> Map<String, Value> {
        Map::new()
    }
}

#[derive(Clone, Default)]
pub struct OAuthProviderCallbacks {
    pub identifier_validator: Option<Arc<dyn OAuthIdentifierValidator>>,
    pub resource_privileges: Option<Arc<dyn OAuthResourcePrivileges>>,
    pub client_reference: Option<Arc<dyn OAuthClientReference>>,
    pub client_privileges: Option<Arc<dyn OAuthClientPrivileges>>,
    pub validate_initial_access_token: Option<Arc<dyn OAuthInitialAccessTokenValidator>>,
    pub ui_redirect: Option<Arc<dyn OAuthUiRedirect>>,
    pub consent_reference: Option<Arc<dyn OAuthConsentReference>>,
    pub format_refresh_token: Option<Arc<dyn OAuthRefreshTokenCodec>>,
    pub claims: Option<Arc<dyn OAuthClaimsProvider>>,
    pub generate_client_id: Option<Arc<dyn OAuthStringGenerator>>,
    pub generate_client_secret: Option<Arc<dyn OAuthStringGenerator>>,
    pub generate_opaque_access_token: Option<Arc<dyn OAuthStringGenerator>>,
    pub generate_refresh_token: Option<Arc<dyn OAuthStringGenerator>>,
    pub request_uri_resolver: Option<Arc<dyn OAuthRequestUriResolver>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OAuthAdvertisedMetadata {
    pub scopes_supported: Option<Vec<String>>,
    pub claims_supported: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OAuthTokenPrefixes {
    pub opaque_access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub client_secret: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthDpopConfig {
    pub proof_max_age_seconds: u64,
    pub signing_algorithms: Vec<String>,
}

impl Default for OAuthDpopConfig {
    fn default() -> Self {
        Self {
            proof_max_age_seconds: 300,
            signing_algorithms: DEFAULT_DPOP_ALGORITHMS
                .iter()
                .map(|value| (*value).into())
                .collect(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OAuthRateLimitRule {
    pub window: u64,
    pub max: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthProviderRateLimits {
    pub token: Option<OAuthRateLimitRule>,
    pub authorize: Option<OAuthRateLimitRule>,
    pub introspect: Option<OAuthRateLimitRule>,
    pub revoke: Option<OAuthRateLimitRule>,
    pub register: Option<OAuthRateLimitRule>,
    pub userinfo: Option<OAuthRateLimitRule>,
}

impl Default for OAuthProviderRateLimits {
    fn default() -> Self {
        let rule = |max| Some(OAuthRateLimitRule { window: 60, max });
        Self {
            token: rule(20),
            authorize: rule(30),
            introspect: rule(100),
            revoke: rule(30),
            register: rule(5),
            userinfo: rule(60),
        }
    }
}
