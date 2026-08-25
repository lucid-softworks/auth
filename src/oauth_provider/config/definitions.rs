#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OAuthResourceSeedMode {
    #[default]
    InsertOnly,
    Merge,
    Overwrite,
}

#[derive(Debug, Clone, PartialEq)]
pub struct OAuthResourceInput {
    pub identifier: String,
    pub name: Option<String>,
    pub access_token_ttl: Option<u64>,
    pub refresh_token_ttl: Option<u64>,
    pub signing_algorithm: Option<String>,
    pub signing_key_id: Option<String>,
    pub allowed_scopes: Option<Vec<String>>,
    pub custom_claims: Option<Map<String, Value>>,
    pub dpop_bound_access_tokens_required: Option<bool>,
    pub disabled: Option<bool>,
    pub metadata: Option<Map<String, Value>>,
}

impl From<String> for OAuthResourceInput {
    fn from(identifier: String) -> Self {
        Self {
            identifier,
            name: None,
            access_token_ttl: None,
            refresh_token_ttl: None,
            signing_algorithm: None,
            signing_key_id: None,
            allowed_scopes: None,
            custom_claims: None,
            dpop_bound_access_tokens_required: None,
            disabled: None,
            metadata: None,
        }
    }
}

impl From<&str> for OAuthResourceInput {
    fn from(identifier: &str) -> Self {
        identifier.to_owned().into()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum OAuthExpiration {
    /// An absolute Unix timestamp in seconds, matching Better Auth's numeric
    /// expiration-time contract.
    Timestamp(i64),
    Duration(String),
    Date(DateTime<Utc>),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OAuthProviderModelSchema {
    pub model_name: Option<String>,
    /// Better Auth field name to adapter column name.
    pub fields: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OAuthProviderSchema {
    pub oauth_client: OAuthProviderModelSchema,
    pub oauth_resource: OAuthProviderModelSchema,
    pub oauth_client_resource: OAuthProviderModelSchema,
    pub oauth_refresh_token: OAuthProviderModelSchema,
    pub oauth_access_token: OAuthProviderModelSchema,
    pub oauth_consent: OAuthProviderModelSchema,
    pub oauth_client_assertion: OAuthProviderModelSchema,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthClientAction {
    Create,
    Read,
    Update,
    Delete,
    List,
    Rotate,
    ConfigureClientCredentialsScopes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthResourceAction {
    Create,
    Read,
    Update,
    Delete,
    List,
    Link,
    Unlink,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct OAuthCallbackContext {
    pub headers: BTreeMap<String, String>,
    pub user: Option<Value>,
    pub session: Option<Value>,
    pub scopes: Vec<String>,
}

#[async_trait]
pub trait OAuthIdentifierValidator: Send + Sync {
    async fn validate(&self, identifier: &str) -> Result<bool, AuthError>;
}

#[async_trait]
pub trait OAuthClientPrivileges: Send + Sync {
    async fn authorize(
        &self,
        action: OAuthClientAction,
        context: &OAuthCallbackContext,
    ) -> Result<Option<bool>, AuthError>;
}

#[async_trait]
pub trait OAuthResourcePrivileges: Send + Sync {
    async fn authorize(
        &self,
        action: OAuthResourceAction,
        resource_id: Option<&str>,
        context: &OAuthCallbackContext,
    ) -> Result<Option<bool>, AuthError>;
}

#[async_trait]
pub trait OAuthClientReference: Send + Sync {
    async fn resolve(&self, context: &OAuthCallbackContext) -> Result<Option<String>, AuthError>;
}

#[async_trait]
pub trait OAuthInitialAccessTokenValidator: Send + Sync {
    async fn validate(
        &self,
        token: &str,
        client_metadata: &Value,
        context: &OAuthCallbackContext,
    ) -> Result<Option<OAuthInitialAccessTokenAuthorization>, AuthError>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OAuthInitialAccessTokenAuthorization {
    pub reference_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthUiStage {
    Signup,
    SelectAccount,
    PostLogin,
}

#[async_trait]
pub trait OAuthUiRedirect: Send + Sync {
    /// `None` continues authorization, while `Some(page)` redirects there.
    async fn redirect(
        &self,
        stage: OAuthUiStage,
        context: &OAuthCallbackContext,
    ) -> Result<Option<String>, AuthError>;
}

#[async_trait]
pub trait OAuthConsentReference: Send + Sync {
    async fn resolve(&self, context: &OAuthCallbackContext) -> Result<Option<String>, AuthError>;
}

#[async_trait]
pub trait OAuthRefreshTokenCodec: Send + Sync {
    async fn encrypt(&self, token: &str, session_id: Option<&str>) -> Result<String, AuthError>;
    async fn decrypt(&self, token: &str) -> Result<OAuthDecodedRefreshToken, AuthError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OAuthDecodedRefreshToken {
    pub session_id: Option<String>,
    pub token: String,
}

#[async_trait]
pub trait OAuthClientSecretHasher: Send + Sync {
    async fn hash(&self, secret: &str) -> Result<String, AuthError>;
    async fn verify(&self, secret: &str, stored_hash: &str) -> Result<bool, AuthError>;
}

#[async_trait]
pub trait OAuthClientSecretCipher: Send + Sync {
    async fn encrypt(&self, secret: &str) -> Result<String, AuthError>;
    async fn decrypt(&self, stored_secret: &str) -> Result<String, AuthError>;
}

#[derive(Clone, Default)]
pub enum OAuthClientSecretStorage {
    #[default]
    Automatic,
    Hashed,
    Encrypted,
    CustomHashed(Arc<dyn OAuthClientSecretHasher>),
    CustomEncrypted(Arc<dyn OAuthClientSecretCipher>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthStoredTokenType {
    AccessToken,
    RefreshToken,
    AuthorizationCode,
}

#[async_trait]
pub trait OAuthTokenHasher: Send + Sync {
    async fn hash(
        &self,
        token: &str,
        token_type: OAuthStoredTokenType,
    ) -> Result<String, AuthError>;
}

#[derive(Clone, Default)]
pub enum OAuthTokenStorage {
    #[default]
    Hashed,
    Custom(Arc<dyn OAuthTokenHasher>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OAuthClaimTarget {
    AccessToken,
    IdToken,
    UserInfo,
    TokenResponse,
}

#[async_trait]
pub trait OAuthClaimsProvider: Send + Sync {
    async fn claims(
        &self,
        target: OAuthClaimTarget,
        context: &OAuthCallbackContext,
        protocol: &Value,
    ) -> Result<Map<String, Value>, AuthError>;
}

#[async_trait]
pub trait OAuthStringGenerator: Send + Sync {
    async fn generate(&self) -> Result<String, AuthError>;
}

#[async_trait]
pub trait OAuthRequestUriResolver: Send + Sync {
    async fn resolve(
        &self,
        request_uri: &str,
        client_id: &str,
        context: &OAuthCallbackContext,
    ) -> Result<Option<Vec<(String, String)>>, AuthError>;
}
