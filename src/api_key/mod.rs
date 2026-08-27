#[cfg(feature = "axum")]
use crate::AuthService;
use crate::{
    AuthConfig, AuthError, AuthPlugin, PluginClientMetadata, PluginDescriptor, PluginEndpoint,
    PluginHttpMethod,
};
use async_trait::async_trait;
use std::{collections::BTreeMap, sync::Arc};

#[cfg(feature = "axum")]
mod axum;
mod config_id;
mod error;
#[cfg(feature = "axum")]
mod http_error;
#[cfg(feature = "axum")]
mod http_input;
#[cfg(feature = "axum")]
mod http_response;
#[cfg(feature = "axum")]
mod listing;
#[cfg(feature = "axum")]
mod request_key;
mod schema_catalog;
mod secondary_storage;

pub(crate) use config_id::config_ids_match;
pub use error::ApiKeyError;
#[cfg(feature = "axum")]
pub(crate) use http_error::api_key_error;
pub use secondary_storage::{ApiKeySecondaryStorage, ApiKeySecondaryStorageMode};

const ENDPOINTS: &[PluginEndpoint] = &[
    endpoint(PluginHttpMethod::Post, "/api-key/create", "apiKey.create"),
    endpoint(PluginHttpMethod::Get, "/api-key/get", "apiKey.get"),
    endpoint(PluginHttpMethod::Get, "/api-key/list", "apiKey.list"),
    endpoint(PluginHttpMethod::Post, "/api-key/update", "apiKey.update"),
    endpoint(PluginHttpMethod::Post, "/api-key/delete", "apiKey.delete"),
];

const fn endpoint(
    method: PluginHttpMethod,
    path: &'static str,
    client_method: &'static str,
) -> PluginEndpoint {
    PluginEndpoint {
        method,
        path: std::borrow::Cow::Borrowed(path),
        client_method,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyReference {
    User,
    Organization,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiKeyStorage {
    Database,
    SecondaryStorage,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiKeyGetterValue {
    Missing,
    Key(String),
    Invalid,
}

pub trait ApiKeyGetter: Send + Sync {
    fn get(&self, context: &crate::PluginRequestContext) -> ApiKeyGetterValue;
}

#[async_trait]
pub trait ApiKeyValidator: Send + Sync {
    async fn validate(
        &self,
        context: &crate::PluginRequestContext,
        key: &str,
    ) -> Result<bool, AuthError>;
}

#[derive(Debug, Clone)]
pub struct ApiKeyRateLimitConfig {
    pub enabled: bool,
    pub time_window_milliseconds: i64,
    pub max_requests: i64,
}

impl Default for ApiKeyRateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            time_window_milliseconds: 86_400_000,
            max_requests: 10,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApiKeyExpirationConfig {
    pub default_expires_in_seconds: Option<i64>,
    pub disable_custom_expires: bool,
    pub minimum_days: f64,
    pub maximum_days: f64,
}

impl Default for ApiKeyExpirationConfig {
    fn default() -> Self {
        Self {
            default_expires_in_seconds: None,
            disable_custom_expires: false,
            minimum_days: 1.0,
            maximum_days: 365.0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ApiKeyStartingCharactersConfig {
    pub store: bool,
    pub length: usize,
}

impl Default for ApiKeyStartingCharactersConfig {
    fn default() -> Self {
        Self {
            store: true,
            length: 6,
        }
    }
}

#[derive(Clone)]
pub struct ApiKeyConfiguration {
    pub config_id: String,
    pub reference: ApiKeyReference,
    pub headers: Vec<String>,
    pub default_key_length: usize,
    pub default_prefix: Option<String>,
    pub minimum_prefix_length: usize,
    pub maximum_prefix_length: usize,
    pub require_name: bool,
    pub minimum_name_length: usize,
    pub maximum_name_length: usize,
    pub enable_metadata: bool,
    pub starting_characters: ApiKeyStartingCharactersConfig,
    pub expiration: ApiKeyExpirationConfig,
    pub rate_limit: ApiKeyRateLimitConfig,
    pub enable_session_for_api_keys: bool,
    pub disable_key_hashing: bool,
    pub storage: ApiKeyStorage,
    pub fallback_to_database: bool,
    pub custom_storage: Option<Arc<dyn crate::SecondaryStorage>>,
    pub defer_updates: bool,
    pub default_permissions: Option<BTreeMap<String, Vec<String>>>,
    pub key_generator: Option<Arc<dyn ApiKeyGenerator>>,
    pub key_getter: Option<Arc<dyn ApiKeyGetter>>,
    pub key_validator: Option<Arc<dyn ApiKeyValidator>>,
}

impl Default for ApiKeyConfiguration {
    fn default() -> Self {
        Self {
            config_id: "default".into(),
            reference: ApiKeyReference::User,
            headers: vec!["x-api-key".into()],
            default_key_length: 64,
            default_prefix: None,
            minimum_prefix_length: 1,
            maximum_prefix_length: 32,
            require_name: false,
            minimum_name_length: 1,
            maximum_name_length: 32,
            enable_metadata: false,
            starting_characters: ApiKeyStartingCharactersConfig::default(),
            expiration: ApiKeyExpirationConfig::default(),
            rate_limit: ApiKeyRateLimitConfig::default(),
            enable_session_for_api_keys: false,
            disable_key_hashing: false,
            storage: ApiKeyStorage::Database,
            fallback_to_database: false,
            custom_storage: None,
            defer_updates: false,
            default_permissions: None,
            key_generator: None,
            key_getter: None,
            key_validator: None,
        }
    }
}

impl ApiKeyConfiguration {
    pub(crate) fn effective_key_length(&self) -> usize {
        if self.default_key_length == 0 {
            64
        } else {
            self.default_key_length
        }
    }
}

#[async_trait]
pub trait ApiKeyGenerator: Send + Sync {
    async fn generate(&self, length: usize, prefix: Option<&str>) -> Result<String, AuthError>;
}

#[derive(Clone)]
pub struct ApiKeyPlugin {
    configurations: Arc<Vec<ApiKeyConfiguration>>,
    options: ApiKeyOptions,
    configuration_array: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ApiKeyOptions {
    pub schema: crate::DatabaseModelSchema,
}

impl ApiKeyPlugin {
    pub fn new(configuration: ApiKeyConfiguration) -> Self {
        Self::with_options(configuration, ApiKeyOptions::default())
    }

    pub fn with_options(configuration: ApiKeyConfiguration, options: ApiKeyOptions) -> Self {
        Self::build(vec![configuration], options, false)
    }

    pub fn with_configurations(configurations: Vec<ApiKeyConfiguration>) -> Self {
        Self::with_configurations_and_options(configurations, ApiKeyOptions::default())
    }

    pub fn with_configurations_and_options(
        configurations: Vec<ApiKeyConfiguration>,
        options: ApiKeyOptions,
    ) -> Self {
        Self::build(configurations, options, true)
    }

    fn build(
        mut configurations: Vec<ApiKeyConfiguration>,
        options: ApiKeyOptions,
        configuration_array: bool,
    ) -> Self {
        if !configuration_array
            && let Some(configuration) = configurations.first_mut()
            && configuration.config_id.is_empty()
        {
            configuration.config_id = "default".into();
        }
        Self {
            configurations: Arc::new(configurations),
            options,
            configuration_array,
        }
    }
}

#[async_trait]
impl AuthPlugin for ApiKeyPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "api-key",
            display_name: "Better Auth API Key",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            provenance: crate::PluginProvenance::pinned_upstream(
                "@better-auth/api-key",
                crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
                "@better-auth/api-key",
                "apiKey",
            ),
            dependencies: if self
                .configurations
                .iter()
                .any(|config| config.reference == ApiKeyReference::Organization)
            {
                &["organization"]
            } else {
                &[]
            },
            conflicts: &[],
            endpoints: std::borrow::Cow::Borrowed(ENDPOINTS),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(PluginClientMetadata::official(
                "@better-auth/api-key",
                "@better-auth/api-key/client",
                "apiKeyClient",
            )),
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        validate_configurations(&self.configurations, self.configuration_array)
    }

    fn schema(&self) -> Vec<crate::PluginSchemaTable> {
        let sole = (self.configurations.len() == 1).then(|| &self.configurations[0]);
        vec![crate::database_schema::remap_plugin_table(
            schema_catalog::table(sole),
            &self.options.schema,
            false,
        )]
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<AuthService>) -> Vec<crate::AxumPluginRoute> {
        axum::routes(service, self.configurations.clone())
    }

    #[cfg(feature = "axum")]
    async fn session_from_headers(
        &self,
        service: &AuthService,
        headers: &::axum::http::HeaderMap,
    ) -> Result<Option<crate::plugin::PluginSession>, AuthError> {
        use crate::{AuthSession, AuthenticationMethod, SessionWithUser};
        use chrono::Utc;

        let Some(context) = request_key::marked_context(headers) else {
            return Ok(None);
        };
        let Some((configuration, key)) = request_key::find(&self.configurations, &context) else {
            return Err(ApiKeyError::InvalidGetterReturnType.into());
        };
        let key = match key {
            ApiKeyGetterValue::Key(key) => key,
            ApiKeyGetterValue::Invalid | ApiKeyGetterValue::Missing => {
                return Err(ApiKeyError::InvalidGetterReturnType.into());
            }
        };
        if key.len() < configuration.effective_key_length() {
            return Err(ApiKeyError::SessionInvalid.into());
        }
        if let Some(validator) = &configuration.key_validator
            && !validator.validate(&context, &key).await?
        {
            return Err(ApiKeyError::SessionInvalid.into());
        }
        let verified = service
            .verify_api_key_after_custom_validation(
                &key,
                &self.configurations,
                Some(&configuration.config_id),
                None,
                &context,
            )
            .await?;
        let user = verified.user.ok_or(ApiKeyError::InvalidReferenceId)?;
        let now = Utc::now();
        let session = SessionWithUser {
            session: AuthSession {
                id: verified.api_key.id,
                user_id: user.id.clone(),
                token: key.clone(),
                actor_user_id: None,
                authentication_method: Some(AuthenticationMethod::Password),
                expires_at: verified.api_key.expires_at.unwrap_or_else(|| {
                    now + chrono::Duration::milliseconds(service.session_ttl().num_seconds())
                }),
                created_at: now,
                updated_at: now,
                ip_address: service.resolve_client_ip(|name| context.headers.get(name).cloned()),
                user_agent: headers
                    .get(::axum::http::header::USER_AGENT)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned),
                additional_fields: serde_json::Map::new(),
            },
            user,
        };
        Ok(Some(crate::plugin::PluginSession {
            session,
            token: key,
        }))
    }

    #[cfg(feature = "axum")]
    async fn on_request(
        &self,
        service: &AuthService,
        mut request: ::axum::extract::Request,
    ) -> Result<::axum::extract::Request, ::axum::response::Response> {
        let context = request_key::context(service, &request);
        if request_key::find(&self.configurations, &context).is_some() {
            request_key::mark(request.headers_mut(), &context);
        }
        Ok(request)
    }
}

fn validate_configurations(
    configurations: &[ApiKeyConfiguration],
    configuration_array: bool,
) -> Result<(), AuthError> {
    if configuration_array
        && !configurations.is_empty()
        && configurations
            .iter()
            .any(|config| config.config_id.is_empty())
    {
        return invalid(
            "configId is required for each API key configuration in the api-key plugin.",
        );
    }
    let mut ids = std::collections::HashSet::new();
    for config in configurations {
        if !ids.insert(config.config_id.as_str()) {
            return invalid(
                "configId must be unique for each API key configuration in the api-key plugin.",
            );
        }
    }
    Ok(())
}

fn invalid<T>(message: &str) -> Result<T, AuthError> {
    Err(AuthError::InvalidConfiguration(message.into()))
}
