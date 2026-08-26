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
mod error;
#[cfg(feature = "axum")]
mod http_error;
#[cfg(feature = "axum")]
mod http_input;
#[cfg(feature = "axum")]
mod http_response;
mod schema_catalog;

pub use error::ApiKeyError;
#[cfg(feature = "axum")]
pub(crate) use http_error::api_key_error;

const ENDPOINTS: &[PluginEndpoint] = &[
    endpoint(PluginHttpMethod::Post, "/api-key/create", "apiKey.create"),
    endpoint(PluginHttpMethod::Get, "/api-key/get", "apiKey.get"),
    endpoint(PluginHttpMethod::Get, "/api-key/list", "apiKey.list"),
    endpoint(PluginHttpMethod::Post, "/api-key/update", "apiKey.update"),
    endpoint(PluginHttpMethod::Post, "/api-key/delete", "apiKey.delete"),
    endpoint(PluginHttpMethod::Post, "/api-key/verify", "verifyApiKey"),
    endpoint(
        PluginHttpMethod::Post,
        "/api-key/delete-all-expired-api-keys",
        "deleteAllExpiredApiKeys",
    ),
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
    pub default_permissions: Option<BTreeMap<String, Vec<String>>>,
    pub key_generator: Option<Arc<dyn ApiKeyGenerator>>,
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
            default_permissions: None,
            key_generator: None,
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
        Self::with_configurations_and_options(vec![configuration], options)
    }

    pub fn with_configurations(configurations: Vec<ApiKeyConfiguration>) -> Self {
        Self::with_configurations_and_options(configurations, ApiKeyOptions::default())
    }

    pub fn with_configurations_and_options(
        configurations: Vec<ApiKeyConfiguration>,
        options: ApiKeyOptions,
    ) -> Self {
        Self {
            configurations: Arc::new(configurations),
            options,
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
        validate_configurations(&self.configurations)
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

        let Some((configuration, key)) = self.configurations.iter().find_map(|configuration| {
            if !configuration.enable_session_for_api_keys {
                return None;
            }
            configuration.headers.iter().find_map(|header| {
                headers
                    .get(header)
                    .and_then(|value| value.to_str().ok())
                    .map(|key| (configuration, key.to_owned()))
            })
        }) else {
            return Ok(None);
        };
        if key.len() < configuration.default_key_length {
            return Err(ApiKeyError::Invalid.into());
        }
        let verified = service
            .verify_api_key(
                &key,
                &self.configurations,
                Some(&configuration.config_id),
                None,
            )
            .await?;
        let user = verified.user.ok_or(ApiKeyError::InvalidReferenceId)?;
        let now = Utc::now();
        let session = SessionWithUser {
            session: AuthSession {
                id: verified.api_key.id,
                user_id: user.id.clone(),
                token: String::new(),
                actor_user_id: None,
                authentication_method: Some(AuthenticationMethod::Password),
                expires_at: verified
                    .api_key
                    .expires_at
                    .unwrap_or_else(|| now + service.session_ttl()),
                created_at: now,
                updated_at: now,
                ip_address: None,
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
}

fn validate_configurations(configurations: &[ApiKeyConfiguration]) -> Result<(), AuthError> {
    if configurations.is_empty() {
        return invalid("at least one API-key configuration is required");
    }
    let mut ids = std::collections::HashSet::new();
    for config in configurations {
        if !ids.insert(config.config_id.as_str()) {
            return invalid("API-key configuration IDs must be unique");
        }
        if config.default_key_length == 0
            || config.minimum_prefix_length > config.maximum_prefix_length
            || config.minimum_name_length > config.maximum_name_length
            || config.starting_characters.length == 0
            || config.rate_limit.time_window_milliseconds <= 0
            || config.rate_limit.max_requests <= 0
            || config.headers.is_empty()
            || config.headers.iter().any(|header| header.trim().is_empty())
        {
            return invalid("API-key configuration values are invalid");
        }
    }
    if !configurations
        .iter()
        .any(|config| config.config_id == "default")
    {
        return invalid("a default API-key configuration is required");
    }
    Ok(())
}

fn invalid<T>(message: &str) -> Result<T, AuthError> {
    Err(AuthError::InvalidConfiguration(message.into()))
}
