use super::OpenApiEndpoint;
use crate::{
    AuthConfig, AuthError, AuthPlugin, PluginDescriptor, PluginEndpoint, PluginHttpMethod,
};
use serde::{Deserialize, Serialize};
#[cfg(feature = "axum")]
use std::sync::Arc;
use std::{borrow::Cow, fmt};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OpenApiTheme {
    Alternate,
    #[default]
    Default,
    Moon,
    Purple,
    Solarized,
    BluePlanet,
    Saturn,
    Kepler,
    Mars,
    DeepSpace,
    Laserwave,
    None,
}

impl OpenApiTheme {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Alternate => "alternate",
            Self::Default => "default",
            Self::Moon => "moon",
            Self::Purple => "purple",
            Self::Solarized => "solarized",
            Self::BluePlanet => "bluePlanet",
            Self::Saturn => "saturn",
            Self::Kepler => "kepler",
            Self::Mars => "mars",
            Self::DeepSpace => "deepSpace",
            Self::Laserwave => "laserwave",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenApiConfig {
    pub path: String,
    pub disable_default_reference: bool,
    pub theme: OpenApiTheme,
    pub nonce: Option<String>,
}

impl Default for OpenApiConfig {
    fn default() -> Self {
        Self {
            path: "/reference".into(),
            disable_default_reference: false,
            theme: OpenApiTheme::Default,
            nonce: None,
        }
    }
}

#[derive(Clone)]
pub struct OpenApiPlugin {
    config: OpenApiConfig,
}

impl OpenApiPlugin {
    pub fn new(config: OpenApiConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &OpenApiConfig {
        &self.config
    }
}

impl Default for OpenApiPlugin {
    fn default() -> Self {
        Self::new(OpenApiConfig::default())
    }
}

impl fmt::Debug for OpenApiPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenApiPlugin")
            .field("config", &self.config)
            .finish()
    }
}

impl AuthPlugin for OpenApiPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "open-api",
            display_name: "Open API",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            provenance: crate::PluginProvenance::better_auth_plugin("openAPI"),
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Owned(vec![
                PluginEndpoint {
                    method: PluginHttpMethod::Get,
                    path: Cow::Borrowed("/open-api/generate-schema"),
                    client_method: "generateOpenAPISchema",
                },
                PluginEndpoint {
                    method: PluginHttpMethod::Get,
                    path: Cow::Owned(self.config.path.clone()),
                    client_method: "openAPIReference",
                },
            ]),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        if !self.config.path.starts_with('/')
            || self.config.path.contains(['?', '#'])
            || self.config.path.split('/').any(|segment| segment == "..")
        {
            return Err(AuthError::InvalidConfiguration(
                "OpenAPI reference path must be an absolute auth-relative path".into(),
            ));
        }
        Ok(())
    }

    fn open_api_endpoints(&self) -> Vec<OpenApiEndpoint> {
        let mut schema =
            OpenApiEndpoint::new("/open-api/generate-schema", vec![PluginHttpMethod::Get]);
        schema.server_only = true;
        let mut reference =
            OpenApiEndpoint::new(self.config.path.clone(), vec![PluginHttpMethod::Get]);
        reference.server_only = true;
        vec![schema, reference]
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        super::axum::routes(service, self.config.clone())
    }
}
