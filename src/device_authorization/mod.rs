#[cfg(feature = "axum")]
pub(crate) mod axum;
mod config;
mod generation;
mod memory;
mod model;
mod oauth;
pub(crate) mod schema;
mod store;

pub(crate) use config::DeviceAuthorizationMode;
pub use config::{
    DEFAULT_DEVICE_CODE_LENGTH, DEFAULT_EXPIRES_IN, DEFAULT_INTERVAL, DEFAULT_USER_CODE_LENGTH,
    DeviceAuthorizationConfig, DeviceAuthorizationConfigError, DeviceAuthorizationRequestObserver,
    DeviceClientValidator, DeviceCodeGenerator, MAX_GENERATED_CODE_CHARACTERS,
    parse_duration_milliseconds,
};
pub use generation::{
    DeviceAuthorizationGenerationError, DeviceAuthorizationRequest, GeneratedDeviceAuthorization,
    build_verification_uris, find_device_code_by_user_code, generate_device_authorization,
};
pub use memory::MemoryDeviceAuthorizationStore;
pub use model::{DeviceCode, DeviceCodeOwner, DeviceCodeStatus, DeviceCodeStatusParseError};
pub const DEVICE_CODE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:device_code";
pub use schema::{DeviceAuthorizationModelSchema, DeviceAuthorizationSchema};
pub use store::{DeviceAuthorizationStore, DeviceCodeCreateOutcome};

use crate::{
    AuthConfig, AuthError, AuthPlugin, PluginClientMetadata, PluginDescriptor, PluginEndpoint,
    PluginHttpMethod, PluginRateLimit,
};
use async_trait::async_trait;
use std::{borrow::Cow, fmt, sync::Arc};

const ENDPOINTS: &[PluginEndpoint] = &[
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: Cow::Borrowed("/device/code"),
        client_method: "device.code",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: Cow::Borrowed("/device/token"),
        client_method: "device.token",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Get,
        path: Cow::Borrowed("/device"),
        client_method: "device",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: Cow::Borrowed("/device/approve"),
        client_method: "device.approve",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: Cow::Borrowed("/device/deny"),
        client_method: "device.deny",
    },
];

#[derive(Clone)]
pub struct DeviceAuthorizationPlugin {
    config: Arc<DeviceAuthorizationConfig>,
    store: Arc<dyn DeviceAuthorizationStore>,
}

impl DeviceAuthorizationPlugin {
    pub fn new<S>(config: DeviceAuthorizationConfig, store: S) -> Self
    where
        S: DeviceAuthorizationStore + 'static,
    {
        Self::from_arc(config, Arc::new(store))
    }

    pub fn from_arc(
        mut config: DeviceAuthorizationConfig,
        store: Arc<dyn DeviceAuthorizationStore>,
    ) -> Self {
        config.mode = DeviceAuthorizationMode::Standalone;
        Self::from_arc_with_mode(config, store, DeviceAuthorizationMode::Standalone)
    }

    fn from_arc_with_mode(
        mut config: DeviceAuthorizationConfig,
        store: Arc<dyn DeviceAuthorizationStore>,
        mode: DeviceAuthorizationMode,
    ) -> Self {
        config.mode = mode;
        Self {
            config: Arc::new(config),
            store,
        }
    }

    pub fn in_memory(config: DeviceAuthorizationConfig) -> Self {
        Self::new(config, MemoryDeviceAuthorizationStore::new())
    }

    #[cfg(feature = "postgres")]
    pub fn postgres(
        config: DeviceAuthorizationConfig,
        store: crate::postgres::PostgresStore,
    ) -> Self {
        let device_store = crate::postgres::PostgresDeviceAuthorizationStore::new(store);
        Self::new(config, device_store)
    }

    pub fn config(&self) -> &DeviceAuthorizationConfig {
        &self.config
    }

    pub fn store(&self) -> &Arc<dyn DeviceAuthorizationStore> {
        &self.store
    }
}

impl Default for DeviceAuthorizationPlugin {
    fn default() -> Self {
        Self::in_memory(DeviceAuthorizationConfig::default())
    }
}

impl fmt::Debug for DeviceAuthorizationPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DeviceAuthorizationPlugin")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub struct OAuthDeviceAuthorizationPlugin {
    inner: DeviceAuthorizationPlugin,
}

impl OAuthDeviceAuthorizationPlugin {
    pub fn new<S>(config: DeviceAuthorizationConfig, store: S) -> Self
    where
        S: DeviceAuthorizationStore + 'static,
    {
        Self::from_arc(config, Arc::new(store))
    }

    pub fn from_arc(
        config: DeviceAuthorizationConfig,
        store: Arc<dyn DeviceAuthorizationStore>,
    ) -> Self {
        Self {
            inner: DeviceAuthorizationPlugin::from_arc_with_mode(
                config,
                store,
                DeviceAuthorizationMode::OAuthProvider,
            ),
        }
    }

    pub fn in_memory(config: DeviceAuthorizationConfig) -> Self {
        Self::new(config, MemoryDeviceAuthorizationStore::new())
    }

    #[cfg(feature = "postgres")]
    pub fn postgres(
        config: DeviceAuthorizationConfig,
        store: crate::postgres::PostgresStore,
    ) -> Self {
        let device_store = crate::postgres::PostgresDeviceAuthorizationStore::new(store);
        Self::new(config, device_store)
    }

    pub fn config(&self) -> &DeviceAuthorizationConfig {
        self.inner.config()
    }

    pub fn store(&self) -> &Arc<dyn DeviceAuthorizationStore> {
        self.inner.store()
    }
}

impl fmt::Debug for OAuthDeviceAuthorizationPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthDeviceAuthorizationPlugin")
            .field("config", &self.inner.config)
            .finish_non_exhaustive()
    }
}

fn descriptor(oauth: bool) -> PluginDescriptor {
    PluginDescriptor {
        id: "device-authorization",
        display_name: "Better Auth Device Authorization",
        version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
        provenance: if oauth {
            crate::PluginProvenance::pinned_upstream(
                "@better-auth/oauth-provider",
                crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
                "@better-auth/oauth-provider",
                "oauthDeviceAuthorization",
            )
        } else {
            crate::PluginProvenance::better_auth_plugin("deviceAuthorization")
        },
        dependencies: if oauth { &["oauth-provider"] } else { &[] },
        conflicts: &[],
        endpoints: Cow::Borrowed(ENDPOINTS),
        cookies: &[],
        rate_limits: &[],
        middleware: &[],
        client: Some(if oauth {
            PluginClientMetadata::official(
                "@better-auth/oauth-provider",
                "@better-auth/oauth-provider/client",
                "oauthDeviceAuthorizationClient",
            )
        } else {
            PluginClientMetadata::official(
                "better-auth",
                "better-auth/client/plugins",
                "deviceAuthorizationClient",
            )
        }),
    }
}

fn rate_limits(config: &DeviceAuthorizationConfig) -> Vec<PluginRateLimit> {
    let Ok(window_ms) = config.expires_in_milliseconds() else {
        return Vec::new();
    };
    vec![PluginRateLimit {
        path: "/device",
        // A zero runtime window is the native disabled marker. Positive
        // fractional seconds round up because native storage expires in whole
        // seconds; they must never become disabled accidentally.
        window: if window_ms <= 0.0 {
            0
        } else {
            (window_ms / 1_000.0).ceil() as u64
        },
        max: 5,
    }]
}

trait DevicePluginInner {
    fn inner(&self) -> &DeviceAuthorizationPlugin;
}

impl DevicePluginInner for DeviceAuthorizationPlugin {
    fn inner(&self) -> &DeviceAuthorizationPlugin {
        self
    }
}

impl DevicePluginInner for OAuthDeviceAuthorizationPlugin {
    fn inner(&self) -> &DeviceAuthorizationPlugin {
        &self.inner
    }
}

macro_rules! impl_device_plugin {
    ($type:ty, $oauth:literal) => {
        #[async_trait]
        impl AuthPlugin for $type {
            fn descriptor(&self) -> PluginDescriptor {
                descriptor($oauth)
            }

            fn validate(&self, _auth: &AuthConfig) -> Result<(), AuthError> {
                self.inner()
                    .config
                    .validate()
                    .map_err(|error| AuthError::InvalidConfiguration(error.to_string()))
            }

            fn rate_limits(&self) -> Vec<PluginRateLimit> {
                rate_limits(&self.inner().config)
            }

            fn schema(&self) -> Vec<crate::PluginSchemaTable> {
                vec![schema::catalog(&self.inner().config.schema, $oauth)]
            }

            fn oauth_provider_extensions(&self) -> Vec<Arc<dyn crate::OAuthProviderExtension>> {
                if $oauth {
                    vec![Arc::new(oauth::OAuthDeviceAuthorizationExtension::new(
                        self.inner().store.clone(),
                    ))]
                } else {
                    Vec::new()
                }
            }

            #[cfg(feature = "axum")]
            fn routes(&self, _service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
                axum::routes(self.inner().config.clone(), self.inner().store.clone())
            }
        }
    };
}

impl_device_plugin!(DeviceAuthorizationPlugin, false);
impl_device_plugin!(OAuthDeviceAuthorizationPlugin, true);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_plugin_types_select_the_only_two_upstream_modes() {
        let standalone = DeviceAuthorizationPlugin::default();
        assert!(!standalone.config().includes_oauth_fields());
        assert_eq!(
            standalone.descriptor().client.unwrap().factory,
            "deviceAuthorizationClient"
        );
        let crate::PluginProvenance::PinnedBetterAuthPort { server, .. } =
            standalone.descriptor().provenance
        else {
            panic!("standalone device authorization must be pinned");
        };
        assert_eq!(server.package, "better-auth");
        assert_eq!(server.export, "deviceAuthorization");

        let oauth = OAuthDeviceAuthorizationPlugin::in_memory(DeviceAuthorizationConfig::default());
        assert!(oauth.config().includes_oauth_fields());
        assert_eq!(
            oauth.descriptor().client.unwrap().factory,
            "oauthDeviceAuthorizationClient"
        );
        let crate::PluginProvenance::PinnedBetterAuthPort { server, .. } =
            oauth.descriptor().provenance
        else {
            panic!("OAuth device authorization must be pinned");
        };
        assert_eq!(server.package, "@better-auth/oauth-provider");
        assert_eq!(server.export, "oauthDeviceAuthorization");
    }

    #[test]
    fn only_get_device_receives_the_plugin_rate_limit() {
        let plugin = DeviceAuthorizationPlugin::default();
        assert_eq!(
            plugin.rate_limits(),
            vec![PluginRateLimit {
                path: "/device",
                window: 1_800,
                max: 5,
            }]
        );
    }

    #[test]
    fn nonpositive_expiration_disables_the_device_rate_limit() {
        for expires_in in ["0s", "-1s"] {
            let plugin = DeviceAuthorizationPlugin::in_memory(DeviceAuthorizationConfig {
                expires_in: expires_in.into(),
                ..DeviceAuthorizationConfig::default()
            });
            assert_eq!(plugin.rate_limits()[0].window, 0);
        }
    }
}
