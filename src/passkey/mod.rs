#[cfg(feature = "axum")]
use crate::AuthService;
use crate::{
    AdditionalField, AdditionalFieldReference, AdditionalFieldType, AuthConfig, AuthError,
    AuthPlugin, PluginClientMetadata, PluginCookie, PluginDescriptor, PluginEndpoint,
    PluginHttpMethod, PluginSchemaTable,
};
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;
use webauthn_rs::prelude::AuthenticatorAttachment;
use webauthn_rs_core::proto::{ResidentKeyRequirement, UserVerificationPolicy};

mod public_key;

pub(crate) use public_key::credential_from_official_fields;

#[cfg(feature = "axum")]
mod axum;

const ENDPOINTS: &[PluginEndpoint] = &[
    PluginEndpoint {
        method: PluginHttpMethod::Get,
        path: std::borrow::Cow::Borrowed("/passkey/generate-register-options"),
        client_method: "passkey.addPasskey",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: std::borrow::Cow::Borrowed("/passkey/verify-registration"),
        client_method: "passkey.addPasskey",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Get,
        path: std::borrow::Cow::Borrowed("/passkey/generate-authenticate-options"),
        client_method: "signIn.passkey",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: std::borrow::Cow::Borrowed("/passkey/verify-authentication"),
        client_method: "signIn.passkey",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Get,
        path: std::borrow::Cow::Borrowed("/passkey/list-user-passkeys"),
        client_method: "passkey.listUserPasskeys",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: std::borrow::Cow::Borrowed("/passkey/delete-passkey"),
        client_method: "passkey.deletePasskey",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: std::borrow::Cow::Borrowed("/passkey/update-passkey"),
        client_method: "passkey.updatePasskey",
    },
];

const COOKIES: &[PluginCookie] = &[PluginCookie {
    name: "better-auth-passkey",
}];

/// Better Auth passkey plugin options.
#[derive(Clone)]
pub struct PasskeyConfig {
    pub schema: crate::DatabaseModelSchema,
    /// Relying-party ID. Defaults to the configured base URL host, then localhost.
    pub rp_id: Option<String>,
    /// Human-readable relying-party name. Defaults to `Better Auth`.
    pub rp_name: Option<String>,
    /// Allowed WebAuthn origins. `None` uses the request `Origin`, matching Better Auth.
    pub origins: Option<Vec<String>>,
    /// Registration authenticator-selection overrides.
    pub authenticator_selection: PasskeyAuthenticatorSelection,
    /// Unprefixed challenge-cookie suffix.
    pub webauthn_challenge_cookie: String,
    /// Registration session and passkey-first user resolution behavior.
    pub registration: PasskeyRegistrationConfig,
    pub authentication: PasskeyAuthenticationConfig,
}

impl Default for PasskeyConfig {
    fn default() -> Self {
        Self {
            schema: crate::DatabaseModelSchema::default(),
            rp_id: None,
            rp_name: None,
            origins: None,
            authenticator_selection: PasskeyAuthenticatorSelection::default(),
            webauthn_challenge_cookie: "better-auth-passkey".into(),
            registration: PasskeyRegistrationConfig::default(),
            authentication: PasskeyAuthenticationConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PasskeyAuthenticatorSelection {
    pub authenticator_attachment: Option<AuthenticatorAttachment>,
    pub resident_key: Option<ResidentKeyRequirement>,
    pub require_resident_key: Option<bool>,
    pub user_verification: Option<UserVerificationPolicy>,
}

#[derive(Clone)]
pub struct PasskeyRegistrationConfig {
    pub require_session: bool,
    pub resolve_user: Option<Arc<dyn PasskeyRegistrationUserResolver>>,
    pub after_verification: Option<Arc<dyn PasskeyRegistrationCallback>>,
    pub extensions: Option<PasskeyExtensions>,
}

impl Default for PasskeyRegistrationConfig {
    fn default() -> Self {
        Self {
            require_session: true,
            resolve_user: None,
            after_verification: None,
            extensions: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PasskeyRegistrationUser {
    pub id: String,
    pub name: String,
    pub display_name: Option<String>,
}

#[async_trait]
pub trait PasskeyRegistrationUserResolver: Send + Sync {
    async fn resolve(&self, context: Option<&str>) -> Result<PasskeyRegistrationUser, AuthError>;
}

#[derive(Debug, Clone)]
pub struct PasskeyRegistrationVerified {
    pub user: PasskeyRegistrationUser,
    pub context: Option<String>,
    pub response: Value,
    pub public_key: String,
    pub counter: u32,
    pub device_type: String,
    pub backed_up: bool,
    pub transports: Option<String>,
    pub aaguid: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PasskeyRegistrationOverride {
    pub user_id: Option<String>,
    pub name: Option<String>,
}

#[async_trait]
pub trait PasskeyRegistrationCallback: Send + Sync {
    async fn after_verification(
        &self,
        event: PasskeyRegistrationVerified,
    ) -> Result<PasskeyRegistrationOverride, AuthError>;
}

#[derive(Clone, Default)]
pub struct PasskeyAuthenticationConfig {
    pub after_verification: Option<Arc<dyn PasskeyAuthenticationCallback>>,
    pub extensions: Option<PasskeyExtensions>,
}

#[derive(Debug, Clone)]
pub struct PasskeyAuthenticationVerified {
    pub passkey_id: String,
    pub user_id: String,
    pub response: Value,
    pub counter: u32,
    pub backed_up: bool,
}

#[async_trait]
pub trait PasskeyAuthenticationCallback: Send + Sync {
    async fn after_verification(
        &self,
        event: PasskeyAuthenticationVerified,
    ) -> Result<(), AuthError>;
}

#[derive(Clone)]
pub enum PasskeyExtensions {
    Static(Value),
    Resolver(Arc<dyn PasskeyExtensionsResolver>),
}

impl From<Value> for PasskeyExtensions {
    fn from(value: Value) -> Self {
        Self::Static(value)
    }
}

impl PasskeyExtensions {
    pub(crate) async fn resolve(&self, context: Option<&str>) -> Result<Option<Value>, AuthError> {
        match self {
            Self::Static(value) => Ok(Some(value.clone())),
            Self::Resolver(resolver) => resolver.resolve(context).await,
        }
    }
}

#[async_trait]
pub trait PasskeyExtensionsResolver: Send + Sync {
    async fn resolve(&self, context: Option<&str>) -> Result<Option<Value>, AuthError>;
}

#[derive(Clone)]
pub struct PasskeyPlugin {
    config: Arc<PasskeyConfig>,
}

impl PasskeyPlugin {
    pub fn new(config: PasskeyConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

#[async_trait]
impl AuthPlugin for PasskeyPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "passkey",
            display_name: "Better Auth Passkey",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            provenance: crate::PluginProvenance::pinned_upstream(
                "@better-auth/passkey",
                crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
                "@better-auth/passkey",
                "passkey",
            ),
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Borrowed(ENDPOINTS),
            cookies: COOKIES,
            rate_limits: &[],
            middleware: &[],
            client: Some(PluginClientMetadata::official(
                "@better-auth/passkey",
                "@better-auth/passkey/client",
                "passkeyClient",
            )),
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        if self.config.webauthn_challenge_cookie.trim().is_empty() {
            return Err(AuthError::InvalidConfiguration(
                "passkey challenge cookie name must not be empty".into(),
            ));
        }
        if self
            .config
            .origins
            .as_ref()
            .is_some_and(|origins| origins.is_empty())
        {
            return Err(AuthError::InvalidConfiguration(
                "passkey origins must contain at least one origin when configured".into(),
            ));
        }
        for origin in self.config.origins.iter().flatten() {
            let parsed = url::Url::parse(origin).map_err(|_| {
                AuthError::InvalidConfiguration("passkey origin must be an absolute URL".into())
            })?;
            if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
                return Err(AuthError::InvalidConfiguration(
                    "passkey origin must be an absolute HTTP(S) URL".into(),
                ));
            }
        }
        Ok(())
    }

    fn schema(&self) -> Vec<PluginSchemaTable> {
        vec![crate::database_schema::remap_plugin_table(
            passkey_schema(),
            &self.config.schema,
            false,
        )]
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<AuthService>) -> Vec<crate::AxumPluginRoute> {
        axum::routes(service, self.config.clone())
    }
}

fn passkey_schema() -> PluginSchemaTable {
    let optional_string = || AdditionalField::new(AdditionalFieldType::String).optional();
    PluginSchemaTable::new("passkey")
        .field("name", optional_string())
        .field(
            "publicKey",
            AdditionalField::new(AdditionalFieldType::String),
        )
        .field(
            "userId",
            AdditionalField::new(AdditionalFieldType::String)
                .references(AdditionalFieldReference {
                    model: "user".into(),
                    field: "id".into(),
                    on_delete: None,
                })
                .index(true),
        )
        .field(
            "credentialID",
            AdditionalField::new(AdditionalFieldType::String).index(true),
        )
        .field("counter", AdditionalField::new(AdditionalFieldType::Number))
        .field(
            "deviceType",
            AdditionalField::new(AdditionalFieldType::String),
        )
        .field(
            "backedUp",
            AdditionalField::new(AdditionalFieldType::Boolean),
        )
        .field("transports", optional_string())
        .field(
            "createdAt",
            AdditionalField::new(AdditionalFieldType::Date).optional(),
        )
        .field("aaguid", optional_string())
}
