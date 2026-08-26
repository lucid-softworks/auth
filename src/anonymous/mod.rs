#[cfg(feature = "axum")]
use crate::AuthService;
use crate::{
    AdditionalField, AdditionalFieldType, AuthConfig, AuthError, AuthPlugin, PluginClientMetadata,
    PluginDescriptor, PluginEndpoint, PluginHttpMethod, PluginSchemaTable, SessionWithUser,
};
use async_trait::async_trait;
use std::sync::Arc;

#[cfg(feature = "axum")]
mod axum;

const ENDPOINTS: &[PluginEndpoint] = &[
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: std::borrow::Cow::Borrowed("/sign-in/anonymous"),
        client_method: "signIn.anonymous",
    },
    PluginEndpoint {
        method: PluginHttpMethod::Post,
        path: std::borrow::Cow::Borrowed("/delete-anonymous-user"),
        client_method: "deleteAnonymousUser",
    },
];

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AnonymousSignInContext {
    pub origin: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone)]
pub struct AnonymousLinkAccount {
    pub anonymous_user: SessionWithUser,
    pub new_user: SessionWithUser,
}

#[async_trait]
pub trait AnonymousNameGenerator: Send + Sync {
    async fn generate(&self, context: &AnonymousSignInContext) -> Result<String, AuthError>;
}

#[async_trait]
pub trait AnonymousEmailGenerator: Send + Sync {
    async fn generate(&self) -> Result<String, AuthError>;
}

#[async_trait]
pub trait AnonymousLinkAccountCallback: Send + Sync {
    async fn call(&self, account: AnonymousLinkAccount) -> Result<(), AuthError>;
}

#[derive(Clone, Default)]
pub struct AnonymousPluginConfig {
    pub schema: crate::DatabaseModelSchema,
    pub email_domain_name: Option<String>,
    pub disable_delete_anonymous_user: bool,
    pub generate_name: Option<Arc<dyn AnonymousNameGenerator>>,
    pub generate_random_email: Option<Arc<dyn AnonymousEmailGenerator>>,
    pub on_link_account: Option<Arc<dyn AnonymousLinkAccountCallback>>,
}

#[derive(Clone, Default)]
pub struct AnonymousPlugin {
    pub(crate) config: Arc<AnonymousPluginConfig>,
}

impl AnonymousPlugin {
    pub fn new(config: AnonymousPluginConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}

#[async_trait]
impl AuthPlugin for AnonymousPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "anonymous",
            display_name: "Better Auth Anonymous",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            provenance: crate::PluginProvenance::better_auth_plugin("anonymous"),
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Borrowed(ENDPOINTS),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(PluginClientMetadata::official(
                "better-auth",
                "better-auth/client/plugins",
                "anonymousClient",
            )),
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        if self
            .config
            .email_domain_name
            .as_deref()
            .is_some_and(|domain| domain.trim().is_empty() || domain.contains('@'))
        {
            return Err(AuthError::InvalidConfiguration(
                "anonymous email domain must be a non-empty domain name".into(),
            ));
        }
        Ok(())
    }

    fn schema(&self) -> Vec<PluginSchemaTable> {
        vec![crate::database_schema::remap_plugin_table(
            PluginSchemaTable::new("user").field(
                "isAnonymous",
                AdditionalField::new(AdditionalFieldType::Boolean)
                    .optional()
                    .input(false)
                    .default_value(serde_json::json!(false)),
            ),
            &self.config.schema,
            false,
        )]
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<AuthService>) -> Vec<crate::AxumPluginRoute> {
        axum::routes(service, self.config.clone())
    }
}
