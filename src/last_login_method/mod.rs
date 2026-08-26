use crate::{
    AdditionalField, AdditionalFieldType, AuthConfig, AuthError, AuthPlugin, DatabaseHookContext,
    DatabaseHooks, DatabaseRecord, PluginClientMetadata, PluginCookie, PluginDescriptor,
    PluginSchemaTable,
};
use async_trait::async_trait;
use std::{fmt, future::Future, sync::Arc};

mod context;
mod database;

#[cfg(feature = "axum")]
mod axum;

pub use context::{LastLoginMethodContext, LastLoginMethodResolver};

const COOKIE_NAME: &str = "better-auth.last_used_login_method";
const COOKIES: &[PluginCookie] = &[PluginCookie { name: COOKIE_NAME }];

#[async_trait]
pub trait BeforeStoreLastLoginMethod: Send + Sync {
    async fn permit(
        &self,
        context: LastLoginMethodContext,
        method: String,
    ) -> Result<bool, AuthError>;
}

#[async_trait]
impl<F, Fut> BeforeStoreLastLoginMethod for F
where
    F: Fn(LastLoginMethodContext, String) -> Fut + Send + Sync,
    Fut: Future<Output = Result<bool, AuthError>> + Send,
{
    async fn permit(
        &self,
        context: LastLoginMethodContext,
        method: String,
    ) -> Result<bool, AuthError> {
        self(context, method).await
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LastLoginMethodUserSchema {
    pub last_login_method_field_name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LastLoginMethodSchema {
    pub user: LastLoginMethodUserSchema,
}

#[derive(Clone)]
pub struct LastLoginMethodConfig {
    pub cookie_name: String,
    /// Cookie lifetime in seconds. A floating-point value preserves Better
    /// Call's flooring, omission, and 400-day rejection behavior.
    pub max_age: f64,
    pub custom_resolve_method: Option<Arc<dyn LastLoginMethodResolver>>,
    pub store_in_database: bool,
    pub before_store_cookie: Option<Arc<dyn BeforeStoreLastLoginMethod>>,
    pub schema: LastLoginMethodSchema,
}

impl Default for LastLoginMethodConfig {
    fn default() -> Self {
        Self {
            cookie_name: COOKIE_NAME.into(),
            max_age: 60.0 * 60.0 * 24.0 * 30.0,
            custom_resolve_method: None,
            store_in_database: false,
            before_store_cookie: None,
            schema: LastLoginMethodSchema::default(),
        }
    }
}

impl fmt::Debug for LastLoginMethodConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LastLoginMethodConfig")
            .field("cookie_name", &self.cookie_name)
            .field("max_age", &self.max_age)
            .field(
                "has_custom_resolve_method",
                &self.custom_resolve_method.is_some(),
            )
            .field("store_in_database", &self.store_in_database)
            .field(
                "has_before_store_cookie",
                &self.before_store_cookie.is_some(),
            )
            .field("schema", &self.schema)
            .finish()
    }
}

#[derive(Clone)]
pub struct LastLoginMethodPlugin {
    config: Arc<LastLoginMethodConfig>,
}

impl LastLoginMethodPlugin {
    pub fn new(config: LastLoginMethodConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    pub fn config(&self) -> &LastLoginMethodConfig {
        &self.config
    }
}

impl Default for LastLoginMethodPlugin {
    fn default() -> Self {
        Self::new(LastLoginMethodConfig::default())
    }
}

impl fmt::Debug for LastLoginMethodPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LastLoginMethodPlugin")
            .field("config", &self.config)
            .finish()
    }
}

#[async_trait]
impl AuthPlugin for LastLoginMethodPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "last-login-method",
            display_name: "Better Auth Last Login Method",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            provenance: crate::PluginProvenance::better_auth_plugin("lastLoginMethod"),
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Borrowed(&[]),
            cookies: COOKIES,
            rate_limits: &[],
            middleware: &[],
            client: Some(PluginClientMetadata::official(
                "better-auth",
                "better-auth/client/plugins",
                "lastLoginMethodClient",
            )),
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        Ok(())
    }

    fn schema(&self) -> Vec<PluginSchemaTable> {
        if !self.config.store_in_database {
            return Vec::new();
        }
        let field_name = self
            .config
            .schema
            .user
            .last_login_method_field_name
            .as_deref()
            .filter(|name| !name.is_empty())
            .unwrap_or("lastLoginMethod");
        vec![
            PluginSchemaTable::new("user").field(
                "lastLoginMethod",
                AdditionalField::new(AdditionalFieldType::String)
                    .optional()
                    .input(false)
                    .field_name(field_name),
            ),
        ]
    }

    fn database_hooks(&self) -> Option<&dyn DatabaseHooks> {
        self.config.store_in_database.then_some(self)
    }

    async fn after_database_create(
        &self,
        service: &crate::AuthService,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        database::after_create(self, service, record, context).await
    }

    #[cfg(feature = "axum")]
    async fn after_response(
        &self,
        service: &crate::AuthService,
        request: &crate::PluginRequestContext,
        response: ::axum::response::Response,
    ) -> ::axum::response::Response {
        axum::after_response(self, service, request, response).await
    }
}
