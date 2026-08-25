#[cfg(feature = "axum")]
use crate::AuthService;
use crate::{
    AdditionalField, AuthConfig, AuthError, AuthUser, AuthenticationMethod, DatabaseHooks,
    DatabaseModel, SessionWithUser,
};
use async_trait::async_trait;
use std::borrow::Cow;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginRequestContext {
    pub method: String,
    pub path: String,
    pub query: Option<String>,
    pub headers: std::collections::BTreeMap<String, String>,
}

/// Browser-security policy selected by an installed plugin for one route.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum PluginRequestSecurity {
    #[default]
    Browser,
    /// Public provider callback whose untouched body is authenticated by the
    /// plugin itself.
    RawPublic,
    /// Applies origin enforcement only when the request carries cookies.
    CookieOrigin,
}

mod any;
mod metadata;
mod registry;

use any::PluginAny;
pub use metadata::*;
pub(crate) use registry::PluginRegistry;

/// One ordered SQL migration contributed by a plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginMigration {
    pub id: Cow<'static, str>,
    pub description: Cow<'static, str>,
    pub sql: Cow<'static, str>,
}

impl PluginMigration {
    pub const fn borrowed(id: &'static str, description: &'static str, sql: &'static str) -> Self {
        Self {
            id: Cow::Borrowed(id),
            description: Cow::Borrowed(description),
            sql: Cow::Borrowed(sql),
        }
    }

    pub fn owned(
        id: impl Into<String>,
        description: impl Into<String>,
        sql: impl Into<String>,
    ) -> Self {
        Self {
            id: Cow::Owned(id.into()),
            description: Cow::Owned(description.into()),
            sql: Cow::Owned(sql.into()),
        }
    }
}

/// Migration paired with the validated plugin that owns it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginMigrationContribution {
    pub plugin_id: &'static str,
    pub migration: PluginMigration,
}

/// Additional Better Auth database field contributed by a native plugin.
#[derive(Debug, Clone)]
pub struct PluginSchemaField {
    pub model: DatabaseModel,
    pub name: String,
    pub field: AdditionalField,
}

impl PluginSchemaField {
    pub fn new(model: DatabaseModel, name: impl Into<String>, field: AdditionalField) -> Self {
        Self {
            model,
            name: name.into(),
            field,
        }
    }
}

/// Erased Axum route contributed without constraining the host router's state.
#[cfg(feature = "axum")]
#[derive(Clone)]
pub struct AxumPluginRoute {
    path: String,
    route: axum::routing::MethodRouter,
}

#[cfg(feature = "axum")]
#[derive(Debug, Clone)]
pub struct PluginSession {
    pub session: SessionWithUser,
    pub token: String,
}

#[cfg(feature = "axum")]
impl AxumPluginRoute {
    pub fn new(path: impl Into<String>, route: axum::routing::MethodRouter) -> Self {
        Self {
            path: path.into(),
            route,
        }
    }

    pub(crate) fn into_parts(self) -> (String, axum::routing::MethodRouter) {
        (self.path, self.route)
    }
}

/// Veto-capable lifecycle events emitted before persistence.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum BeforeAuthEvent {
    SessionCreate {
        user: AuthUser,
        authentication_method: AuthenticationMethod,
        actor_user_id: Option<Uuid>,
    },
    UserDelete {
        user: AuthUser,
    },
}

/// Observational lifecycle events emitted after a successful write.
#[derive(Debug, Clone)]
#[non_exhaustive]
// Keep the public event payloads inline; registry dispatch borrows the event.
#[allow(clippy::large_enum_variant)]
pub enum AfterAuthEvent {
    SessionCreated { session: SessionWithUser },
    UserDeleted { user: AuthUser },
}

/// Typed authorization point for optional host security policy plugins.
pub struct SensitiveOperation<'a> {
    pub session: &'a SessionWithUser,
    pub operation: &'static str,
}

/// Typed user-management action inspected by optional native host policy plugins.
pub struct UserManagementOperation<'a> {
    pub actor: &'a SessionWithUser,
    pub action: UserManagementAction<'a>,
}

pub enum UserManagementAction<'a> {
    Create {
        role: &'a str,
    },
    ChangeRole {
        target: &'a AuthUser,
        new_role: &'a str,
    },
    ChangeBan {
        target: &'a AuthUser,
        banned: bool,
    },
    Delete {
        target: &'a AuthUser,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UserManagementDecision {
    pub revoke_target_sessions: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordCredentialSource {
    Provisioned,
    AdministratorCreated,
    AdministratorReset,
    SelfServiceChange,
    PasswordReset,
}

pub struct PasswordCredentialChanged {
    pub user_id: Uuid,
    pub source: PasswordCredentialSource,
}

#[async_trait]
pub trait AuthPlugin: PluginAny + Send + Sync {
    fn descriptor(&self) -> PluginDescriptor;

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        Ok(())
    }

    fn migrations(&self) -> Cow<'_, [PluginMigration]> {
        Cow::Borrowed(&[])
    }

    /// Runtime rules contributed with the plugin's configured options.
    fn rate_limits(&self) -> Vec<PluginRateLimit> {
        self.descriptor().rate_limits.to_vec()
    }

    fn schema_fields(&self) -> Vec<PluginSchemaField> {
        Vec::new()
    }

    fn open_api_endpoints(&self) -> Vec<crate::OpenApiEndpoint> {
        crate::open_api::endpoints_from_descriptor(&self.descriptor())
    }

    fn open_api_models(&self) -> Vec<crate::OpenApiModel> {
        Vec::new()
    }

    /// Selects request-security handling for one plugin-owned route.
    fn request_security(&self, _method: PluginHttpMethod, _path: &str) -> PluginRequestSecurity {
        PluginRequestSecurity::Browser
    }

    /// Callback/redirect request fields that use Better Auth's trusted-origin
    /// validation for one plugin route.
    fn request_origin_fields(
        &self,
        _method: PluginHttpMethod,
        _path: &str,
    ) -> &'static [&'static str] {
        &[]
    }

    /// Social providers registered by a plugin ahead of core providers.
    fn social_providers(&self) -> Vec<Arc<dyn crate::SocialProvider>> {
        Vec::new()
    }

    /// Contributes capabilities to an installed OAuth Provider companion.
    ///
    /// Companion plugins use this during registry construction and request
    /// dispatch, matching Better Auth's `extendOAuthProvider` initialization
    /// contract without requiring the application to wire the same extension
    /// object into two plugin configurations.
    fn oauth_provider_extensions(&self) -> Vec<Arc<dyn crate::OAuthProviderExtension>> {
        Vec::new()
    }

    fn database_hooks(&self) -> Option<&dyn DatabaseHooks> {
        None
    }

    /// Runs service-aware work after a database record has been created.
    async fn after_database_create(
        &self,
        _service: &crate::AuthService,
        _record: &crate::DatabaseRecord,
        _context: &crate::DatabaseHookContext,
    ) -> Result<(), AuthError> {
        Ok(())
    }

    /// Runs service-aware work after a database record has been updated.
    async fn after_database_update(
        &self,
        _service: &crate::AuthService,
        _record: &crate::DatabaseRecord,
        _context: &crate::DatabaseHookContext,
    ) -> Result<(), AuthError> {
        Ok(())
    }

    /// Runs service-aware preparation before a database record is deleted.
    async fn before_database_delete(
        &self,
        _service: &crate::AuthService,
        _record: &crate::DatabaseRecord,
        _context: &crate::DatabaseHookContext,
    ) -> Result<(), AuthError> {
        Ok(())
    }

    /// Runs service-aware work after a database record has been deleted.
    async fn after_database_delete(
        &self,
        _service: &crate::AuthService,
        _record: &crate::DatabaseRecord,
        _context: &crate::DatabaseHookContext,
    ) -> Result<(), AuthError> {
        Ok(())
    }

    async fn before(&self, _event: &BeforeAuthEvent) -> Result<(), AuthError> {
        Ok(())
    }

    async fn after(&self, _event: &AfterAuthEvent) {}

    /// Initializes security-critical plugin state for a newly persisted session.
    async fn initialize_session(&self, _session: &SessionWithUser) -> Result<(), AuthError> {
        Ok(())
    }

    /// Clears plugin-owned authentication factors after a host security reset.
    async fn reset_user_security_state(&self, _user_id: Uuid) -> Result<(), AuthError> {
        Ok(())
    }

    async fn password_credential_changed(
        &self,
        _event: &PasswordCredentialChanged,
    ) -> Result<(), AuthError> {
        Ok(())
    }

    /// Applies optional host policy before exposing a principal to application code.
    async fn authorize_application_access(
        &self,
        _session: &SessionWithUser,
    ) -> Result<(), AuthError> {
        Ok(())
    }

    /// Applies optional policy to a security-sensitive native operation.
    async fn authorize_sensitive(
        &self,
        _operation: &SensitiveOperation<'_>,
    ) -> Result<(), AuthError> {
        Ok(())
    }

    /// Applies host-product invariants to Better Auth Admin user changes.
    async fn authorize_user_management(
        &self,
        _store: &dyn crate::AuthStore,
        _operation: &UserManagementOperation<'_>,
    ) -> Result<UserManagementDecision, AuthError> {
        Ok(UserManagementDecision::default())
    }

    /// Adds optional host authorization metadata to a neutral core principal.
    fn project_principal(&self, _session: &SessionWithUser, _principal: &mut crate::Principal) {}

    /// Rejects a persisted session when plugin-owned state has expired or been revoked.
    async fn validate_session(&self, _session: &SessionWithUser) -> Result<bool, AuthError> {
        Ok(true)
    }

    #[cfg(feature = "axum")]
    fn routes(&self, _service: Arc<AuthService>) -> Vec<AxumPluginRoute> {
        Vec::new()
    }

    /// Adds routes that must live outside the configured Better Auth base path.
    ///
    /// Standards such as RFC 8414 derive discovery URLs from an issuer path and
    /// therefore cannot always be represented by a route nested under
    /// `AuthConfig::base_path()`. Most plugins should continue using `routes`.
    #[cfg(feature = "axum")]
    fn root_routes(&self, _service: Arc<AuthService>) -> Vec<AxumPluginRoute> {
        Vec::new()
    }

    #[cfg(feature = "axum")]
    async fn session_from_headers(
        &self,
        _service: &AuthService,
        _headers: &axum::http::HeaderMap,
    ) -> Result<Option<PluginSession>, AuthError> {
        Ok(None)
    }

    /// Runs before route dispatch and may replace the request or short-circuit
    /// with a direct response. Hooks run in plugin registration order.
    #[cfg(feature = "axum")]
    async fn on_request(
        &self,
        _service: &AuthService,
        request: axum::extract::Request,
    ) -> Result<axum::extract::Request, axum::response::Response> {
        Ok(request)
    }

    #[cfg(feature = "axum")]
    fn middleware(
        &self,
        route: axum::routing::MethodRouter,
        _service: Arc<AuthService>,
    ) -> axum::routing::MethodRouter {
        route
    }

    #[cfg(feature = "axum")]
    async fn after_response(
        &self,
        _service: &AuthService,
        _request: &PluginRequestContext,
        response: axum::response::Response,
    ) -> axum::response::Response {
        response
    }
}
