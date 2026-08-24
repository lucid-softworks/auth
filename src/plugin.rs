#[cfg(feature = "axum")]
use crate::AuthService;
use crate::{
    AdditionalField, AuthConfig, AuthError, AuthUser, AuthenticationMethod, DatabaseHooks,
    DatabaseModel, SessionWithUser, protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
};
use async_trait::async_trait;
use serde::Serialize;
use std::any::Any;
#[cfg(feature = "axum")]
use std::sync::Arc;
use uuid::Uuid;

mod registry;

pub(crate) use registry::PluginRegistry;

/// HTTP method owned by a native authentication plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum PluginHttpMethod {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

/// One plugin-owned wire endpoint and its official-client action name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginEndpoint {
    pub method: PluginHttpMethod,
    pub path: &'static str,
    pub client_method: &'static str,
}

/// Cookie name reserved by a plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginCookie {
    pub name: &'static str,
}

/// Per-endpoint rate-limit policy advertised by a plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginRateLimit {
    pub path: &'static str,
    pub window: u64,
    pub max: u32,
}

/// Named middleware contribution, applied in dependency order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginMiddleware {
    pub id: &'static str,
}

/// JavaScript client declaration used by compatibility tooling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginClientMetadata {
    pub package: &'static str,
    pub import_path: &'static str,
    pub factory: &'static str,
    pub better_auth_version: &'static str,
}

impl PluginClientMetadata {
    pub const fn current(
        package: &'static str,
        import_path: &'static str,
        factory: &'static str,
    ) -> Self {
        Self {
            package,
            import_path,
            factory,
            better_auth_version: COMPATIBLE_BETTER_AUTH_VERSION,
        }
    }
}

/// Static identity, dependency, wire, and compatibility declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginDescriptor {
    pub id: &'static str,
    pub display_name: &'static str,
    pub version: &'static str,
    pub dependencies: &'static [&'static str],
    pub conflicts: &'static [&'static str],
    pub endpoints: &'static [PluginEndpoint],
    pub cookies: &'static [PluginCookie],
    pub rate_limits: &'static [PluginRateLimit],
    pub middleware: &'static [PluginMiddleware],
    pub client: Option<PluginClientMetadata>,
}

/// One ordered SQL migration contributed by a plugin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PluginMigration {
    pub id: &'static str,
    pub description: &'static str,
    pub sql: &'static str,
}

/// Migration paired with the validated plugin that owns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    path: &'static str,
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
    pub fn new(path: &'static str, route: axum::routing::MethodRouter) -> Self {
        Self { path, route }
    }

    pub(crate) fn into_parts(self) -> (&'static str, axum::routing::MethodRouter) {
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

/// Native, in-process extension boundary for Better Auth-compatible plugins.
#[doc(hidden)]
pub trait PluginAny: Any {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any> PluginAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

#[async_trait]
pub trait AuthPlugin: PluginAny + Send + Sync {
    fn descriptor(&self) -> PluginDescriptor;

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        Ok(())
    }

    fn migrations(&self) -> &'static [PluginMigration] {
        &[]
    }

    /// Runtime rules contributed with the plugin's configured options.
    fn rate_limits(&self) -> Vec<PluginRateLimit> {
        self.descriptor().rate_limits.to_vec()
    }

    fn schema_fields(&self) -> Vec<PluginSchemaField> {
        Vec::new()
    }

    fn database_hooks(&self) -> Option<&dyn DatabaseHooks> {
        None
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

    #[cfg(feature = "axum")]
    async fn session_from_headers(
        &self,
        _service: &AuthService,
        _headers: &axum::http::HeaderMap,
    ) -> Result<Option<PluginSession>, AuthError> {
        Ok(None)
    }

    #[cfg(feature = "axum")]
    fn middleware(
        &self,
        route: axum::routing::MethodRouter,
        _service: Arc<AuthService>,
    ) -> axum::routing::MethodRouter {
        route
    }
}
