#[cfg(feature = "axum")]
use crate::AuthService;
use crate::{
    Assurance, AuthConfig, AuthError, AuthUser, SessionWithUser,
    protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
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
    pub window_seconds: u64,
    pub max_requests: u32,
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
        assurance: Assurance,
        actor_user_id: Option<Uuid>,
        guest_grant_id: Option<Uuid>,
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

    async fn before(&self, _event: &BeforeAuthEvent) -> Result<(), AuthError> {
        Ok(())
    }

    async fn after(&self, _event: &AfterAuthEvent) {}

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
