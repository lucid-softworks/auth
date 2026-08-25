use crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION;
use serde::Serialize;
use std::borrow::Cow;

/// Exact HTTP error contributed by a plugin lifecycle hook.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct PluginApiError {
    pub status: u16,
    pub code: &'static str,
    pub message: String,
}

impl PluginApiError {
    pub fn new(status: u16, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
}

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginEndpoint {
    pub method: PluginHttpMethod,
    pub path: Cow<'static, str>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_version: Option<&'static str>,
    #[serde(skip_serializing_if = "<[&str]>::is_empty")]
    pub custom_actions: &'static [&'static str],
    #[serde(skip_serializing_if = "<[&str]>::is_empty")]
    pub non_action_paths: &'static [&'static str],
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
            client_id: None,
            client_version: None,
            custom_actions: &[],
            non_action_paths: &[],
        }
    }

    pub const fn with_identity(mut self, id: &'static str, version: &'static str) -> Self {
        self.client_id = Some(id);
        self.client_version = Some(version);
        self
    }

    pub const fn with_custom_actions(mut self, actions: &'static [&'static str]) -> Self {
        self.custom_actions = actions;
        self
    }

    pub const fn with_non_action_paths(mut self, paths: &'static [&'static str]) -> Self {
        self.non_action_paths = paths;
        self
    }
}

/// Static identity, dependency, wire, and compatibility declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginDescriptor {
    pub id: &'static str,
    pub display_name: &'static str,
    pub version: &'static str,
    pub dependencies: &'static [&'static str],
    pub conflicts: &'static [&'static str],
    pub endpoints: Cow<'static, [PluginEndpoint]>,
    pub cookies: &'static [PluginCookie],
    pub rate_limits: &'static [PluginRateLimit],
    pub middleware: &'static [PluginMiddleware],
    pub client: Option<PluginClientMetadata>,
}
