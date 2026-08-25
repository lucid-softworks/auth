use super::AdminConfig;
use crate::{
    AuthConfig, AuthError, AuthPlugin, PluginClientMetadata, PluginCookie, PluginDescriptor,
    PluginEndpoint, PluginHttpMethod, SessionWithUser,
};
use async_trait::async_trait;
use chrono::Utc;
use std::sync::Arc;

const ENDPOINTS: &[PluginEndpoint] = &[
    endpoint(
        PluginHttpMethod::Get,
        "/admin/list-users",
        "admin.listUsers",
    ),
    endpoint(PluginHttpMethod::Get, "/admin/get-user", "admin.getUser"),
    endpoint(
        PluginHttpMethod::Post,
        "/admin/create-user",
        "admin.createUser",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/admin/update-user",
        "admin.updateUser",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/admin/has-permission",
        "admin.hasPermission",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/admin/set-user-password",
        "admin.setUserPassword",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/admin/remove-user",
        "admin.removeUser",
    ),
    endpoint(PluginHttpMethod::Post, "/admin/set-role", "admin.setRole"),
    endpoint(PluginHttpMethod::Post, "/admin/ban-user", "admin.banUser"),
    endpoint(
        PluginHttpMethod::Post,
        "/admin/unban-user",
        "admin.unbanUser",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/admin/list-user-sessions",
        "admin.listUserSessions",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/admin/revoke-user-session",
        "admin.revokeUserSession",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/admin/revoke-user-sessions",
        "admin.revokeUserSessions",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/admin/impersonate-user",
        "admin.impersonateUser",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/admin/stop-impersonating",
        "admin.stopImpersonating",
    ),
];

const COOKIES: &[PluginCookie] = &[PluginCookie {
    name: "better-auth.admin_session",
}];

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

#[derive(Clone, Default)]
pub struct AdminPlugin {
    config: Arc<AdminConfig>,
}

impl AdminPlugin {
    pub fn new(config: AdminConfig) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    pub fn config(&self) -> &AdminConfig {
        &self.config
    }
}

#[async_trait]
impl AuthPlugin for AdminPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "admin",
            display_name: "Better Auth Admin",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            provenance: crate::PluginProvenance::better_auth_plugin("admin"),
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Borrowed(ENDPOINTS),
            cookies: COOKIES,
            rate_limits: &[],
            middleware: &[],
            client: Some(PluginClientMetadata::official(
                "better-auth",
                "better-auth/client/plugins",
                "adminClient",
            )),
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        self.config.validate()
    }

    async fn authorize_application_access(
        &self,
        session: &SessionWithUser,
    ) -> Result<(), AuthError> {
        if session.user.banned
            && session
                .user
                .ban_expires
                .is_none_or(|expires| expires > Utc::now())
        {
            return Err(AuthError::AccountDisabled(
                self.config.banned_user_message.clone(),
            ));
        }
        Ok(())
    }

    #[cfg(feature = "axum")]
    fn routes(&self, _service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        crate::axum::admin::routes()
    }
}
