#[cfg(feature = "axum")]
use super::DashJwtVerifier;
use super::{InfraConnectionOptions, ResolvedConnectionOptions, VERSION};
use crate::{
    AdditionalField, AdditionalFieldType, AuthConfig, AuthError, AuthPlugin, DatabaseRecord,
    PluginArtifactMetadata, PluginClientMetadata, PluginClientPathMethod, PluginDescriptor,
    PluginEndpoint, PluginHttpMethod, PluginProvenance, PluginSchemaTable,
};
use async_trait::async_trait;
use std::{borrow::Cow, fmt, sync::Arc};

#[cfg(test)]
mod contract;
#[cfg(feature = "axum")]
mod activity;
mod directory_schema;
mod endpoints;
mod options;

#[cfg(feature = "axum")]
use activity::activity_was_recent;

pub use options::{
    DashActivityTracking, DashDirectoryMembershipProjection, DashManagedDirectorySync, DashOptions,
};

const ENDPOINTS: &[PluginEndpoint] = &[
    endpoint(PluginHttpMethod::Get, "/dash/config", "getDashConfig"),
    endpoint(PluginHttpMethod::Get, "/dash/validate", "getDashValidate"),
    endpoint(PluginHttpMethod::Get, "/dash/list-users", "getDashUsers"),
    endpoint(
        PluginHttpMethod::Get,
        "/dash/export-users",
        "exportDashUsers",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/create-user",
        "createDashUser",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/delete-user",
        "deleteDashUser",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/delete-many-users",
        "deleteManyDashUsers",
    ),
    endpoint(PluginHttpMethod::Get, "/dash/user", "getDashUser"),
    endpoint(
        PluginHttpMethod::Get,
        "/dash/user-organizations",
        "getDashUserOrganizations",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/update-user",
        "updateDashUser",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/unlink-account",
        "unlinkDashAccount",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/set-password",
        "setDashPassword",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/sessions/revoke",
        "dashRevokeSession",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/sessions/revoke-all",
        "dashRevokeAllSessions",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/sessions/revoke-many",
        "dashRevokeManySessions",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/dash/impersonate-user",
        "dashImpersonateUser",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/dash/user-stats",
        "dashGetUserStats",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/dash/user-graph-data",
        "dashGetUserGraphData",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/dash/user-retention-data",
        "dashGetUserRetentionData",
    ),
    endpoint(PluginHttpMethod::Post, "/dash/ban-user", "dashBanUser"),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/ban-many-users",
        "dashBanManyUsers",
    ),
    endpoint(PluginHttpMethod::Post, "/dash/unban-user", "dashUnbanUser"),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/send-verification-email",
        "dashSendVerificationEmail",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/send-many-verification-emails",
        "dashSendManyVerificationEmails",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/send-reset-password-email",
        "dashSendResetPasswordEmail",
    ),
    endpoint(
        PluginHttpMethod::Post,
        "/dash/execute-adapter",
        "dashExecuteAdapter",
    ),
    endpoint(PluginHttpMethod::Get, "/events/list", "getUserEvents"),
    endpoint(
        PluginHttpMethod::Get,
        "/events/audit-logs",
        "dash.getAuditLogs",
    ),
    endpoint(
        PluginHttpMethod::Get,
        "/events/all-audit-logs",
        "dash.getAllAuditLogs",
    ),
    endpoint(PluginHttpMethod::Get, "/events/types", "getEventTypes"),
];

const CLIENT_ACTIONS: &[&str] = &["dash.getAuditLogs", "dash.getAllAuditLogs"];
const CLIENT_NON_ACTION_PATHS: &[&str] = &["/events/list", "/events/types"];
const CLIENT_PATH_METHODS: &[PluginClientPathMethod] = &[
    PluginClientPathMethod::new("/events/audit-logs", PluginHttpMethod::Get),
    PluginClientPathMethod::new("/events/all-audit-logs", PluginHttpMethod::Get),
];

pub(super) const fn endpoint(
    method: PluginHttpMethod,
    path: &'static str,
    client_method: &'static str,
) -> PluginEndpoint {
    PluginEndpoint {
        method,
        path: Cow::Borrowed(path),
        client_method,
    }
}

/// Native port of the core endpoint family from `@better-auth/infra`'s `dash()` plugin.
#[derive(Clone)]
pub struct DashPlugin {
    options: Arc<DashOptions>,
    connection: Arc<ResolvedConnectionOptions>,
    #[cfg(feature = "axum")]
    verifier: DashJwtVerifier,
}

impl DashPlugin {
    pub fn new(options: DashOptions) -> Self {
        let connection = Arc::new(options.connection.clone().resolve());
        #[cfg(feature = "axum")]
        let verifier = DashJwtVerifier::new(&connection);
        Self {
            options: Arc::new(options),
            connection,
            #[cfg(feature = "axum")]
            verifier,
        }
    }

    pub fn options(&self) -> &DashOptions {
        &self.options
    }

    #[cfg(feature = "axum")]
    pub(crate) fn verifier(&self) -> &DashJwtVerifier {
        &self.verifier
    }

    pub(crate) fn resolved_connection(&self) -> &ResolvedConnectionOptions {
        &self.connection
    }
}

impl Default for DashPlugin {
    fn default() -> Self {
        Self::new(DashOptions::default())
    }
}

impl fmt::Debug for DashPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DashPlugin")
            .field("options", &self.options)
            .field("connection", &self.connection)
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl AuthPlugin for DashPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        let mut endpoints = ENDPOINTS.to_vec();
        endpoints.extend_from_slice(endpoints::MANAGEMENT);
        endpoints.extend_from_slice(endpoints::DIRECTORY_CONTROL_PLANE);
        PluginDescriptor {
            id: "dash",
            display_name: "Better Auth Infrastructure Dash",
            version: VERSION,
            provenance: PluginProvenance::PinnedBetterAuthPort {
                better_auth_version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
                server: PluginArtifactMetadata::new(
                    "@better-auth/infra",
                    VERSION,
                    "@better-auth/infra",
                    "dash",
                ),
            },
            dependencies: &[],
            conflicts: &[],
            endpoints: Cow::Owned(endpoints),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(
                PluginClientMetadata::official(
                    "@better-auth/infra",
                    "@better-auth/infra/client",
                    "dashClient",
                )
                .with_identity("dash", VERSION)
                .with_custom_actions(CLIENT_ACTIONS)
                .with_non_action_paths(CLIENT_NON_ACTION_PATHS)
                .with_path_methods(CLIENT_PATH_METHODS),
            ),
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        Ok(())
    }

    fn schema(&self) -> Vec<PluginSchemaTable> {
        let mut schema = Vec::new();
        if self.options.activity_tracking.enabled {
            schema.push(
                PluginSchemaTable::new("user").field(
                    "lastActiveAt",
                    AdditionalField::new(AdditionalFieldType::Date).optional(),
                ),
            );
        }
        if self.options.managed_directory_sync.enabled {
            schema.extend(directory_schema::tables());
        }
        schema
    }

    fn request_origin_fields(
        &self,
        method: PluginHttpMethod,
        path: &str,
    ) -> &'static [&'static str] {
        if method == PluginHttpMethod::Post
            && matches!(
                path,
                "/dash/send-verification-email"
                    | "/dash/send-many-verification-emails"
                    | "/dash/send-reset-password-email"
            )
        {
            &["callbackUrl"]
        } else {
            &[]
        }
    }

    #[cfg(feature = "axum")]
    async fn on_request(
        &self,
        _service: &crate::AuthService,
        request: axum::extract::Request,
    ) -> Result<axum::extract::Request, axum::response::Response> {
        super::axum::capture_request_body(request).await
    }

    #[cfg(feature = "axum")]
    fn contributes_on_request(&self) -> bool {
        true
    }

    async fn after_database_create(
        &self,
        service: &crate::AuthService,
        record: &DatabaseRecord,
        context: &crate::DatabaseHookContext,
    ) -> Result<(), AuthError> {
        if self.options.activity_tracking.enabled
            && let DatabaseRecord::Session(session) = record
        {
            let _ = service.dash_touch_user_activity(&session.user_id).await;
        }
        super::projection::after_create(self, service, record, context).await;
        Ok(())
    }

    async fn after_database_update(
        &self,
        service: &crate::AuthService,
        record: &DatabaseRecord,
        context: &crate::DatabaseHookContext,
    ) -> Result<(), AuthError> {
        super::projection::after_update(self, service, record, context).await;
        Ok(())
    }

    async fn after_database_delete(
        &self,
        service: &crate::AuthService,
        record: &DatabaseRecord,
        context: &crate::DatabaseHookContext,
    ) -> Result<(), AuthError> {
        super::projection::after_delete(self, service, record, context).await;
        Ok(())
    }

    async fn after_organization(&self, event: &crate::AfterOrganizationEvent<'_>) {
        super::projection::organization(self, event);
    }

    #[cfg(feature = "axum")]
    async fn after_response(
        &self,
        service: &crate::AuthService,
        request: &crate::PluginRequestContext,
        response: axum::response::Response,
    ) -> axum::response::Response {
        let failed = response.status().is_client_error()
            || response.status().is_server_error()
            || response
                .extensions()
                .get::<crate::axum::ApiErrorResponse>()
                .is_some();
        let body = response
            .extensions()
            .get::<crate::plugin::CapturedPluginRequestBody>()
            .and_then(|body| body.0.as_object().cloned());
        let new_session = response
            .extensions()
            .get::<crate::axum::http::BoundSession>()
            .map(|session| session.0.clone());
        super::projection::after_response(
            self,
            service,
            request,
            failed,
            body,
            new_session,
        )
        .await;
        let tracking = self.options.activity_tracking;
        if !tracking.enabled
            || tracking.update_interval.is_zero()
            || request.method.eq_ignore_ascii_case("GET")
        {
            return response;
        }

        let mut headers = axum::http::HeaderMap::new();
        for (name, value) in &request.headers {
            if let (Ok(name), Ok(value)) = (
                name.parse::<axum::http::HeaderName>(),
                value.parse::<axum::http::HeaderValue>(),
            ) {
                headers.append(name, value);
            }
        }
        let Ok(Some(session)) = service.plugin_session(&headers).await else {
            return response;
        };
        let recently_active = activity_was_recent(
            session.session.user.additional_fields.get("lastActiveAt"),
            tracking.update_interval,
            chrono::Utc::now(),
        );
        if !recently_active {
            let _ = service
                .dash_touch_user_activity(&session.session.user.id)
                .await;
        }
        response
    }

    #[cfg(feature = "axum")]
    fn contributes_on_response(&self) -> bool {
        true
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        super::axum::routes(service, self.clone())
    }
}
