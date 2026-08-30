#[cfg(feature = "axum")]
use super::DashJwtVerifier;
use super::{InfraConnectionOptions, ResolvedConnectionOptions, VERSION};
use crate::{
    AdditionalField, AdditionalFieldType, AuthConfig, AuthError, AuthPlugin, DatabaseRecord,
    PluginArtifactMetadata, PluginClientMetadata, PluginClientPathMethod, PluginDescriptor,
    PluginEndpoint, PluginHttpMethod, PluginProvenance, PluginSchemaTable,
};
use async_trait::async_trait;
use std::{borrow::Cow, fmt, sync::Arc, time::Duration};

#[cfg(test)]
mod contract;

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

const fn endpoint(
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

/// Opt-in activity tracking published by `dash()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DashActivityTracking {
    pub enabled: bool,
    pub update_interval: Duration,
}

impl Default for DashActivityTracking {
    fn default() -> Self {
        Self {
            enabled: false,
            update_interval: Duration::from_millis(300_000),
        }
    }
}

/// Native inputs corresponding to the pinned `dash()` options owned by this endpoint family.
#[derive(Clone, Debug, Default)]
pub struct DashOptions {
    pub connection: InfraConnectionOptions,
    pub activity_tracking: DashActivityTracking,
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

    #[cfg(feature = "axum")]
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
            endpoints: Cow::Borrowed(ENDPOINTS),
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
        self.options
            .activity_tracking
            .enabled
            .then(|| {
                PluginSchemaTable::new("user").field(
                    "lastActiveAt",
                    AdditionalField::new(AdditionalFieldType::Date).optional(),
                )
            })
            .into_iter()
            .collect()
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

    async fn after_database_create(
        &self,
        service: &crate::AuthService,
        record: &DatabaseRecord,
        _context: &crate::DatabaseHookContext,
    ) -> Result<(), AuthError> {
        if self.options.activity_tracking.enabled
            && let DatabaseRecord::Session(session) = record
        {
            let _ = service.dash_touch_user_activity(&session.user_id).await;
        }
        Ok(())
    }

    #[cfg(feature = "axum")]
    async fn after_response(
        &self,
        service: &crate::AuthService,
        request: &crate::PluginRequestContext,
        response: axum::response::Response,
    ) -> axum::response::Response {
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
    fn routes(&self, service: Arc<crate::AuthService>) -> Vec<crate::AxumPluginRoute> {
        super::axum::routes(service, self.clone())
    }
}

#[cfg(feature = "axum")]
trait ValueExt {
    fn date_time(&self) -> Option<chrono::DateTime<chrono::Utc>>;
}

#[cfg(feature = "axum")]
impl ValueExt for serde_json::Value {
    fn date_time(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.as_str()?.parse().ok()
    }
}

#[cfg(feature = "axum")]
fn activity_was_recent(
    value: Option<&serde_json::Value>,
    interval: Duration,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    value
        .and_then(ValueExt::date_time)
        .is_some_and(|last_active| {
            now.signed_duration_since(last_active)
                < chrono::Duration::from_std(interval).unwrap_or(chrono::Duration::MAX)
        })
}
