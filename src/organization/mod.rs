#[cfg(feature = "axum")]
use crate::AuthService;
use crate::{AuthConfig, AuthError, AuthPlugin, PluginClientMetadata, PluginDescriptor};
use async_trait::async_trait;
use std::sync::Arc;

#[cfg(feature = "axum")]
mod axum;
mod config;
mod endpoints;
mod error;
mod hooks;
mod memory;
mod model;
mod schema_catalog;
mod store;

pub use config::{
    OrganizationCreationPolicy, OrganizationDynamicAccessControlConfig,
    OrganizationInvitationEmail, OrganizationInvitationEmailSender, OrganizationPluginConfig,
    OrganizationSchema, OrganizationTeamsConfig,
};
pub use error::{OrganizationError, OrganizationErrorStatus};
pub use hooks::OrganizationLifecycleHooks;
pub use memory::MemoryOrganizationStore;
pub use model::{
    FullOrganization, NewOrganization, NewOrganizationInvitation, Organization,
    OrganizationCreation, OrganizationInvitation, OrganizationInvitationAcceptance,
    OrganizationInvitationDetails, OrganizationInvitationStatus, OrganizationMember,
    OrganizationMemberWithUser, OrganizationPermissions, OrganizationRole, OrganizationTeam,
    OrganizationTeamMember, OrganizationUpdate,
};
pub use store::{
    OrganizationCreateOutcome, OrganizationDataStore, OrganizationInvitationStore,
    OrganizationInvitationWriteOutcome, OrganizationMemberStore, OrganizationMemberWriteOutcome,
    OrganizationRoleStore, OrganizationStore, OrganizationTeamStore, OrganizationTeamWriteOutcome,
};

#[derive(Clone)]
pub struct OrganizationPlugin {
    pub(crate) store: Arc<dyn OrganizationStore>,
    pub(crate) config: Arc<OrganizationPluginConfig>,
}

impl OrganizationPlugin {
    pub fn new(store: Arc<dyn OrganizationStore>) -> Self {
        Self::with_config(store, OrganizationPluginConfig::default())
    }

    pub fn with_config(
        store: Arc<dyn OrganizationStore>,
        config: OrganizationPluginConfig,
    ) -> Self {
        Self {
            store,
            config: Arc::new(config),
        }
    }
}

#[async_trait]
impl AuthPlugin for OrganizationPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "organization",
            display_name: "Better Auth Organization",
            version: crate::protocol::better_auth::COMPATIBLE_BETTER_AUTH_VERSION,
            provenance: crate::PluginProvenance::better_auth_plugin("organization"),
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Borrowed(endpoints::for_options(
                self.config.teams.enabled,
                self.config.dynamic_access_control.enabled,
            )),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: Some(PluginClientMetadata::official(
                "better-auth",
                "better-auth/client/plugins",
                "organizationClient",
            )),
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        if self.config.membership_limit == 0
            || self.config.invitation_limit == 0
            || self.config.invitation_expires_in_seconds <= 0
            || self.config.creator_role.trim().is_empty()
        {
            return Err(AuthError::InvalidConfiguration(
                "organization limits, invitation expiry, and creator role must be positive".into(),
            ));
        }
        if !self.config.roles.contains_key(&self.config.creator_role) {
            return Err(AuthError::InvalidConfiguration(
                "organization creator role must have configured permissions".into(),
            ));
        }
        Ok(())
    }

    fn schema(&self) -> Vec<crate::PluginSchemaTable> {
        schema_catalog::tables(&self.config)
    }

    #[cfg(feature = "axum")]
    fn routes(&self, service: Arc<AuthService>) -> Vec<crate::AxumPluginRoute> {
        axum::routes(service)
    }
}
