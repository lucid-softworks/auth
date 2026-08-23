mod service;

pub use service::{OperatorSecurityService, OperatorSecurityStatus};

use crate::{
    AfterAuthEvent, AuthConfig, AuthError, AuthPlugin, PasswordCredentialChanged,
    PasswordCredentialSource, PluginDescriptor, PluginMigration, SensitiveOperation,
    SessionWithUser,
};
use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

const PLUGIN_ID: &str = "lucid-operator-security";
const MIGRATIONS: &[PluginMigration] = &[PluginMigration {
    id: "extract-managed-password-policy",
    description: "Lucid operator temporary-password state",
    sql: include_str!("../../migrations/operator_security_plugin.sql"),
}];

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OperatorSecurityError {
    #[error("a temporary password must be replaced before accessing the application")]
    TemporaryPasswordRequired,
    #[error("local recovery requires the named account to be the sole owner")]
    SoleOwnerRecoveryUnavailable,
}

#[async_trait]
pub trait OperatorSecurityStore: Send + Sync {
    async fn is_temporary_password(&self, user_id: Uuid) -> Result<bool, AuthError>;
    async fn set_temporary_password(&self, user_id: Uuid, temporary: bool)
    -> Result<(), AuthError>;
    async fn recover_sole_owner(
        &self,
        user_id: Uuid,
        owner_role: &str,
        password_hash: String,
    ) -> Result<bool, AuthError>;
}

#[derive(Debug, Clone)]
pub struct OperatorSecurityConfig {
    pub administrator_passwords_are_temporary: bool,
    pub provisioned_passwords_are_temporary: bool,
}

impl Default for OperatorSecurityConfig {
    fn default() -> Self {
        Self {
            administrator_passwords_are_temporary: true,
            provisioned_passwords_are_temporary: false,
        }
    }
}

#[derive(Clone)]
pub struct OperatorSecurityPlugin {
    pub(crate) store: Arc<dyn OperatorSecurityStore>,
    pub(crate) config: Arc<OperatorSecurityConfig>,
}

impl OperatorSecurityPlugin {
    pub fn new(store: Arc<dyn OperatorSecurityStore>, config: OperatorSecurityConfig) -> Self {
        Self {
            store,
            config: Arc::new(config),
        }
    }

    pub(crate) async fn status(&self, user_id: Uuid) -> Result<OperatorSecurityStatus, AuthError> {
        Ok(OperatorSecurityStatus {
            temporary_password: self.store.is_temporary_password(user_id).await?,
        })
    }

    async fn enforce(&self, session: &SessionWithUser) -> Result<(), AuthError> {
        if self.store.is_temporary_password(session.user.id).await? {
            return Err(OperatorSecurityError::TemporaryPasswordRequired.into());
        }
        Ok(())
    }
}

#[async_trait]
impl AuthPlugin for OperatorSecurityPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: PLUGIN_ID,
            display_name: "Lucid Operator Security",
            version: env!("CARGO_PKG_VERSION"),
            dependencies: &["lucid-owner-policy"],
            conflicts: &[],
            endpoints: &[],
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        Ok(())
    }

    fn migrations(&self) -> &'static [PluginMigration] {
        MIGRATIONS
    }

    async fn password_credential_changed(
        &self,
        event: &PasswordCredentialChanged,
    ) -> Result<(), AuthError> {
        let temporary = match event.source {
            PasswordCredentialSource::AdministratorCreated
            | PasswordCredentialSource::AdministratorReset => {
                self.config.administrator_passwords_are_temporary
            }
            PasswordCredentialSource::Provisioned => {
                if !self.config.provisioned_passwords_are_temporary {
                    return Ok(());
                }
                true
            }
            PasswordCredentialSource::SelfServiceChange
            | PasswordCredentialSource::PasswordReset => false,
        };
        self.store
            .set_temporary_password(event.user_id, temporary)
            .await
    }

    async fn authorize_application_access(
        &self,
        session: &SessionWithUser,
    ) -> Result<(), AuthError> {
        self.enforce(session).await
    }

    async fn authorize_sensitive(
        &self,
        operation: &SensitiveOperation<'_>,
    ) -> Result<(), AuthError> {
        self.enforce(operation.session).await
    }

    async fn reset_user_security_state(&self, user_id: Uuid) -> Result<(), AuthError> {
        self.store.set_temporary_password(user_id, false).await
    }

    async fn after(&self, event: &AfterAuthEvent) {
        if let AfterAuthEvent::UserDeleted { user } = event {
            let _ = self.store.set_temporary_password(user.id, false).await;
        }
    }
}
