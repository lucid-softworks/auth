mod memory;
mod recovery;

pub use memory::MemoryStepUpStore;
pub use recovery::{RecoveryCodeStatus, StepUpPolicyService};

use crate::{
    AfterAuthEvent, AuthConfig, AuthError, AuthPlugin, AuthStore, AuthenticationMethod,
    PluginDescriptor, PluginMigration, SensitiveOperation, SessionWithUser,
};
use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::sync::Arc;
use uuid::Uuid;

const MIGRATIONS: &[PluginMigration] = &[PluginMigration::borrowed(
    "extract-step-up-policy",
    "Lucid step-up assurance and recovery-code state",
    include_str!("../../migrations/step_up_policy_plugin.sql"),
)];

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum StepUpError {
    #[error("recovery codes are not enabled for this account")]
    RecoveryCodesNotEnabled,
    #[error("the recovery code is invalid")]
    InvalidRecoveryCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepUpAssurance {
    PendingEnrollment,
    PendingPasskey,
    StrongPasskey,
    StrongTwoFactor,
    Recovery,
}

impl StepUpAssurance {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PendingEnrollment => "pending_enrollment",
            Self::PendingPasskey => "pending_passkey",
            Self::StrongPasskey => "strong_passkey",
            Self::StrongTwoFactor => "strong_two_factor",
            Self::Recovery => "recovery",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "pending_enrollment" => Some(Self::PendingEnrollment),
            "pending_passkey" => Some(Self::PendingPasskey),
            "strong_passkey" => Some(Self::StrongPasskey),
            "strong_two_factor" => Some(Self::StrongTwoFactor),
            "recovery" => Some(Self::Recovery),
            _ => None,
        }
    }

    pub const fn is_strong(self) -> bool {
        matches!(
            self,
            Self::StrongPasskey | Self::StrongTwoFactor | Self::Recovery
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepUpSession {
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub assurance: StepUpAssurance,
    pub authenticated_at: DateTime<Utc>,
}

/// Plugin-owned projection for hosts that surface custom step-up UI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepUpSessionProjection {
    pub required: bool,
    pub assurance: Option<StepUpAssurance>,
    pub authenticated_at: Option<DateTime<Utc>>,
    pub fresh: bool,
    pub step_up_required: bool,
}

#[async_trait]
pub trait StepUpStore: Send + Sync {
    async fn upsert_step_up_session(&self, session: StepUpSession) -> Result<(), AuthError>;
    async fn find_step_up_session(
        &self,
        session_id: Uuid,
    ) -> Result<Option<StepUpSession>, AuthError>;
    async fn delete_step_up_session(&self, session_id: Uuid) -> Result<(), AuthError>;
    async fn delete_user_step_up_state(&self, user_id: Uuid) -> Result<(), AuthError>;
    async fn replace_step_up_recovery_codes(
        &self,
        user_id: Uuid,
        code_hashes: Vec<String>,
    ) -> Result<(), AuthError>;
    async fn consume_step_up_recovery_code(
        &self,
        user_id: Uuid,
        code_hash: &str,
    ) -> Result<bool, AuthError>;
    async fn step_up_recovery_code_count(&self, user_id: Uuid) -> Result<usize, AuthError>;
    async fn delete_step_up_recovery_codes(&self, user_id: Uuid) -> Result<(), AuthError>;
}

#[derive(Debug, Clone)]
pub struct StepUpPolicyConfig {
    pub required_roles: Vec<String>,
    pub freshness: Duration,
    pub recovery_code_count: usize,
    pub recovery_rate_limit_window: Duration,
    pub recovery_rate_limit_max: u32,
}

impl Default for StepUpPolicyConfig {
    fn default() -> Self {
        Self {
            required_roles: Vec::new(),
            freshness: Duration::days(1),
            recovery_code_count: 10,
            recovery_rate_limit_window: Duration::minutes(5),
            recovery_rate_limit_max: 5,
        }
    }
}

#[derive(Clone)]
pub struct StepUpPolicyPlugin {
    pub(crate) auth_store: Arc<dyn AuthStore>,
    pub(crate) store: Arc<dyn StepUpStore>,
    pub(crate) config: Arc<StepUpPolicyConfig>,
}

impl StepUpPolicyPlugin {
    pub fn new(
        auth_store: Arc<dyn AuthStore>,
        store: Arc<dyn StepUpStore>,
        config: StepUpPolicyConfig,
    ) -> Self {
        Self {
            auth_store,
            store,
            config: Arc::new(config),
        }
    }

    pub(crate) fn requires(&self, role: &str) -> bool {
        self.config
            .required_roles
            .iter()
            .any(|required| required == role)
    }

    async fn initial_assurance(
        &self,
        session: &SessionWithUser,
    ) -> Result<StepUpAssurance, AuthError> {
        match session.session.authentication_method {
            AuthenticationMethod::Passkey => Ok(StepUpAssurance::StrongPasskey),
            AuthenticationMethod::TwoFactor => Ok(StepUpAssurance::StrongTwoFactor),
            _ if self
                .auth_store
                .list_passkeys(session.user.id)
                .await?
                .is_empty() =>
            {
                Ok(StepUpAssurance::PendingEnrollment)
            }
            _ => Ok(StepUpAssurance::PendingPasskey),
        }
    }

    pub(crate) async fn project_session(
        &self,
        session: &SessionWithUser,
    ) -> Result<StepUpSessionProjection, AuthError> {
        if !self.requires(&session.user.role) || session.session.actor_user_id.is_some() {
            return Ok(StepUpSessionProjection {
                required: false,
                assurance: None,
                authenticated_at: None,
                fresh: true,
                step_up_required: false,
            });
        }
        let state = self
            .store
            .find_step_up_session(session.session.id)
            .await?
            .filter(|state| state.user_id == session.user.id);
        let fresh = state.as_ref().is_some_and(|state| {
            state.assurance.is_strong()
                && state.authenticated_at + self.config.freshness > Utc::now()
        });
        Ok(StepUpSessionProjection {
            required: true,
            assurance: state.as_ref().map(|state| state.assurance),
            authenticated_at: state.as_ref().map(|state| state.authenticated_at),
            fresh,
            step_up_required: !fresh,
        })
    }
}

#[async_trait]
impl AuthPlugin for StepUpPolicyPlugin {
    fn descriptor(&self) -> PluginDescriptor {
        PluginDescriptor {
            id: "lucid-step-up-policy",
            display_name: "Lucid Step-Up Policy",
            version: env!("CARGO_PKG_VERSION"),
            dependencies: &[],
            conflicts: &[],
            endpoints: std::borrow::Cow::Borrowed(&[]),
            cookies: &[],
            rate_limits: &[],
            middleware: &[],
            client: None,
        }
    }

    fn validate(&self, _config: &AuthConfig) -> Result<(), AuthError> {
        if self.config.required_roles.is_empty()
            || self
                .config
                .required_roles
                .iter()
                .any(|role| role.trim().is_empty())
            || self.config.freshness <= Duration::zero()
            || self.config.recovery_code_count == 0
            || self.config.recovery_rate_limit_window <= Duration::zero()
            || self.config.recovery_rate_limit_max == 0
        {
            return Err(AuthError::InvalidConfiguration(
                "step-up roles, freshness, recovery-code count, and recovery limit must be non-empty and positive".into(),
            ));
        }
        Ok(())
    }

    fn migrations(&self) -> std::borrow::Cow<'_, [PluginMigration]> {
        std::borrow::Cow::Borrowed(MIGRATIONS)
    }

    async fn initialize_session(&self, session: &SessionWithUser) -> Result<(), AuthError> {
        if !self.requires(&session.user.role) || session.session.actor_user_id.is_some() {
            return self.store.delete_step_up_session(session.session.id).await;
        }
        self.store
            .upsert_step_up_session(StepUpSession {
                session_id: session.session.id,
                user_id: session.user.id,
                assurance: self.initial_assurance(session).await?,
                authenticated_at: session.session.created_at,
            })
            .await
    }

    async fn reset_user_security_state(&self, user_id: Uuid) -> Result<(), AuthError> {
        self.store.delete_user_step_up_state(user_id).await
    }

    async fn validate_session(&self, session: &SessionWithUser) -> Result<bool, AuthError> {
        if !self.requires(&session.user.role) || session.session.actor_user_id.is_some() {
            return Ok(true);
        }
        Ok(self
            .store
            .find_step_up_session(session.session.id)
            .await?
            .is_some_and(|state| state.user_id == session.user.id))
    }

    async fn authorize_sensitive(
        &self,
        operation: &SensitiveOperation<'_>,
    ) -> Result<(), AuthError> {
        if !self.requires(&operation.session.user.role) {
            return Ok(());
        }
        let state = self
            .store
            .find_step_up_session(operation.session.session.id)
            .await?
            .ok_or(AuthError::StepUpRequired)?;
        if !state.assurance.is_strong()
            || state.authenticated_at + self.config.freshness <= Utc::now()
        {
            return Err(AuthError::StepUpRequired);
        }
        Ok(())
    }

    async fn after(&self, event: &AfterAuthEvent) {
        if let AfterAuthEvent::UserDeleted { user } = event {
            let _ = self.store.delete_user_step_up_state(user.id).await;
        }
    }
}
