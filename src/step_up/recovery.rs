use super::StepUpSessionProjection;
use crate::{AuthError, AuthService, SessionWithUser, SignInResult};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryCodeStatus {
    pub remaining: usize,
}

/// Native recovery-code API contributed by [`crate::StepUpPolicyPlugin`].
pub struct StepUpPolicyService<'a> {
    service: &'a AuthService,
}

impl<'a> StepUpPolicyService<'a> {
    pub(crate) fn new(service: &'a AuthService) -> Self {
        Self { service }
    }

    pub async fn generate_recovery_codes(
        &self,
        actor: &SessionWithUser,
        password: String,
    ) -> Result<Vec<String>, AuthError> {
        self.service
            .generate_step_up_recovery_codes(actor, password)
            .await
    }

    /// Projects plugin-owned state without adding fields to Better Auth JSON.
    pub async fn session_projection(
        &self,
        session: &SessionWithUser,
    ) -> Result<StepUpSessionProjection, AuthError> {
        self.service.step_up_session_projection(session).await
    }

    pub async fn recovery_code_status(
        &self,
        actor: &SessionWithUser,
    ) -> Result<RecoveryCodeStatus, AuthError> {
        self.service.step_up_recovery_code_status(actor).await
    }

    pub async fn verify_recovery_code(
        &self,
        actor: &SessionWithUser,
        code: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<SignInResult, AuthError> {
        self.service
            .verify_step_up_recovery_code(actor, code, ip_address, user_agent)
            .await
    }
}
