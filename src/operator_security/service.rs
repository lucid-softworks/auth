use crate::{AuthError, AuthService};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OperatorSecurityStatus {
    pub temporary_password: bool,
}

/// Native operator API contributed by [`crate::OperatorSecurityPlugin`].
pub struct OperatorSecurityService<'a> {
    service: &'a AuthService,
}

impl<'a> OperatorSecurityService<'a> {
    pub(crate) fn new(service: &'a AuthService) -> Self {
        Self { service }
    }

    pub async fn status(&self, user_id: &str) -> Result<OperatorSecurityStatus, AuthError> {
        self.service.operator_security_status(user_id).await
    }

    pub async fn local_recover_sole_owner(
        &self,
        username: &str,
        password: String,
    ) -> Result<(), AuthError> {
        self.service
            .operator_recover_sole_owner(username, password)
            .await
    }

    pub async fn require_replacement(&self, user_id: &str) -> Result<(), AuthError> {
        self.service
            .set_operator_temporary_password(user_id, true)
            .await
    }

    pub async fn clear_replacement(&self, user_id: &str) -> Result<(), AuthError> {
        self.service
            .set_operator_temporary_password(user_id, false)
            .await
    }
}
