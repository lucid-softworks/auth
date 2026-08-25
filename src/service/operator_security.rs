use super::{AuthService, password::hash_password, password::normalize_username};
use crate::{AuthError, OperatorSecurityError, OperatorSecurityPlugin, OperatorSecurityStatus};

const PLUGIN_ID: &str = "lucid-operator-security";

impl AuthService {
    pub(crate) async fn operator_security_status(
        &self,
        user_id: uuid::Uuid,
    ) -> Result<OperatorSecurityStatus, AuthError> {
        self.operator_security_plugin()?.status(user_id).await
    }

    pub(crate) async fn set_operator_temporary_password(
        &self,
        user_id: uuid::Uuid,
        temporary: bool,
    ) -> Result<(), AuthError> {
        self.operator_security_plugin()?
            .store
            .set_temporary_password(user_id, temporary)
            .await
    }

    pub(crate) async fn operator_recover_sole_owner(
        &self,
        username: &str,
        password: String,
    ) -> Result<(), AuthError> {
        let plugin = self.operator_security_plugin()?;
        let owner_policy = self.owner_policy()?;
        let username = normalize_username(username)?;
        self.validate_new_password(&password).await?;
        let target = self
            .store
            .find_user_by_username(&username)
            .await?
            .filter(|user| owner_policy.is_owner_user(user))
            .ok_or(OperatorSecurityError::SoleOwnerRecoveryUnavailable)?;
        if !plugin
            .store
            .recover_sole_owner(
                target.id,
                owner_policy.owner_role(),
                hash_password(password).await?,
            )
            .await?
        {
            return Err(OperatorSecurityError::SoleOwnerRecoveryUnavailable.into());
        }
        self.plugins
            .reset_user_security_state_except(target.id, PLUGIN_ID)
            .await?;
        self.activity(crate::AuthActivity::SoleOwnerRecovered { user_id: target.id })
            .await;
        Ok(())
    }

    fn operator_security_plugin(&self) -> Result<&OperatorSecurityPlugin, AuthError> {
        self.plugins.find().ok_or_else(|| {
            AuthError::InvalidConfiguration("operator-security plugin is disabled".into())
        })
    }

    fn owner_policy(&self) -> Result<&crate::OwnerPolicyPlugin, AuthError> {
        self.plugins.find().ok_or_else(|| {
            AuthError::InvalidConfiguration("owner-policy plugin is disabled".into())
        })
    }
}
