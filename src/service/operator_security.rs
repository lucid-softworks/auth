use super::{
    AuthService, account_limit_key, password::hash_password, password::normalize_username,
};
use crate::{AuthError, OperatorSecurityError, OperatorSecurityPlugin, OperatorSecurityStatus};
use serde_json::json;

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
        let username = normalize_username(username)?;
        self.validate_new_password(&password).await?;
        let target = self
            .store
            .find_user_by_username(&username)
            .await?
            .filter(|user| !user.is_anonymous && user.role == "owner")
            .ok_or(OperatorSecurityError::SoleOwnerRecoveryUnavailable)?;
        if !plugin
            .store
            .recover_sole_owner(target.id, hash_password(password).await?)
            .await?
        {
            return Err(OperatorSecurityError::SoleOwnerRecoveryUnavailable.into());
        }
        self.plugins
            .reset_user_security_state_except(target.id, PLUGIN_ID)
            .await?;
        self.store
            .clear_auth_failures(&account_limit_key(&username))
            .await?;
        self.audit_actorless(
            Some(target.id),
            "operator_security.owner_recovered",
            Some(target.id.to_string()),
            json!({
                "sessionsRevoked": true,
                "factorsReset": true,
                "replacementRequired": true,
            }),
        )
        .await;
        Ok(())
    }

    fn operator_security_plugin(&self) -> Result<&OperatorSecurityPlugin, AuthError> {
        self.plugins.find().ok_or_else(|| {
            AuthError::InvalidConfiguration("operator-security plugin is disabled".into())
        })
    }
}
