use super::PluginRegistry;
use crate::{
    AfterAuthEvent, AuthError, BeforeAuthEvent, PasswordCredentialChanged, SensitiveOperation,
    SessionWithUser, UserManagementDecision, UserManagementOperation,
};

impl PluginRegistry {
    pub(crate) async fn before(&self, event: &BeforeAuthEvent) -> Result<(), AuthError> {
        for plugin in &self.plugins {
            plugin.before(event).await?;
        }
        Ok(())
    }

    pub(crate) async fn after(&self, event: &AfterAuthEvent) {
        for plugin in &self.plugins {
            plugin.after(event).await;
        }
    }

    pub(crate) async fn initialize_session(
        &self,
        session: &SessionWithUser,
    ) -> Result<(), AuthError> {
        for plugin in &self.plugins {
            plugin.initialize_session(session).await?;
        }
        Ok(())
    }

    pub(crate) async fn reset_user_security_state_except(
        &self,
        user_id: uuid::Uuid,
        excluded_plugin_id: &str,
    ) -> Result<(), AuthError> {
        for plugin in &self.plugins {
            if plugin.descriptor().id != excluded_plugin_id {
                plugin.reset_user_security_state(user_id).await?;
            }
        }
        Ok(())
    }

    pub(crate) async fn password_credential_changed(
        &self,
        event: &PasswordCredentialChanged,
    ) -> Result<(), AuthError> {
        for plugin in &self.plugins {
            plugin.password_credential_changed(event).await?;
        }
        Ok(())
    }

    pub(crate) async fn authorize_application_access(
        &self,
        session: &SessionWithUser,
    ) -> Result<(), AuthError> {
        for plugin in &self.plugins {
            plugin.authorize_application_access(session).await?;
        }
        Ok(())
    }

    pub(crate) async fn authorize_sensitive(
        &self,
        operation: &SensitiveOperation<'_>,
    ) -> Result<(), AuthError> {
        for plugin in &self.plugins {
            plugin.authorize_sensitive(operation).await?;
        }
        Ok(())
    }

    pub(crate) async fn authorize_user_management(
        &self,
        store: &dyn crate::AuthStore,
        operation: &UserManagementOperation<'_>,
    ) -> Result<UserManagementDecision, AuthError> {
        let mut decision = UserManagementDecision::default();
        for plugin in &self.plugins {
            let plugin_decision = plugin.authorize_user_management(store, operation).await?;
            decision.revoke_target_sessions |= plugin_decision.revoke_target_sessions;
        }
        Ok(decision)
    }

    pub(crate) fn project_principal(
        &self,
        session: &SessionWithUser,
        principal: &mut crate::Principal,
    ) {
        for plugin in &self.plugins {
            plugin.project_principal(session, principal);
        }
    }

    pub(crate) async fn validates_session(
        &self,
        session: &SessionWithUser,
    ) -> Result<bool, AuthError> {
        for plugin in &self.plugins {
            if !plugin.validate_session(session).await? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn session_from_headers(
        &self,
        service: &crate::AuthService,
        headers: &axum::http::HeaderMap,
    ) -> Result<Option<crate::PluginSession>, AuthError> {
        for plugin in &self.plugins {
            if let Some(session) = plugin.session_from_headers(service, headers).await? {
                return Ok(Some(session));
            }
        }
        Ok(None)
    }
}
