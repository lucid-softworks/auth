use super::PluginRegistry;
use crate::{
    AfterAuthEvent, AfterOrganizationEvent, AuthError, BeforeAuthEvent, BeforeDatabaseUpdateHook,
    DatabaseHookContext, DatabaseRecord, DatabaseUpdateRecord, PasswordCredentialChanged,
    SensitiveOperation, SessionWithUser, UserManagementDecision, UserManagementOperation,
};

mod create;

impl PluginRegistry {
    pub(crate) async fn after_database_create(
        &self,
        service: &crate::AuthService,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        for plugin in &self.plugins {
            plugin
                .after_database_create(service, record, context)
                .await?;
            if let Some(hooks) = plugin.database_hooks() {
                hooks.after_create(record, context).await?;
            }
        }
        Ok(())
    }

    pub(crate) async fn before_database_update(
        &self,
        mut record: DatabaseUpdateRecord,
        context: &DatabaseHookContext,
    ) -> Result<DatabaseUpdateRecord, AuthError> {
        for hooks in self
            .plugins
            .iter()
            .filter_map(|plugin| plugin.database_hooks())
        {
            apply_update_before(hooks.before_update(&record, context).await?, &mut record)?;
        }
        Ok(record)
    }

    pub(crate) async fn after_database_update(
        &self,
        service: &crate::AuthService,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        for plugin in &self.plugins {
            plugin
                .after_database_update(service, record, context)
                .await?;
            if let Some(hooks) = plugin.database_hooks() {
                hooks.after_update(record, context).await?;
            }
        }
        Ok(())
    }

    pub(crate) async fn before_database_delete(
        &self,
        service: &crate::AuthService,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        for plugin in &self.plugins {
            plugin
                .before_database_delete(service, record, context)
                .await?;
            if let Some(hooks) = plugin.database_hooks()
                && !hooks.before_delete(record, context).await?
            {
                return Err(cancelled(record.model(), "delete"));
            }
        }
        Ok(())
    }

    pub(crate) async fn after_database_delete(
        &self,
        service: &crate::AuthService,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        for plugin in &self.plugins {
            plugin
                .after_database_delete(service, record, context)
                .await?;
            if let Some(hooks) = plugin.database_hooks() {
                hooks.after_delete(record, context).await?;
            }
        }
        Ok(())
    }

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

    pub(crate) async fn after_organization(&self, event: &AfterOrganizationEvent<'_>) {
        for plugin in &self.plugins {
            plugin.after_organization(event).await;
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
        user_id: &str,
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

fn apply_update_before(
    result: BeforeDatabaseUpdateHook,
    current: &mut DatabaseUpdateRecord,
) -> Result<(), AuthError> {
    match result {
        BeforeDatabaseUpdateHook::Continue => Ok(()),
        BeforeDatabaseUpdateHook::Merge(patch) => {
            current.merge(patch);
            Ok(())
        }
        BeforeDatabaseUpdateHook::Cancel => Err(cancelled(current.model(), "update")),
    }
}

fn cancelled(model: crate::DatabaseModel, operation: &'static str) -> AuthError {
    AuthError::DatabaseHookCancelled {
        model: model.as_str(),
        operation,
    }
}
