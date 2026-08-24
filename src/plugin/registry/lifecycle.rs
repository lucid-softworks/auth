use super::PluginRegistry;
use crate::{
    AfterAuthEvent, AuthError, BeforeAuthEvent, BeforeDatabaseHook, DatabaseHookContext,
    DatabaseRecord, PasswordCredentialChanged, SensitiveOperation, SessionWithUser,
    UserManagementDecision, UserManagementOperation,
};

impl PluginRegistry {
    pub(crate) async fn before_database_create(
        &self,
        mut record: DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<DatabaseRecord, AuthError> {
        for hooks in self
            .plugins
            .iter()
            .filter_map(|plugin| plugin.database_hooks())
        {
            record = apply_before(
                hooks.before_create(&record, context).await?,
                record,
                "create",
            )?;
        }
        Ok(record)
    }

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
        mut record: DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<DatabaseRecord, AuthError> {
        for hooks in self
            .plugins
            .iter()
            .filter_map(|plugin| plugin.database_hooks())
        {
            record = apply_before(
                hooks.before_update(&record, context).await?,
                record,
                "update",
            )?;
        }
        Ok(record)
    }

    pub(crate) async fn after_database_update(
        &self,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        for hooks in self
            .plugins
            .iter()
            .filter_map(|plugin| plugin.database_hooks())
        {
            hooks.after_update(record, context).await?;
        }
        Ok(())
    }

    pub(crate) async fn before_database_delete(
        &self,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        for hooks in self
            .plugins
            .iter()
            .filter_map(|plugin| plugin.database_hooks())
        {
            if !hooks.before_delete(record, context).await? {
                return Err(cancelled(record, "delete"));
            }
        }
        Ok(())
    }

    pub(crate) async fn after_database_delete(
        &self,
        record: &DatabaseRecord,
        context: &DatabaseHookContext,
    ) -> Result<(), AuthError> {
        for hooks in self
            .plugins
            .iter()
            .filter_map(|plugin| plugin.database_hooks())
        {
            hooks.after_delete(record, context).await?;
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

fn apply_before(
    result: BeforeDatabaseHook,
    current: DatabaseRecord,
    operation: &'static str,
) -> Result<DatabaseRecord, AuthError> {
    match result {
        BeforeDatabaseHook::Continue => Ok(current),
        BeforeDatabaseHook::Replace(replacement) if replacement.model() == current.model() => {
            Ok(*replacement)
        }
        BeforeDatabaseHook::Replace(_) => Err(AuthError::InvalidConfiguration(
            "a database hook replaced a record with a different model".into(),
        )),
        BeforeDatabaseHook::Cancel => Err(cancelled(&current, operation)),
    }
}

fn cancelled(record: &DatabaseRecord, operation: &'static str) -> AuthError {
    AuthError::DatabaseHookCancelled {
        model: record.model().as_str(),
        operation,
    }
}
