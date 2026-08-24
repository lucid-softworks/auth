use super::AuthService;
use crate::{AuthError, BeforeDatabaseHook, DatabaseModel, DatabaseRecord};
use chrono::{DateTime, Utc};

impl AuthService {
    pub(super) async fn prepare_user_create(
        &self,
        mut user: crate::AuthUser,
    ) -> Result<crate::AuthUser, AuthError> {
        user.additional_fields =
            self.create_additional_fields(DatabaseModel::User, user.additional_fields)?;
        match self
            .before_database_create(DatabaseRecord::User(user))
            .await?
        {
            DatabaseRecord::User(user) => Ok(user),
            _ => unreachable!("database hook model was validated"),
        }
    }

    pub(super) async fn finish_user_create(&self, user: &crate::AuthUser) -> Result<(), AuthError> {
        self.after_database_create(&DatabaseRecord::User(user.clone()))
            .await
    }

    pub(super) async fn prepare_user_update(
        &self,
        original: &crate::AuthUser,
        candidate: crate::AuthUser,
    ) -> Result<crate::AuthUser, AuthError> {
        let candidate = match self
            .before_database_update(DatabaseRecord::User(candidate))
            .await?
        {
            DatabaseRecord::User(user) => user,
            _ => unreachable!("database hook model was validated"),
        };
        if candidate.id != original.id || candidate.created_at != original.created_at {
            return Err(AuthError::InvalidConfiguration(
                "a user update database hook changed a protected field".into(),
            ));
        }
        Ok(candidate)
    }

    pub(super) fn create_additional_fields(
        &self,
        model: DatabaseModel,
        supplied: serde_json::Map<String, serde_json::Value>,
    ) -> Result<serde_json::Map<String, serde_json::Value>, AuthError> {
        crate::additional_fields::parse_create_fields(self.database_schema_fields(model), supplied)
    }

    pub(super) fn update_additional_fields(
        &self,
        model: DatabaseModel,
        supplied: serde_json::Map<String, serde_json::Value>,
    ) -> Result<serde_json::Map<String, serde_json::Value>, AuthError> {
        crate::additional_fields::parse_update_fields(self.database_schema_fields(model), supplied)
    }

    pub(super) async fn before_database_create(
        &self,
        record: DatabaseRecord,
    ) -> Result<DatabaseRecord, AuthError> {
        let context = crate::database_hooks::current_context();
        let record = self
            .plugins
            .before_database_create(record, &context)
            .await?;
        match &self.config.database_hooks {
            Some(hooks) => apply_before(
                hooks.before_create(&record, &context).await?,
                record,
                "create",
            ),
            None => Ok(record),
        }
    }

    pub(super) async fn after_database_create(
        &self,
        record: &DatabaseRecord,
    ) -> Result<(), AuthError> {
        let context = crate::database_hooks::current_context();
        self.plugins
            .after_database_create(self, record, &context)
            .await?;
        if let Some(hooks) = &self.config.database_hooks {
            hooks.after_create(record, &context).await?;
        }
        Ok(())
    }

    pub(super) async fn before_database_update(
        &self,
        record: DatabaseRecord,
    ) -> Result<DatabaseRecord, AuthError> {
        let context = crate::database_hooks::current_context();
        let record = self
            .plugins
            .before_database_update(record, &context)
            .await?;
        match &self.config.database_hooks {
            Some(hooks) => apply_before(
                hooks.before_update(&record, &context).await?,
                record,
                "update",
            ),
            None => Ok(record),
        }
    }

    pub(super) async fn after_database_update(
        &self,
        record: &DatabaseRecord,
    ) -> Result<(), AuthError> {
        let context = crate::database_hooks::current_context();
        self.plugins.after_database_update(record, &context).await?;
        if let Some(hooks) = &self.config.database_hooks {
            hooks.after_update(record, &context).await?;
        }
        if let DatabaseRecord::User(user) = record {
            self.refresh_secondary_user_sessions(user).await?;
        }
        Ok(())
    }

    pub(super) async fn before_database_delete(
        &self,
        record: &DatabaseRecord,
    ) -> Result<(), AuthError> {
        let context = crate::database_hooks::current_context();
        self.plugins
            .before_database_delete(record, &context)
            .await?;
        if let Some(hooks) = &self.config.database_hooks
            && !hooks.before_delete(record, &context).await?
        {
            return Err(cancelled(record, "delete"));
        }
        Ok(())
    }

    pub(super) async fn after_database_delete(
        &self,
        record: &DatabaseRecord,
    ) -> Result<(), AuthError> {
        let context = crate::database_hooks::current_context();
        self.plugins.after_database_delete(record, &context).await?;
        if let Some(hooks) = &self.config.database_hooks {
            hooks.after_delete(record, &context).await?;
        }
        Ok(())
    }

    pub(super) async fn prepare_account_create(
        &self,
        mut account: crate::OAuthAccount,
    ) -> Result<crate::OAuthAccount, AuthError> {
        account.additional_fields =
            self.create_additional_fields(DatabaseModel::Account, account.additional_fields)?;
        match self
            .before_database_create(DatabaseRecord::Account(account))
            .await?
        {
            DatabaseRecord::Account(account) => Ok(account),
            _ => unreachable!("database hook model was validated"),
        }
    }

    pub(super) async fn prepare_credential_account(
        &self,
        user_id: uuid::Uuid,
        password_hash: String,
        now: DateTime<Utc>,
        updating: bool,
    ) -> Result<crate::OAuthAccount, AuthError> {
        let mut account = crate::OAuthAccount {
            id: uuid::Uuid::new_v4(),
            user_id,
            issuer: "local:credential".into(),
            account_id: user_id.to_string(),
            provider_id: "credential".into(),
            access_token: None,
            refresh_token: None,
            id_token: None,
            access_token_expires_at: None,
            refresh_token_expires_at: None,
            scope: None,
            password: Some(password_hash),
            additional_fields: serde_json::Map::new(),
            created_at: now,
            updated_at: now,
        };
        if updating
            && let Some(existing) = self
                .store
                .find_oauth_account_owner("local:credential", &user_id.to_string())
                .await?
                .map(|owner| owner.account)
        {
            account.id = existing.id;
            account.created_at = existing.created_at;
            account.additional_fields = existing.additional_fields;
            return self.prepare_account_update(account).await;
        }
        self.prepare_account_create(account).await
    }

    pub(super) async fn finish_account_create(
        &self,
        account: &crate::OAuthAccount,
    ) -> Result<(), AuthError> {
        self.after_database_create(&DatabaseRecord::Account(account.clone()))
            .await
    }

    pub(super) async fn prepare_account_update(
        &self,
        account: crate::OAuthAccount,
    ) -> Result<crate::OAuthAccount, AuthError> {
        match self
            .before_database_update(DatabaseRecord::Account(account))
            .await?
        {
            DatabaseRecord::Account(account) => Ok(account),
            _ => unreachable!("database hook model was validated"),
        }
    }

    pub(super) async fn finish_account_update(
        &self,
        account: &crate::OAuthAccount,
    ) -> Result<(), AuthError> {
        self.after_database_update(&DatabaseRecord::Account(account.clone()))
            .await
    }

    pub(super) async fn delete_session_token_with_hooks(
        &self,
        token: &str,
    ) -> Result<(), AuthError> {
        let record = self
            .find_stored_session(token)
            .await?
            .map(|session| DatabaseRecord::Session(session.session));
        if let Some(record) = &record {
            self.before_database_delete(record).await?;
        }
        self.delete_stored_session_token(token).await?;
        if let Some(record) = &record {
            self.after_database_delete(record).await?;
        }
        Ok(())
    }

    pub(super) async fn delete_user_record_with_hooks(
        &self,
        user: &crate::AuthUser,
    ) -> Result<(), AuthError> {
        let record = DatabaseRecord::User(user.clone());
        self.before_database_delete(&record).await?;
        self.store.delete_user(user.id).await?;
        self.after_database_delete(&record).await
    }

    pub(super) async fn delete_session_id_with_hooks(
        &self,
        session_id: uuid::Uuid,
    ) -> Result<(), AuthError> {
        let record = self
            .find_stored_session_by_id(session_id)
            .await?
            .map(|(_, session)| DatabaseRecord::Session(session));
        if let Some(record) = &record {
            self.before_database_delete(record).await?;
        }
        self.delete_stored_session_id(session_id).await?;
        if let Some(record) = &record {
            self.after_database_delete(record).await?;
        }
        Ok(())
    }

    pub(super) async fn delete_user_sessions_with_hooks(
        &self,
        user_id: uuid::Uuid,
    ) -> Result<(), AuthError> {
        let records: Vec<_> = self
            .stored_sessions(user_id)
            .await?
            .into_iter()
            .map(|(_, session)| DatabaseRecord::Session(session))
            .collect();
        for record in &records {
            self.before_database_delete(record).await?;
        }
        self.delete_stored_user_sessions(user_id).await?;
        for record in &records {
            self.after_database_delete(record).await?;
        }
        Ok(())
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
