use super::AuthService;
use crate::store::{
    DatabaseCreate, DatabaseIdInput, DatabaseIdPlan, DatabaseWrite, PreparedDatabaseId,
};
use crate::{AuthError, BeforeDatabaseHook, DatabaseCreateRecord, DatabaseModel, DatabaseRecord};
use chrono::{DateTime, Utc};

mod create;
mod delete;

use create::{
    CredentialAccountCreate, OAuthAccountCreate, apply_create_before, create_hook_record,
    decode_create_hook_record,
};

impl AuthService {
    pub(crate) fn database_id_plan(
        &self,
        model: impl Into<String>,
        input: DatabaseIdInput,
        force_allow_id: bool,
    ) -> DatabaseIdPlan {
        DatabaseIdPlan::new(
            self.config.database_id_generation.clone(),
            model,
            input,
            force_allow_id,
        )
    }

    pub(crate) fn prepare_database_id(
        &self,
        plan: &DatabaseIdPlan,
    ) -> Result<PreparedDatabaseId, AuthError> {
        plan.prepare(self.store.as_ref())
    }

    pub(crate) async fn create_device_authorization_code(
        &self,
        store: &dyn crate::DeviceAuthorizationStore,
        record: crate::DeviceCode,
    ) -> Result<crate::DeviceCodeCreateOutcome, AuthError> {
        let create = DatabaseCreate::new(
            record,
            self.database_id_plan("deviceCode", DatabaseIdInput::Absent, false),
        );
        store.create_device_code(create, self.store.as_ref()).await
    }

    pub(super) fn credential_account_create(
        &self,
        password_hash: String,
        now: DateTime<Utc>,
    ) -> CredentialAccountCreate {
        CredentialAccountCreate {
            service: self.clone(),
            password_hash,
            now,
        }
    }

    pub(super) fn oauth_account_create(&self, account: crate::OAuthAccount) -> OAuthAccountCreate {
        OAuthAccountCreate {
            service: self.clone(),
            account,
        }
    }

    pub(super) async fn prepare_user_create(
        &self,
        user: crate::AuthUser,
    ) -> Result<DatabaseCreate<crate::AuthUser>, AuthError> {
        self.prepare_user_create_with_input(user, None).await
    }

    pub(super) async fn prepare_forced_user_create(
        &self,
        user: crate::AuthUser,
    ) -> Result<DatabaseCreate<crate::AuthUser>, AuthError> {
        let id = DatabaseIdInput::String(user.id.clone());
        self.prepare_user_create_with_input(user, Some(id)).await
    }

    async fn prepare_user_create_with_input(
        &self,
        mut user: crate::AuthUser,
        supplied_id: Option<DatabaseIdInput>,
    ) -> Result<DatabaseCreate<crate::AuthUser>, AuthError> {
        user.additional_fields =
            self.create_additional_fields(DatabaseModel::User, user.additional_fields)?;
        let mut draft = create_hook_record(DatabaseRecord::User(user))?;
        if let Some(id) = supplied_id {
            draft.merge(crate::DatabaseCreatePatch::new().with_id(id));
        }
        let (record, id, id_present) =
            decode_create_hook_record(self.before_database_create(draft).await?, None)?;
        match record {
            DatabaseRecord::User(user) => {
                self.prepare_database_create(DatabaseModel::User.as_str(), id, id_present, user)
            }
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
        record: DatabaseCreateRecord,
    ) -> Result<DatabaseCreateRecord, AuthError> {
        let context = crate::database_hooks::current_context();
        let mut record = self
            .plugins
            .before_database_create(record, &context)
            .await?;
        if let Some(hooks) = &self.config.database_hooks {
            apply_create_before(hooks.before_create(&record, &context).await?, &mut record)?;
        }
        Ok(record)
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
        self.plugins
            .after_database_update(self, record, &context)
            .await?;
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
            .before_database_delete(self, record, &context)
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
        self.plugins
            .after_database_delete(self, record, &context)
            .await?;
        if let Some(hooks) = &self.config.database_hooks {
            hooks.after_delete(record, &context).await?;
        }
        Ok(())
    }

    pub(super) async fn prepare_account_create(
        &self,
        mut account: crate::OAuthAccount,
    ) -> Result<DatabaseCreate<crate::OAuthAccount>, AuthError> {
        account.additional_fields =
            self.create_additional_fields(DatabaseModel::Account, account.additional_fields)?;
        let draft = create_hook_record(DatabaseRecord::Account(account))?;
        let (record, id, id_present) =
            decode_create_hook_record(self.before_database_create(draft).await?, None)?;
        match record {
            DatabaseRecord::Account(account) => self.prepare_database_create(
                DatabaseModel::Account.as_str(),
                id,
                id_present,
                account,
            ),
            _ => unreachable!("database hook model was validated"),
        }
    }

    pub(super) async fn prepare_session_create(
        &self,
        session: crate::AuthSession,
    ) -> Result<DatabaseCreate<crate::AuthSession>, AuthError> {
        let authentication_method = session.authentication_method;
        let draft = create_hook_record(DatabaseRecord::Session(session))?;
        let (record, id, id_present) = decode_create_hook_record(
            self.before_database_create(draft).await?,
            authentication_method,
        )?;
        match record {
            DatabaseRecord::Session(session) => self.prepare_database_create(
                DatabaseModel::Session.as_str(),
                id,
                id_present,
                session,
            ),
            _ => unreachable!("database hook model was validated"),
        }
    }

    pub(super) async fn prepare_verification_create(
        &self,
        value: crate::VerificationValue,
    ) -> Result<DatabaseCreate<crate::VerificationValue>, AuthError> {
        let draft = create_hook_record(DatabaseRecord::Verification(value))?;
        let (record, id, id_present) =
            decode_create_hook_record(self.before_database_create(draft).await?, None)?;
        match record {
            DatabaseRecord::Verification(value) => self.prepare_database_create(
                DatabaseModel::Verification.as_str(),
                id,
                id_present,
                value,
            ),
            _ => unreachable!("database hook model was validated"),
        }
    }

    pub(super) async fn prepare_credential_account(
        &self,
        user_id: String,
        password_hash: String,
        now: DateTime<Utc>,
        existing: Option<&crate::OAuthAccount>,
    ) -> Result<DatabaseWrite<crate::OAuthAccount>, AuthError> {
        let mut account = crate::OAuthAccount {
            id: String::new(),
            user_id: user_id.clone(),
            issuer: "local:credential".into(),
            account_id: user_id.clone(),
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
        if let Some(existing) = existing {
            account = existing.clone();
            account.updated_at = now;
            return self
                .prepare_account_update(account)
                .await
                .map(DatabaseWrite::Update);
        }
        self.prepare_account_create(account)
            .await
            .map(DatabaseWrite::Create)
    }

    pub(super) async fn finish_account_create(
        &self,
        account: &crate::OAuthAccount,
    ) -> Result<(), AuthError> {
        self.after_database_create(&DatabaseRecord::Account(account.clone()))
            .await
    }

    pub(crate) fn prepare_database_create<T>(
        &self,
        model: &str,
        input: DatabaseIdInput,
        force_allow_id: bool,
        record: T,
    ) -> Result<DatabaseCreate<T>, AuthError> {
        Ok(DatabaseCreate::new(
            record,
            DatabaseIdPlan::new(
                self.config.database_id_generation.clone(),
                model,
                input,
                force_allow_id,
            ),
        ))
    }

    pub(super) async fn set_password_hash_with_database_id(
        &self,
        user_id: &str,
        password_hash: String,
    ) -> Result<(), AuthError> {
        let id = DatabaseIdPlan::new(
            self.config.database_id_generation.clone(),
            DatabaseModel::Account.as_str(),
            DatabaseIdInput::Absent,
            false,
        );
        let prepare_id = || id.prepare(self.store.as_ref());
        self.store
            .set_password_hash(&prepare_id, user_id, password_hash)
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
