use super::AuthService;
use crate::{
    AdminCreateUser, AuthError, AuthSession, AuthUser, DashAdapterWhere, DatabaseModel,
    DatabaseRecord, UserProfileUpdate,
};
use chrono::Utc;
use serde_json::{Value, json};

impl AuthService {
    pub(crate) fn scim_base_url(&self) -> String {
        let path = self.base_path();
        match self.config.base_url() {
            Some(base) if base.path() != "/" => base.as_str().trim_end_matches('/').to_owned(),
            Some(base) => format!("{}{}", base.as_str().trim_end_matches('/'), path),
            None => path.to_owned(),
        }
    }

    pub(crate) async fn scim_create_user(
        &self,
        email: String,
        name: String,
    ) -> Result<AuthUser, AuthError> {
        let input = AdminCreateUser {
            email,
            password: None,
            name,
            roles: Vec::new(),
            data: serde_json::Map::new(),
        };
        let Some(transaction) = crate::database_hooks::current_transaction() else {
            return self.dash_create_user(input).await;
        };
        let mut input = input;
        let user = super::user::admin_user_from_input(&mut input, "user".into())?;
        let email = user.email.to_lowercase();
        if !transaction
            .find_records("user", &[equal("email", json!(email))], Some(1), 0, None, &[])
            .await?
            .is_empty()
        {
            return Err(AuthError::UserAlreadyExistsEmail);
        }
        self.persist_admin_user(user, None).await
    }

    pub(crate) async fn scim_update_user_profile(
        &self,
        user_id: &str,
        name: String,
        old_email: &str,
        email: String,
    ) -> Result<Option<AuthUser>, AuthError> {
        if let Some(transaction) = crate::database_hooks::current_transaction() {
            let Some(DatabaseRecord::User(original)) = transaction
                .find_by_id(DatabaseModel::User, user_id)
                .await?
            else {
                return Ok(None);
            };
            if !original.email.eq_ignore_ascii_case(old_email) {
                return Ok(None);
            }
            let email = email.to_lowercase();
            if !original.email.eq_ignore_ascii_case(&email) {
                let records = transaction
                    .find_records(
                        "user",
                        &[equal("email", json!(email))],
                        Some(1),
                        0,
                        None,
                        &[],
                    )
                    .await?;
                if records.iter().any(|record| {
                    record.get("id").and_then(Value::as_str) != Some(user_id)
                }) {
                    return Err(AuthError::UserAlreadyExistsEmail);
                }
            }
            let mut candidate = original.clone();
            candidate.name = name;
            if !candidate.email.eq_ignore_ascii_case(&email) {
                candidate.email = email;
                candidate.email_verified = false;
            }
            candidate.updated_at = Utc::now();
            let candidate = self.prepare_user_update(&original, candidate).await?;
            let DatabaseRecord::User(updated) = transaction
                .update(DatabaseRecord::User(candidate))
                .await?
            else {
                unreachable!("transaction update preserves its model")
            };
            self.after_database_update(&DatabaseRecord::User(updated.clone()))
                .await?;
            return Ok(Some(updated));
        }
        let updated = self
            .store
            .update_user_profile(
                user_id,
                UserProfileUpdate {
                    name: Some(name),
                    ..UserProfileUpdate::default()
                },
            )
            .await?;
        if old_email.eq_ignore_ascii_case(&email) {
            return Ok(updated);
        }
        self.store
            .update_user_email(user_id, old_email, &email.to_lowercase(), false)
            .await
    }

    pub(crate) async fn scim_revoke_user_sessions(&self, user_id: &str) -> Result<(), AuthError> {
        if let Some(transaction) = crate::database_hooks::current_transaction() {
            let records = transaction
                .find_records(
                    "session",
                    &[equal("userId", json!(user_id))],
                    None,
                    0,
                    None,
                    &[],
                )
                .await?;
            let sessions = records
                .into_iter()
                .map(|record| {
                    serde_json::from_value::<AuthSession>(Value::Object(record)).map_err(|error| {
                        AuthError::Storage(format!("invalid transaction session row: {error}"))
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            for session in &sessions {
                self.before_database_delete(&DatabaseRecord::Session(session.clone()))
                    .await?;
            }
            transaction
                .delete_records("session", &[equal("userId", json!(user_id))])
                .await?;
            for session in sessions {
                self.after_database_delete(&DatabaseRecord::Session(session))
                    .await?;
            }
            return Ok(());
        }
        self.delete_user_sessions_with_hooks(user_id).await
    }

    pub(crate) async fn scim_rollback_created_user(&self, user: &AuthUser) {
        let _ = self.delete_user_record_with_hooks(user).await;
    }
}

fn equal(field: &str, value: Value) -> DashAdapterWhere {
    DashAdapterWhere {
        field: field.into(),
        value,
        operator: Default::default(),
        connector: None,
    }
}
