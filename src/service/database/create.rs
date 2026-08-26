use super::AuthService;
use crate::{
    AuthError, BeforeDatabaseCreateHook, DatabaseCreateRecord, DatabaseIdInput, DatabaseModel,
    DatabaseRecord, DatabaseWrite,
};
use chrono::{DateTime, Utc};

pub(in crate::service) struct CredentialAccountCreate {
    pub(super) service: AuthService,
    pub(super) password_hash: String,
    pub(super) now: DateTime<Utc>,
}

pub(in crate::service) struct OAuthAccountCreate {
    pub(super) service: AuthService,
    pub(super) account: crate::OAuthAccount,
}

#[async_trait::async_trait]
impl crate::DependentAccountPreparer for CredentialAccountCreate {
    fn pending_account_key(&self, user: &crate::AuthUser) -> Option<(String, String)> {
        Some(("local:credential".to_owned(), user.id.clone()))
    }

    async fn prepare_account(
        &self,
        context: crate::DependentAccountContext<'_>,
    ) -> Result<DatabaseWrite<crate::OAuthAccount>, AuthError> {
        self.service
            .prepare_credential_account(
                context.user.id.clone(),
                self.password_hash.clone(),
                self.now,
                context.existing_account,
            )
            .await
    }
}

#[async_trait::async_trait]
impl crate::DependentAccountPreparer for OAuthAccountCreate {
    fn pending_account_key(&self, _user: &crate::AuthUser) -> Option<(String, String)> {
        Some((self.account.issuer.clone(), self.account.account_id.clone()))
    }

    async fn prepare_account(
        &self,
        context: crate::DependentAccountContext<'_>,
    ) -> Result<DatabaseWrite<crate::OAuthAccount>, AuthError> {
        if context.existing_account.is_some() {
            return Err(AuthError::Storage(
                "fresh OAuth account preparer received an existing account".into(),
            ));
        }
        let mut account = self.account.clone();
        account.user_id = context.user.id.clone();
        self.service
            .prepare_account_create(account)
            .await
            .map(DatabaseWrite::Create)
    }
}

#[async_trait::async_trait]
impl crate::DatabaseAccountCreate for OAuthAccountCreate {
    async fn prepare(
        &self,
        user: &crate::AuthUser,
    ) -> Result<crate::DatabaseCreate<crate::OAuthAccount>, AuthError> {
        let mut account = self.account.clone();
        account.user_id = user.id.clone();
        self.service.prepare_account_create(account).await
    }
}

pub(super) fn create_hook_record(
    record: DatabaseRecord,
) -> Result<DatabaseCreateRecord, AuthError> {
    let model = record.model();
    let value = match record {
        DatabaseRecord::User(user) => serde_json::to_value(user),
        DatabaseRecord::Session(session) => serde_json::to_value(session),
        DatabaseRecord::Verification(value) => serde_json::to_value(value),
        DatabaseRecord::Account(account) => serde_json::to_value(&account).map(|mut value| {
            let fields = value
                .as_object_mut()
                .expect("an account serializes as an object");
            fields.insert(
                "accessToken".into(),
                option_string_value(account.access_token),
            );
            fields.insert(
                "refreshToken".into(),
                option_string_value(account.refresh_token),
            );
            fields.insert("idToken".into(), option_string_value(account.id_token));
            fields.insert("password".into(), option_string_value(account.password));
            value
        }),
    }
    .map_err(|error| {
        AuthError::Storage(format!("database create hook encoding failed: {error}"))
    })?;
    let mut fields = value
        .as_object()
        .cloned()
        .ok_or_else(|| AuthError::Storage("database create hook record is not an object".into()))?;
    fields.remove("id");
    Ok(DatabaseCreateRecord::new(model, fields))
}

pub(super) fn decode_create_hook_record(
    record: DatabaseCreateRecord,
    authentication_method: Option<crate::AuthenticationMethod>,
) -> Result<(DatabaseRecord, DatabaseIdInput, bool), AuthError> {
    let (model, id, id_present, mut fields) = record.into_parts();
    fields.insert("id".into(), serde_json::Value::String(String::new()));
    let value = serde_json::Value::Object(fields);
    let record = match model {
        DatabaseModel::User => serde_json::from_value(value).map(DatabaseRecord::User),
        DatabaseModel::Session => {
            serde_json::from_value(value).map(|mut session: crate::AuthSession| {
                session.authentication_method = authentication_method;
                DatabaseRecord::Session(session)
            })
        }
        DatabaseModel::Account => serde_json::from_value(value).map(DatabaseRecord::Account),
        DatabaseModel::Verification => {
            serde_json::from_value(value).map(DatabaseRecord::Verification)
        }
        DatabaseModel::Organization => {
            return Err(AuthError::InvalidConfiguration(
                "organization create hooks require a plugin-owned record boundary".into(),
            ));
        }
    }
    .map_err(|error| {
        AuthError::InvalidConfiguration(format!(
            "a {model:?} before-create hook returned incompatible fields: {error}"
        ))
    })?;
    Ok((record, id, id_present))
}

pub(super) fn apply_create_before(
    result: BeforeDatabaseCreateHook,
    current: &mut DatabaseCreateRecord,
) -> Result<(), AuthError> {
    match result {
        BeforeDatabaseCreateHook::Continue => Ok(()),
        BeforeDatabaseCreateHook::Merge(patch) => {
            current.merge(patch);
            Ok(())
        }
        BeforeDatabaseCreateHook::Cancel => Err(AuthError::DatabaseHookCancelled {
            model: current.model().as_str(),
            operation: "create",
        }),
    }
}

fn option_string_value(value: Option<String>) -> serde_json::Value {
    value.map_or(serde_json::Value::Null, serde_json::Value::String)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DatabaseCreatePatch;
    use chrono::Utc;

    fn user() -> crate::AuthUser {
        let now = Utc::now();
        crate::AuthUser {
            id: String::new(),
            username: None,
            display_username: None,
            name: "Hook Draft".into(),
            email: "hook@example.com".into(),
            email_verified: false,
            image: None,
            additional_fields: serde_json::Map::new(),
            role: "user".into(),
            is_anonymous: false,
            banned: false,
            ban_reason: None,
            ban_expires: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn ordinary_hook_input_has_no_id_property() {
        let draft = create_hook_record(DatabaseRecord::User(user())).unwrap();
        assert!(!draft.has_id());
        assert_eq!(draft.id(), &DatabaseIdInput::Absent);
        assert!(!draft.fields().contains_key("id"));
    }

    #[test]
    fn hook_id_presence_survives_truthy_null_and_undefined_values() {
        for id in [
            DatabaseIdInput::String("hook-id".into()),
            DatabaseIdInput::Null,
            DatabaseIdInput::Absent,
        ] {
            let mut draft = create_hook_record(DatabaseRecord::User(user())).unwrap();
            draft.merge(DatabaseCreatePatch::new().with_id(id.clone()));
            let (record, actual, present) = decode_create_hook_record(draft, None).unwrap();
            assert!(present);
            assert_eq!(actual, id);
            assert!(matches!(record, DatabaseRecord::User(user) if user.id.is_empty()));
        }
    }
}
