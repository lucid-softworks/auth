use super::{AuthService, create_hook_record, decode_create_hook_record};
use crate::{AuthError, DatabaseCreate, DatabaseIdInput, DatabaseModel, DatabaseRecord};

impl AuthService {
    pub(in crate::service) async fn prepare_user_create(
        &self,
        user: crate::AuthUser,
    ) -> Result<DatabaseCreate<crate::AuthUser>, AuthError> {
        self.prepare_user_create_from_input(user, None, serde_json::Map::new())
            .await
    }

    pub(in crate::service) async fn prepare_user_create_with_internal_fields(
        &self,
        user: crate::AuthUser,
        internal_fields: serde_json::Map<String, serde_json::Value>,
    ) -> Result<DatabaseCreate<crate::AuthUser>, AuthError> {
        self.prepare_user_create_from_input(user, None, internal_fields)
            .await
    }

    pub(in crate::service) async fn prepare_forced_user_create(
        &self,
        user: crate::AuthUser,
    ) -> Result<DatabaseCreate<crate::AuthUser>, AuthError> {
        let id = DatabaseIdInput::String(user.id.clone());
        self.prepare_user_create_from_input(user, Some(id), serde_json::Map::new())
            .await
    }

    async fn prepare_user_create_from_input(
        &self,
        mut user: crate::AuthUser,
        supplied_id: Option<DatabaseIdInput>,
        internal_fields: serde_json::Map<String, serde_json::Value>,
    ) -> Result<DatabaseCreate<crate::AuthUser>, AuthError> {
        user.additional_fields =
            self.create_additional_fields(DatabaseModel::User, user.additional_fields)?;
        self.prepare_user_create_record(user, supplied_id, internal_fields)
            .await
    }

    async fn prepare_user_create_record(
        &self,
        mut user: crate::AuthUser,
        supplied_id: Option<DatabaseIdInput>,
        internal_fields: serde_json::Map<String, serde_json::Value>,
    ) -> Result<DatabaseCreate<crate::AuthUser>, AuthError> {
        user.additional_fields.extend(internal_fields);
        let mut draft = create_hook_record(DatabaseRecord::User(user))?;
        if let Some(id) = supplied_id {
            draft.merge(crate::DatabaseCreatePatch::new().with_id(id));
        }
        let (mut record, id, id_present) =
            decode_create_hook_record(self.before_database_create(draft).await?, None)?;
        self.transform_create_record(&mut record)?;
        match record {
            DatabaseRecord::User(user) => {
                self.prepare_database_create(DatabaseModel::User.as_str(), id, id_present, user)
            }
            _ => unreachable!("database hook model was validated"),
        }
    }

    pub(in crate::service) async fn finish_user_create(
        &self,
        user: &crate::AuthUser,
    ) -> Result<(), AuthError> {
        self.after_database_create(&DatabaseRecord::User(user.clone()))
            .await
    }

    pub(in crate::service) async fn prepare_user_update(
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
}
