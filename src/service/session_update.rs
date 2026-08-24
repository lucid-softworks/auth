use super::AuthService;
use crate::{AuthError, AuthSession, DatabaseModel, DatabaseRecord, SessionWithUser};
use serde_json::{Map, Value};

impl AuthService {
    pub async fn update_current_session(
        &self,
        current: &SessionWithUser,
        fields: Map<String, Value>,
    ) -> Result<AuthSession, AuthError> {
        let fields = self.update_additional_fields(DatabaseModel::Session, fields)?;
        if fields.is_empty() {
            return Err(AuthError::InvalidRequest("No fields to update".into()));
        }
        let mut candidate = current.session.clone();
        candidate.additional_fields.extend(fields);
        let candidate = match self
            .before_database_update(DatabaseRecord::Session(candidate))
            .await?
        {
            DatabaseRecord::Session(session) => session,
            _ => unreachable!("database hook model was validated"),
        };
        if candidate.id != current.session.id
            || candidate.user_id != current.session.user_id
            || candidate.token_hash != current.session.token_hash
            || candidate.created_at != current.session.created_at
        {
            return Err(AuthError::InvalidConfiguration(
                "a session update database hook changed a protected field".into(),
            ));
        }
        let persisted_fields = candidate.additional_fields;
        let updated = self
            .store
            .update_session_fields(current.session.id, persisted_fields)
            .await?
            .ok_or(AuthError::InvalidSession)?;
        self.after_database_update(&DatabaseRecord::Session(updated.clone()))
            .await?;
        Ok(updated)
    }
}
