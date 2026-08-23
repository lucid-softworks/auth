use super::AuthService;
use crate::{AuthError, AuthSession, SessionWithUser};
use serde_json::{Map, Value};

impl AuthService {
    pub async fn update_current_session(
        &self,
        current: &SessionWithUser,
        fields: Map<String, Value>,
    ) -> Result<AuthSession, AuthError> {
        let fields = crate::additional_fields::parse_update_fields(
            &self.config.session.additional_fields,
            fields,
        )?;
        if fields.is_empty() {
            return Err(AuthError::InvalidRequest("No fields to update".into()));
        }
        self.store
            .update_session_fields(current.session.id, fields)
            .await?
            .ok_or(AuthError::InvalidSession)
    }
}
