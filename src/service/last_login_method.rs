use super::AuthService;
use crate::{AuthError, DatabaseRecord, UserProfileUpdate};
use serde_json::Value;

impl AuthService {
    pub(crate) async fn update_last_login_method(
        &self,
        user_id: &str,
        method: String,
    ) -> Result<(), AuthError> {
        let Some(original) = self.store.find_user_by_id(user_id).await? else {
            return Ok(());
        };
        let mut candidate = original.clone();
        candidate
            .additional_fields
            .insert("lastLoginMethod".into(), Value::String(method));
        let candidate = self.prepare_user_update(&original, candidate).await?;
        let update = UserProfileUpdate {
            name: (candidate.name != original.name).then_some(candidate.name),
            image: (candidate.image != original.image).then_some(candidate.image),
            username: (candidate.username != original.username)
                .then_some(candidate.username)
                .flatten(),
            display_username: (candidate.display_username != original.display_username)
                .then_some(candidate.display_username)
                .flatten(),
            additional_fields: candidate.additional_fields,
        };
        if let Some(updated) = self.store.update_user_profile(user_id, update).await? {
            self.after_database_update(&DatabaseRecord::User(updated))
                .await?;
        }
        Ok(())
    }
}
