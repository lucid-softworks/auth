use super::super::AuthService;
use crate::{AuthError, UserProfileUpdate};
use chrono::{DateTime, Utc};
use serde_json::{Map, json};

impl AuthService {
    pub(crate) async fn dash_touch_user_activity(&self, user_id: &str) -> Result<(), AuthError> {
        self.dash_set_user_activity(user_id, Utc::now()).await
    }

    pub(super) async fn dash_set_user_activity(
        &self,
        user_id: &str,
        last_active_at: DateTime<Utc>,
    ) -> Result<(), AuthError> {
        let mut additional_fields = Map::new();
        additional_fields.insert("lastActiveAt".into(), json!(last_active_at));
        self.store
            .update_user_profile(
                user_id,
                UserProfileUpdate {
                    additional_fields,
                    ..UserProfileUpdate::default()
                },
            )
            .await?;
        Ok(())
    }
}
