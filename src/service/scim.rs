use super::AuthService;
use crate::{AdminCreateUser, AuthError, AuthUser, UserProfileUpdate};

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
        self.dash_create_user(AdminCreateUser {
            email,
            password: None,
            name,
            roles: Vec::new(),
            data: serde_json::Map::new(),
        })
        .await
    }

    pub(crate) async fn scim_update_user_profile(
        &self,
        user_id: &str,
        name: String,
        old_email: &str,
        email: String,
    ) -> Result<Option<AuthUser>, AuthError> {
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
        self.delete_user_sessions_with_hooks(user_id).await
    }

    pub(crate) async fn scim_rollback_created_user(&self, user: &AuthUser) {
        let _ = self.delete_user_record_with_hooks(user).await;
    }
}
