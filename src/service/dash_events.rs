use super::AuthService;
use crate::{AuthError, AuthUser};

impl AuthService {
    pub(crate) async fn dash_event_user(
        &self,
        user_id: &str,
    ) -> Result<Option<AuthUser>, AuthError> {
        self.store.find_user_by_id(user_id).await
    }

    #[cfg(feature = "axum")]
    pub(crate) async fn dash_event_user_by_email(
        &self,
        email: &str,
    ) -> Result<Option<AuthUser>, AuthError> {
        self.store.find_user_by_email(email).await
    }
}
