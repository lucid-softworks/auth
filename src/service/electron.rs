use super::{AuthService, SignInResult};
use crate::AuthError;

impl AuthService {
    pub(crate) async fn create_electron_session(
        &self,
        user_id: &str,
    ) -> Result<Option<SignInResult>, AuthError> {
        let Some(user) = self.store.find_user_by_id(user_id).await? else {
            return Ok(None);
        };
        self.create_session(user, None, None, None, None)
            .await
            .map(Some)
    }
}
