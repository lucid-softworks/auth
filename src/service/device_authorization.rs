use super::AuthService;
use crate::{AuthError, AuthUser, AuthenticationMethod, SignInResult};
use axum::http::HeaderMap;

impl AuthService {
    pub(crate) async fn device_authorization_user(
        &self,
        user_id: &str,
    ) -> Result<Option<AuthUser>, AuthError> {
        self.store.find_user_by_id(user_id).await
    }

    pub(crate) async fn create_device_authorization_session(
        &self,
        user: AuthUser,
        headers: &HeaderMap,
    ) -> Result<SignInResult, AuthError> {
        let ip_address = self.resolve_client_ip(|name| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        });
        self.create_session(
            user,
            AuthenticationMethod::Extension,
            None,
            ip_address,
            crate::axum::http::user_agent(headers),
        )
        .await
    }
}
