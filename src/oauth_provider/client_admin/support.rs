use crate::{
    AuthError,
    oauth_provider::{OAuthCallbackContext, OAuthProviderError},
};
use serde_json::Value;

pub(super) fn context_user_id(context: &OAuthCallbackContext) -> Result<&str, OAuthProviderError> {
    context
        .user
        .as_ref()
        .and_then(|user| user.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| OAuthProviderError::UnauthorizedClient("authentication required".into()))
}

pub(super) fn server_error(error: AuthError) -> OAuthProviderError {
    OAuthProviderError::ServerError(error.to_string())
}
