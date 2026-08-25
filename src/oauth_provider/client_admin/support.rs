use crate::{
    AuthError,
    oauth_provider::{OAuthCallbackContext, OAuthProviderError},
};
use serde_json::Value;
use uuid::Uuid;

pub(super) fn context_user_id(context: &OAuthCallbackContext) -> Result<Uuid, OAuthProviderError> {
    context
        .user
        .as_ref()
        .and_then(|user| user.get("id"))
        .and_then(Value::as_str)
        .and_then(|id| Uuid::parse_str(id).ok())
        .ok_or_else(|| OAuthProviderError::UnauthorizedClient("authentication required".into()))
}

pub(super) fn server_error(error: AuthError) -> OAuthProviderError {
    OAuthProviderError::ServerError(error.to_string())
}
