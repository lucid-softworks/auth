use crate::{
    AuthError,
    oauth_provider::{OAuthProviderConfig, OAuthProviderError, expiration},
};
use chrono::{DateTime, Utc};

use super::super::super::crypto::random_letters;

pub(super) async fn generate_client_id(config: &OAuthProviderConfig) -> Result<String, AuthError> {
    match &config.callbacks.generate_client_id {
        Some(generator) => generator.generate().await,
        None => Ok(random_letters(32)),
    }
}

pub(super) async fn generate_secret(config: &OAuthProviderConfig) -> Result<String, AuthError> {
    match &config.callbacks.generate_client_secret {
        Some(generator) => generator.generate().await,
        None => Ok(random_letters(32)),
    }
}

pub(super) fn expiration_date(
    configured: &super::super::super::OAuthExpiration,
    now: DateTime<Utc>,
) -> Result<Option<DateTime<Utc>>, OAuthProviderError> {
    expiration::expiration_date(configured, now).map_err(server_error_message)
}

pub(super) fn server_error(error: AuthError) -> OAuthProviderError {
    OAuthProviderError::ServerError(error.to_string())
}

fn server_error_message(error: String) -> OAuthProviderError {
    OAuthProviderError::ServerError(error)
}
