use super::input::ClientMetadataInput;
use crate::{AuthService, oauth_provider::OAuthProviderError};

pub(super) fn validate(
    service: &AuthService,
    input: &ClientMetadataInput,
) -> Result<(), OAuthProviderError> {
    let auth_method = input
        .token_endpoint_auth_method
        .as_deref()
        .unwrap_or("client_secret_basic");
    if auth_method == "private_key_jwt" && input.jwks.is_none() && input.jwks_uri.is_none() {
        return Err(OAuthProviderError::InvalidRequest(
            "private_key_jwt requires either jwks or jwks_uri".into(),
        ));
    }
    if input.jwks.is_some() && input.jwks_uri.is_some() {
        return Err(OAuthProviderError::InvalidRequest(
            "jwks and jwks_uri are mutually exclusive".into(),
        ));
    }
    if let Some(uri) = input.jwks_uri.as_deref() {
        super::super::token::validate_registration_jwks_uri(service, uri, None)
            .map_err(OAuthProviderError::InvalidRequest)?;
    }
    if let Some(jwks) = input.jwks.as_ref() {
        super::super::token::validate_registration_jwks(jwks)
            .map_err(|error| OAuthProviderError::InvalidRequest(error.into()))?;
    }
    Ok(())
}
