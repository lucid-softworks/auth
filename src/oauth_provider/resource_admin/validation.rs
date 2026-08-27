use super::{AuthError, OAuthProviderResourceAdminUpdateInput, OAuthResourceInput};

const RESOURCE_SIGNING_ALGORITHMS: &[&str] = &["EdDSA", "ES256", "ES512", "PS256", "RS256"];

pub(super) fn validate_create_input(input: &OAuthResourceInput) -> Result<(), AuthError> {
    if input.access_token_ttl == Some(0) || input.refresh_token_ttl == Some(0) {
        return Err(AuthError::InvalidRequest(
            "OAuth resource TTLs must be positive".into(),
        ));
    }
    validate_signing_algorithm(input.signing_algorithm.as_deref())
}

pub(super) fn validate_update_input(
    input: &OAuthProviderResourceAdminUpdateInput,
) -> Result<(), AuthError> {
    if input.access_token_ttl == Some(Some(0)) || input.refresh_token_ttl == Some(Some(0)) {
        return Err(AuthError::InvalidRequest(
            "OAuth resource TTLs must be positive".into(),
        ));
    }
    if input
        .access_token_ttl
        .flatten()
        .is_some_and(|value| value > i64::MAX as u64)
        || input
            .refresh_token_ttl
            .flatten()
            .is_some_and(|value| value > i64::MAX as u64)
    {
        return Err(AuthError::InvalidRequest(
            "OAuth resource TTL exceeds i64::MAX".into(),
        ));
    }
    validate_signing_algorithm(input.signing_algorithm.as_ref().and_then(Option::as_deref))
}

fn validate_signing_algorithm(algorithm: Option<&str>) -> Result<(), AuthError> {
    if algorithm.is_some_and(|value| !RESOURCE_SIGNING_ALGORITHMS.contains(&value)) {
        return Err(AuthError::InvalidRequest(
            "OAuth resource signingAlgorithm is unsupported".into(),
        ));
    }
    Ok(())
}
