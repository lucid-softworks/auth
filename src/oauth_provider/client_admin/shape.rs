use super::{OAuthProviderClientAdminCreateInput, OAuthProviderClientAdminUpdateInput};
use crate::oauth_provider::OAuthProviderError;

pub(super) fn normalize_strings(method: &mut Option<String>, grants: &mut Option<Vec<String>>) {
    if let Some(method) = method {
        *method = method.trim().to_owned();
    }
    normalize_grants(grants);
}

pub(super) fn normalize_grants(grants: &mut Option<Vec<String>>) {
    for grant in grants.iter_mut().flatten() {
        *grant = grant.trim().to_owned();
    }
}

pub(super) fn validate_create(
    input: &OAuthProviderClientAdminCreateInput,
) -> Result<(), OAuthProviderError> {
    validate_common(
        input.redirect_uris.as_ref(),
        input.post_logout_redirect_uris.as_ref(),
        input.contacts.as_ref(),
        input.grant_types.as_ref(),
        input.response_types.as_ref(),
    )?;
    if input
        .token_endpoint_auth_method
        .as_deref()
        .is_some_and(str::is_empty)
    {
        return Err(OAuthProviderError::InvalidRequest(
            "token_endpoint_auth_method must not be empty".into(),
        ));
    }
    Ok(())
}

pub(super) fn validate_update(
    input: &OAuthProviderClientAdminUpdateInput,
) -> Result<(), OAuthProviderError> {
    validate_common(
        input.redirect_uris.as_ref(),
        input.post_logout_redirect_uris.as_ref(),
        input.contacts.as_ref(),
        input.grant_types.as_ref(),
        input.response_types.as_ref(),
    )
}

fn validate_common(
    redirect_uris: Option<&Vec<String>>,
    post_logout_redirect_uris: Option<&Vec<String>>,
    contacts: Option<&Vec<String>>,
    grant_types: Option<&Vec<String>>,
    response_types: Option<&Vec<String>>,
) -> Result<(), OAuthProviderError> {
    for (name, values) in [
        ("redirect_uris", redirect_uris),
        ("post_logout_redirect_uris", post_logout_redirect_uris),
        ("contacts", contacts),
    ] {
        if values.is_some_and(Vec::is_empty) {
            return Err(OAuthProviderError::InvalidRequest(format!(
                "{name} must contain at least one value"
            )));
        }
    }
    let has_empty = contacts.into_iter().flatten().any(|value| value.is_empty())
        || grant_types
            .is_some_and(|values| values.is_empty() || values.iter().any(String::is_empty));
    if has_empty {
        return Err(OAuthProviderError::InvalidRequest(
            "client metadata arrays must contain non-empty values".into(),
        ));
    }
    if response_types
        .into_iter()
        .flatten()
        .any(|response| response != "code")
    {
        return Err(OAuthProviderError::InvalidRequest(
            "response_types may only contain code".into(),
        ));
    }
    Ok(())
}
