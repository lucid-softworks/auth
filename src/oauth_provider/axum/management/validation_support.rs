use super::{
    input::ClientMetadataInput, registration::RegistrationSource, validation::validate_metadata,
};
use crate::{
    AuthService,
    oauth_provider::{
        OAuthCallbackContext, OAuthProviderClient, OAuthProviderConfig, OAuthProviderError,
    },
};

pub(crate) async fn validate_client(
    service: &AuthService,
    config: &OAuthProviderConfig,
    client: &OAuthProviderClient,
    context: &OAuthCallbackContext,
) -> Result<(), OAuthProviderError> {
    let input = input_from_client(client);
    validate_metadata(service, config, &input, RegistrationSource::Admin, context).await
}

fn input_from_client(client: &OAuthProviderClient) -> ClientMetadataInput {
    ClientMetadataInput {
        redirect_uris: (!client.redirect_uris.is_empty()).then(|| client.redirect_uris.clone()),
        scope: client.scopes.as_ref().map(|scopes| scopes.join(" ")),
        client_name: client.name.clone(),
        client_uri: client.uri.clone(),
        logo_uri: client.icon.clone(),
        contacts: client.contacts.clone(),
        tos_uri: client.tos.clone(),
        policy_uri: client.policy.clone(),
        software_id: client.software_id.clone(),
        software_version: client.software_version.clone(),
        software_statement: client.software_statement.clone(),
        post_logout_redirect_uris: client.post_logout_redirect_uris.clone(),
        backchannel_logout_uri: client.backchannel_logout_uri.clone(),
        backchannel_logout_session_required: client.backchannel_logout_session_required,
        token_endpoint_auth_method: client.token_endpoint_auth_method.clone(),
        application_type: client.application_type.clone(),
        jwks: client
            .jwks
            .as_deref()
            .and_then(|jwks| serde_json::from_str(jwks).ok()),
        jwks_uri: client.jwks_uri.clone(),
        grant_types: client.grant_types.clone(),
        response_types: client.response_types.clone(),
        require_pkce: client.require_pkce,
        dpop_bound_access_tokens: Some(client.dpop_bound_access_tokens),
        subject_type: client.subject_type.clone(),
        resources: None,
        extensions: client
            .metadata
            .as_ref()
            .and_then(serde_json::Value::as_object)
            .cloned()
            .unwrap_or_default(),
    }
}

pub(super) fn validate_shape(input: &ClientMetadataInput) -> Result<(), OAuthProviderError> {
    for (name, values) in [
        ("redirect_uris", input.redirect_uris.as_ref()),
        (
            "post_logout_redirect_uris",
            input.post_logout_redirect_uris.as_ref(),
        ),
        ("contacts", input.contacts.as_ref()),
    ] {
        if values.is_some_and(Vec::is_empty) {
            return Err(OAuthProviderError::InvalidRequest(format!(
                "{name} must contain at least one value"
            )));
        }
    }
    let empty_contact = input
        .contacts
        .iter()
        .flatten()
        .any(|contact| contact.is_empty());
    let empty_method = input
        .token_endpoint_auth_method
        .as_deref()
        .is_some_and(|method| method.trim().is_empty());
    let empty_grant = input.grant_types.as_ref().is_some_and(Vec::is_empty)
        || input
            .grant_types
            .iter()
            .flatten()
            .any(|grant| grant.trim().is_empty());
    if empty_contact || empty_method || empty_grant {
        return Err(OAuthProviderError::InvalidRequest(
            "client metadata must contain non-empty values".into(),
        ));
    }
    if input
        .response_types
        .iter()
        .flatten()
        .any(|response| response != "code")
    {
        return Err(OAuthProviderError::InvalidRequest(
            "response_types may only contain code".into(),
        ));
    }
    Ok(())
}
