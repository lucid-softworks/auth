use super::{OAuthProviderClientAdminCreateInput, OAuthProviderClientAdminUpdateInput};
use crate::oauth_provider::OAuthProviderClient;
use chrono::{DateTime, Utc};
use serde_json::Value;
use uuid::Uuid;

pub(super) fn from_create(
    input: OAuthProviderClientAdminCreateInput,
    client_id: String,
    client_secret: Option<String>,
    user_id: Option<String>,
    reference_id: Option<String>,
    now: DateTime<Utc>,
) -> OAuthProviderClient {
    let grants = input
        .grant_types
        .unwrap_or_else(|| vec!["authorization_code".into()]);
    let response_types = input.response_types.or_else(|| {
        grants
            .iter()
            .any(|grant| grant == "authorization_code")
            .then(|| vec!["code".into()])
    });
    OAuthProviderClient {
        id: Uuid::new_v4(),
        client_id,
        client_secret,
        client_discovery_id: None,
        disabled: false,
        skip_consent: input.skip_consent,
        enable_end_session: input.enable_end_session,
        subject_type: input.subject_type,
        scopes: input.scopes,
        client_credentials_scopes: input.client_credentials_scopes,
        user_id,
        created_at: Some(now),
        updated_at: Some(now),
        expires_at: input.client_secret_expires_at,
        name: input.client_name,
        uri: input.client_uri,
        icon: input.logo_uri,
        contacts: input.contacts,
        tos: input.tos_uri,
        policy: input.policy_uri,
        software_id: input.software_id,
        software_version: input.software_version,
        software_statement: input.software_statement,
        redirect_uris: input.redirect_uris.unwrap_or_default(),
        post_logout_redirect_uris: input.post_logout_redirect_uris,
        backchannel_logout_uri: input.backchannel_logout_uri,
        backchannel_logout_session_required: input.backchannel_logout_session_required,
        token_endpoint_auth_method: Some(
            input
                .token_endpoint_auth_method
                .unwrap_or_else(|| "client_secret_basic".into()),
        ),
        application_type: Some(input.application_type.unwrap_or_else(|| "web".into())),
        jwks: input.jwks.map(|jwks| jwks.to_string()),
        jwks_uri: input.jwks_uri,
        grant_types: Some(grants),
        response_types,
        require_pkce: input.require_pkce,
        dpop_bound_access_tokens: input.dpop_bound_access_tokens.unwrap_or(false),
        reference_id,
        metadata: input.metadata.map(Value::Object),
    }
}

pub(super) fn apply_update(
    client: &mut OAuthProviderClient,
    input: OAuthProviderClientAdminUpdateInput,
) {
    macro_rules! replace {
        ($input:ident, $output:ident) => {
            if let Some(value) = input.$input {
                client.$output = Some(value);
            }
        };
    }
    if let Some(value) = input.redirect_uris {
        client.redirect_uris = value;
    }
    replace!(scopes, scopes);
    replace!(client_name, name);
    replace!(client_uri, uri);
    replace!(logo_uri, icon);
    replace!(contacts, contacts);
    replace!(tos_uri, tos);
    replace!(policy_uri, policy);
    replace!(software_id, software_id);
    replace!(software_version, software_version);
    replace!(software_statement, software_statement);
    replace!(post_logout_redirect_uris, post_logout_redirect_uris);
    replace!(backchannel_logout_uri, backchannel_logout_uri);
    replace!(
        backchannel_logout_session_required,
        backchannel_logout_session_required
    );
    replace!(application_type, application_type);
    replace!(grant_types, grant_types);
    if let Some(value) = input.client_credentials_scopes {
        client.client_credentials_scopes = value;
    }
    replace!(response_types, response_types);
    if let Some(value) = input.client_secret_expires_at {
        client.expires_at = value;
    }
    replace!(skip_consent, skip_consent);
    replace!(enable_end_session, enable_end_session);
    if let Some(value) = input.dpop_bound_access_tokens {
        client.dpop_bound_access_tokens = value;
    }
    if let Some(value) = input.metadata {
        client.metadata = Some(Value::Object(value));
    }
}

pub(super) fn clear_inapplicable_client_credentials_scopes(client: &mut OAuthProviderClient) {
    let supports_grant = client
        .grant_types
        .as_deref()
        .unwrap_or_default()
        .iter()
        .any(|grant| grant == "client_credentials");
    if !supports_grant || client.token_endpoint_auth_method.as_deref() == Some("none") {
        client.client_credentials_scopes.clear();
    }
}
