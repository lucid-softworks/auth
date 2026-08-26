use super::input::ClientMetadataInput;
use super::registration_support::{
    expiration_date, generate_client_id, generate_secret, server_error,
};
use super::validation::{registration_scopes, validate_metadata};
use super::wire::client_json;
use super::{ManagementState, second_precision_now, split_scopes};
use crate::{
    AuthService,
    oauth_provider::{
        OAuthCallbackContext, OAuthClientRegistrationMode, OAuthClientRegistrationOutcome,
        OAuthClientRegistrationWrite, OAuthProviderClient, OAuthProviderConfig, OAuthProviderError,
    },
};
use serde_json::Value;
use std::collections::BTreeSet;
use uuid::Uuid;

use super::super::super::crypto::store_client_secret;

#[derive(Clone, Copy)]
pub(super) enum RegistrationSource {
    Dynamic,
    OwnerCreate,
    OwnerUpdate,
    Admin,
}

pub(super) fn normalize_input(
    config: &OAuthProviderConfig,
    input: &mut ClientMetadataInput,
    source: RegistrationSource,
) {
    if let Some(method) = input.token_endpoint_auth_method.as_mut() {
        *method = method.trim().to_owned();
    }
    if let Some(grants) = input.grant_types.as_mut() {
        for grant in grants {
            *grant = grant.trim().to_owned();
        }
    }
    match source {
        RegistrationSource::Dynamic => {
            input.require_pkce = None;
            let extension_fields = config
                .extensions
                .iter()
                .flat_map(|extension| extension.client_registration_metadata_fields())
                .collect::<BTreeSet<_>>();
            input
                .extensions
                .retain(|name, _| extension_fields.contains(name));
        }
        RegistrationSource::OwnerCreate => {
            input.require_pkce = None;
            input.subject_type = None;
            input.resources = None;
            input.extensions.clear();
        }
        RegistrationSource::OwnerUpdate => {
            input.token_endpoint_auth_method = None;
            input.jwks = None;
            input.jwks_uri = None;
            input.require_pkce = None;
            input.dpop_bound_access_tokens = None;
            input.subject_type = None;
            input.resources = None;
            input.extensions.clear();
        }
        RegistrationSource::Admin => {}
    }
}

pub(super) async fn persist_new_client(
    service: &AuthService,
    state: &ManagementState,
    mut input: ClientMetadataInput,
    user_id: Option<String>,
    reference_id: Option<String>,
    source: RegistrationSource,
    context: &OAuthCallbackContext,
) -> Result<Value, OAuthProviderError> {
    apply_defaults(&state.config, &mut input, source);
    validate_metadata(service, &state.config, &input, source, context).await?;
    if matches!(source, RegistrationSource::Dynamic) {
        input.scope = Some(registration_scopes(&state.config).join(" "));
    }
    let prepared =
        prepare_registration(service, state, input, user_id, reference_id, source).await?;
    let persisted =
        persist_registration(state, prepared.client, prepared.resources.clone()).await?;
    let exposed = prepared.plaintext.map(|secret| {
        format!(
            "{}{}",
            state.config.prefix.client_secret.as_deref().unwrap_or(""),
            secret
        )
    });
    Ok(client_json(
        &state.config,
        &persisted,
        exposed.as_deref(),
        Some(&prepared.resources),
    ))
}

struct PreparedRegistration {
    client: OAuthProviderClient,
    plaintext: Option<String>,
    resources: Vec<String>,
}

async fn prepare_registration(
    service: &AuthService,
    state: &ManagementState,
    input: ClientMetadataInput,
    user_id: Option<String>,
    reference_id: Option<String>,
    source: RegistrationSource,
) -> Result<PreparedRegistration, OAuthProviderError> {
    let resources = resolve_resources(state, &input, source).await?;
    let (plaintext, stored_secret) = registration_secret(service, state, &input).await?;
    let now = second_precision_now();
    let expires_at = if stored_secret.is_some() && matches!(source, RegistrationSource::Dynamic) {
        match state
            .config
            .client_registration_client_secret_expiration
            .as_ref()
        {
            Some(configured) => expiration_date(configured, now)?,
            None => None,
        }
    } else {
        None
    };
    let client_id = generate_client_id(&state.config)
        .await
        .map_err(server_error)?;
    let client = client_from_input(
        input,
        client_id,
        stored_secret,
        user_id,
        reference_id,
        now,
        expires_at,
        source,
    );
    Ok(PreparedRegistration {
        client,
        plaintext,
        resources,
    })
}

async fn registration_secret(
    service: &AuthService,
    state: &ManagementState,
    input: &ClientMetadataInput,
) -> Result<(Option<String>, Option<String>), OAuthProviderError> {
    let method = input.token_endpoint_auth_method.as_deref();
    if matches!(method, Some("none" | "private_key_jwt")) {
        return Ok((None, None));
    }
    let plaintext = generate_secret(&state.config).await.map_err(server_error)?;
    let stored = store_client_secret(service, &state.config, &plaintext)
        .await
        .map_err(server_error)?;
    Ok((Some(plaintext), Some(stored)))
}

#[allow(clippy::too_many_arguments)]
fn client_from_input(
    input: ClientMetadataInput,
    client_id: String,
    client_secret: Option<String>,
    user_id: Option<String>,
    reference_id: Option<String>,
    now: chrono::DateTime<chrono::Utc>,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
    source: RegistrationSource,
) -> OAuthProviderClient {
    let metadata = (matches!(source, RegistrationSource::Dynamic) && !input.extensions.is_empty())
        .then(|| Value::Object(input.extensions.clone()));
    OAuthProviderClient {
        id: Uuid::new_v4(),
        client_id,
        client_secret,
        client_discovery_id: None,
        disabled: false,
        skip_consent: None,
        enable_end_session: None,
        subject_type: input.subject_type,
        scopes: input.scope.map(|scope| split_scopes(&scope)),
        client_credentials_scopes: Vec::new(),
        user_id,
        created_at: Some(now),
        updated_at: Some(now),
        expires_at,
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
        token_endpoint_auth_method: input.token_endpoint_auth_method,
        application_type: input.application_type,
        jwks: input.jwks.map(|value| value.to_string()),
        jwks_uri: input.jwks_uri,
        grant_types: input.grant_types,
        response_types: input.response_types,
        require_pkce: input.require_pkce,
        dpop_bound_access_tokens: input.dpop_bound_access_tokens.unwrap_or(false),
        reference_id,
        metadata,
    }
}

async fn persist_registration(
    state: &ManagementState,
    client: OAuthProviderClient,
    resource_ids: Vec<String>,
) -> Result<OAuthProviderClient, OAuthProviderError> {
    let outcome = state
        .store
        .persist_oauth_client_registration(OAuthClientRegistrationWrite {
            client,
            resource_ids,
            mode: OAuthClientRegistrationMode::Create,
        })
        .await
        .map_err(server_error)?;
    match outcome {
        OAuthClientRegistrationOutcome::Created(client) => Ok(client),
        OAuthClientRegistrationOutcome::ClientIdTaken => Err(OAuthProviderError::InvalidClient(
            "client_id is already registered".into(),
        )),
        OAuthClientRegistrationOutcome::ResourceNotFound(resource) => {
            Err(OAuthProviderError::InvalidRequest(format!(
                "requested resource {resource} does not exist"
            )))
        }
        _ => Err(OAuthProviderError::ServerError(
            "unable to register client".into(),
        )),
    }
}

fn apply_defaults(
    config: &OAuthProviderConfig,
    input: &mut ClientMetadataInput,
    source: RegistrationSource,
) {
    let grants = input
        .grant_types
        .get_or_insert_with(|| vec!["authorization_code".into()]);
    if input.response_types.is_none() && grants.iter().any(|grant| grant == "authorization_code") {
        input.response_types = Some(vec!["code".into()]);
    }
    input
        .token_endpoint_auth_method
        .get_or_insert_with(|| "client_secret_basic".into());
    input.application_type.get_or_insert_with(|| "web".into());
    if matches!(source, RegistrationSource::Dynamic) {
        let all_scopes = registration_scopes(config);
        if input.scope.is_none() {
            input.scope = Some(all_scopes.join(" "));
        }
        if input.require_pkce.is_none()
            && !config.client_registration_require_pkce
            && input.token_endpoint_auth_method.as_deref() != Some("none")
        {
            input.require_pkce = Some(false);
        }
    }
}

async fn resolve_resources(
    state: &ManagementState,
    input: &ClientMetadataInput,
    source: RegistrationSource,
) -> Result<Vec<String>, OAuthProviderError> {
    if !matches!(source, RegistrationSource::Dynamic) {
        return Ok(Vec::new());
    }
    let allowed = state
        .config
        .client_registration_default_resources
        .iter()
        .chain(&state.config.client_registration_allowed_resources)
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut resources = state.config.client_registration_default_resources.clone();
    for resource in input.resources.iter().flatten() {
        if !allowed.contains(resource) {
            return Err(OAuthProviderError::InvalidRequest(format!(
                "requested resource {resource} is not allowed for client registration"
            )));
        }
        if !resources.contains(resource) {
            resources.push(resource.clone());
        }
    }
    for resource in &resources {
        match state
            .store
            .find_oauth_resource(resource)
            .await
            .map_err(server_error)?
        {
            Some(row) if row.disabled => {
                return Err(OAuthProviderError::InvalidRequest(format!(
                    "requested resource {resource} is disabled"
                )));
            }
            Some(_) => {}
            None => {
                return Err(OAuthProviderError::InvalidRequest(format!(
                    "requested resource {resource} does not exist"
                )));
            }
        }
    }
    Ok(resources)
}

mod endpoint;

pub(super) use endpoint::register;
