use super::{CimdMetadata, CimdOptions};
use crate::{
    AuthError, AuthService, DatabaseIdInput, OAuthCallbackContext, OAuthClientRegistrationMode,
    OAuthClientRegistrationOutcome, OAuthClientRegistrationWrite, OAuthProviderClient,
    OAuthProviderError, OAuthProviderPluginConfig, OAuthProviderStore,
};
use chrono::{TimeZone, Utc};
use serde_json::Value;
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct ProviderBinding {
    pub service: AuthService,
    pub config: Arc<OAuthProviderPluginConfig>,
    pub store: Arc<dyn OAuthProviderStore>,
}

pub(super) async fn persist_client(
    binding: &ProviderBinding,
    options: &CimdOptions,
    client_id: &str,
    metadata: &CimdMetadata,
    existing: Option<&OAuthProviderClient>,
    context: &OAuthCallbackContext,
) -> Result<OAuthProviderClient, AuthError> {
    if existing.is_some_and(|client| client.client_discovery_id.as_deref() != Some("cimd")) {
        return Err(OAuthProviderError::InvalidClient(
            "client_id is already owned by a different registration source".into(),
        )
        .into());
    }
    let client = client_from_metadata(client_id, metadata, existing);
    let created = existing.is_none();
    let outcome = write(binding, client, created).await?;
    let (client, created, previous) = match outcome {
        OAuthClientRegistrationOutcome::Created(client) => (client, true, None),
        OAuthClientRegistrationOutcome::Updated(client) => {
            (client, false, existing.cloned())
        }
        OAuthClientRegistrationOutcome::ClientIdTaken if created => {
            retry_same_owner_race(binding, options, client_id, metadata).await?
        }
        OAuthClientRegistrationOutcome::DiscoveryOwnershipChanged
        | OAuthClientRegistrationOutcome::ClientIdTaken => {
            return Err(OAuthProviderError::InvalidClient(
                "client_id is already owned by a different registration source".into(),
            )
            .into());
        }
        OAuthClientRegistrationOutcome::ResourceNotFound(resource) => {
            return Err(OAuthProviderError::InvalidClient(format!(
                "server-default resource {resource} does not exist"
            ))
            .into());
        }
    };
    notify_lifecycle(options, client.clone(), previous, metadata, context, created).await;
    Ok(client)
}

async fn retry_same_owner_race(
    binding: &ProviderBinding,
    _options: &CimdOptions,
    client_id: &str,
    metadata: &CimdMetadata,
) -> Result<(OAuthProviderClient, bool, Option<OAuthProviderClient>), AuthError> {
    let current = binding
        .store
        .find_oauth_client(client_id)
        .await?
        .filter(|client| client.client_discovery_id.as_deref() == Some("cimd"))
        .ok_or_else(|| {
            AuthError::from(OAuthProviderError::InvalidClient(
                "client_id is already owned by a different registration source".into(),
            ))
        })?;
    match write(
        binding,
        client_from_metadata(client_id, metadata, Some(&current)),
        false,
    )
    .await?
    {
        OAuthClientRegistrationOutcome::Updated(client) => Ok((client, false, Some(current))),
        _ => Err(OAuthProviderError::InvalidClient(
            "unable to reconcile discovered client registration".into(),
        )
        .into()),
    }
}

async fn write(
    binding: &ProviderBinding,
    client: OAuthProviderClient,
    create: bool,
) -> Result<OAuthClientRegistrationOutcome, AuthError> {
    let service = &binding.service;
    binding
        .store
        .persist_oauth_client_registration(
            &|| {
                service.prepare_database_id(&service.database_id_plan(
                    "oauthClient",
                    DatabaseIdInput::Absent,
                    false,
                ))
            },
            &|| {
                service.prepare_database_id(&service.database_id_plan(
                    "oauthClientResource",
                    DatabaseIdInput::Absent,
                    false,
                ))
            },
            OAuthClientRegistrationWrite {
                client,
                resource_ids: binding.config.client_registration_default_resources.clone(),
                mode: if create {
                    OAuthClientRegistrationMode::Create
                } else {
                    OAuthClientRegistrationMode::RefreshDiscovered {
                        discovery_id: "cimd".into(),
                    }
                },
            },
        )
        .await
}

fn client_from_metadata(
    client_id: &str,
    metadata: &CimdMetadata,
    existing: Option<&OAuthProviderClient>,
) -> OAuthProviderClient {
    let now = Utc
        .timestamp_opt(Utc::now().timestamp(), 0)
        .single()
        .unwrap_or_else(Utc::now);
    OAuthProviderClient {
        id: existing.map_or_else(String::new, |client| client.id.clone()),
        client_id: client_id.into(),
        client_secret: None,
        client_discovery_id: Some("cimd".into()),
        disabled: existing.is_some_and(|client| client.disabled),
        skip_consent: existing.and_then(|client| client.skip_consent),
        enable_end_session: existing.and_then(|client| client.enable_end_session),
        subject_type: string(metadata, "subject_type"),
        scopes: string(metadata, "scope").map(|scope| {
            scope.split_whitespace().map(str::to_owned).collect()
        }),
        client_credentials_scopes: existing
            .map(|client| client.client_credentials_scopes.clone())
            .unwrap_or_default(),
        user_id: existing.and_then(|client| client.user_id.clone()),
        created_at: existing.and_then(|client| client.created_at).or(Some(now)),
        updated_at: Some(now),
        expires_at: None,
        name: string(metadata, "client_name"),
        uri: string(metadata, "client_uri"),
        icon: string(metadata, "logo_uri"),
        contacts: strings(metadata, "contacts"),
        tos: string(metadata, "tos_uri"),
        policy: string(metadata, "policy_uri"),
        software_id: string(metadata, "software_id"),
        software_version: string(metadata, "software_version"),
        software_statement: string(metadata, "software_statement"),
        redirect_uris: strings(metadata, "redirect_uris").unwrap_or_default(),
        post_logout_redirect_uris: strings(metadata, "post_logout_redirect_uris"),
        backchannel_logout_uri: None,
        backchannel_logout_session_required: None,
        token_endpoint_auth_method: string(metadata, "token_endpoint_auth_method"),
        application_type: string(metadata, "application_type"),
        jwks: metadata.get("jwks").map(Value::to_string),
        jwks_uri: string(metadata, "jwks_uri"),
        grant_types: strings(metadata, "grant_types"),
        response_types: strings(metadata, "response_types"),
        require_pkce: None,
        dpop_bound_access_tokens: metadata
            .get("dpop_bound_access_tokens")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        reference_id: existing.and_then(|client| client.reference_id.clone()),
        metadata: None,
    }
}

async fn notify_lifecycle(
    options: &CimdOptions,
    client: OAuthProviderClient,
    previous: Option<OAuthProviderClient>,
    metadata: &CimdMetadata,
    context: &OAuthCallbackContext,
    created: bool,
) {
    let Some(lifecycle) = &options.lifecycle else { return; };
    let result = if created {
        lifecycle
            .created(super::CimdClientCreatedEvent {
                client,
                client_metadata_document: metadata.clone(),
                context: context.clone(),
            })
            .await
    } else if let Some(previous_client) = previous {
        lifecycle
            .refreshed(super::CimdClientRefreshedEvent {
                client,
                previous_client,
                client_metadata_document: metadata.clone(),
                context: context.clone(),
            })
            .await
    } else { Ok(()) };
    if let Err(error) = result {
        tracing::error!(%error, "cimd client lifecycle notification failed");
    }
}

fn string(metadata: &CimdMetadata, name: &str) -> Option<String> {
    metadata.get(name).and_then(Value::as_str).map(str::to_owned)
}

fn strings(metadata: &CimdMetadata, name: &str) -> Option<Vec<String>> {
    metadata.get(name).and_then(Value::as_array).map(|values| {
        values.iter().filter_map(Value::as_str).map(str::to_owned).collect()
    })
}
