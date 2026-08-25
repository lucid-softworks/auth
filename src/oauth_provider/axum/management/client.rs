use super::input::{
    ClientIdInput, ClientMetadataInput, ClientQuery, PublicClientPreloginInput, UpdateClientInput,
};
use super::registration::{RegistrationSource, normalize_input, persist_new_client};
use super::registration_support::generate_secret;
use super::validation::validate_metadata;
use super::wire::{client_json, endpoint_error, metadata_protocol_error, public_client_json};
use super::{
    ManagementState, apply_update, authorize_client_action, callback_context,
    merged_client_metadata, owns_client, resolve_client_reference, resolve_provider_client,
    second_precision_now,
};
use crate::{
    AuthError, AuthService, OAuthClientAction,
    axum::http::{auth_error, current_session},
};
use axum::{
    Extension, Json,
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::Value;
use std::sync::Arc;

use super::super::super::crypto::store_client_secret;
use super::super::body::JsonOnly;
use super::super::response::{no_store, oauth_error};

pub(super) async fn create_client(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<ManagementState>,
    headers: HeaderMap,
    JsonOnly(mut input): JsonOnly<ClientMetadataInput>,
) -> Response {
    normalize_input(&state.config, &mut input, RegistrationSource::OwnerCreate);
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let context = callback_context(&headers, Some(&session), input.scope.as_deref());
    if let Err(response) =
        authorize_client_action(&state.config, OAuthClientAction::Create, &context).await
    {
        return *response;
    }
    let reference_id = match resolve_client_reference(&state.config, &context).await {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let user_id = reference_id.is_none().then_some(session.user.id);
    match persist_new_client(
        &service,
        &state,
        input,
        user_id,
        reference_id,
        RegistrationSource::OwnerCreate,
        &context,
    )
    .await
    {
        Ok(value) => no_store((StatusCode::CREATED, Json(value)).into_response()),
        Err(error) => metadata_protocol_error(error, true),
    }
}
pub(super) async fn get_client(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<ManagementState>,
    headers: HeaderMap,
    Query(input): Query<ClientQuery>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let context = callback_context(&headers, Some(&session), None);
    if let Err(response) =
        authorize_client_action(&state.config, OAuthClientAction::Read, &context).await
    {
        return *response;
    }
    let client = match resolve_provider_client(&state, &headers, &input.client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => return endpoint_error(StatusCode::NOT_FOUND, "not_found", "client not found"),
        Err(error) => return oauth_error(&error),
    };
    if !owns_client(&state.config, &client, &session, &context).await {
        return auth_error(AuthError::Unauthorized);
    }
    Json(client_json(&state.config, &client, None, None)).into_response()
}

pub(super) async fn get_public_client(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<ManagementState>,
    headers: HeaderMap,
    Query(input): Query<ClientQuery>,
) -> Response {
    if current_session(&service, &headers).await.is_none() {
        return auth_error(AuthError::Unauthorized);
    }
    match resolve_provider_client(&state, &headers, &input.client_id).await {
        Ok(Some(client)) if !client.disabled => {
            Json(public_client_json(&state.config, &client)).into_response()
        }
        Ok(_) => endpoint_error(StatusCode::NOT_FOUND, "not_found", "client not found"),
        Err(error) => oauth_error(&error),
    }
}

pub(super) async fn get_public_client_prelogin(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<ManagementState>,
    headers: HeaderMap,
    JsonOnly(input): JsonOnly<PublicClientPreloginInput>,
) -> Response {
    if !state.config.allow_public_client_prelogin {
        return auth_error(AuthError::InvalidRequest("Bad Request".into()));
    }
    if !input
        .oauth_query
        .as_deref()
        .is_some_and(|query| super::super::authorize::verify_oauth_query_signature(&service, query))
    {
        return endpoint_error(
            StatusCode::UNAUTHORIZED,
            "invalid_signature",
            "invalid_signature",
        );
    }
    match resolve_provider_client(&state, &headers, &input.client_id).await {
        Ok(Some(client)) if !client.disabled => {
            Json(public_client_json(&state.config, &client)).into_response()
        }
        Ok(_) => endpoint_error(StatusCode::NOT_FOUND, "not_found", "client not found"),
        Err(error) => oauth_error(&error),
    }
}

pub(super) async fn list_clients(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<ManagementState>,
    headers: HeaderMap,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let context = callback_context(&headers, Some(&session), None);
    if let Err(response) =
        authorize_client_action(&state.config, OAuthClientAction::List, &context).await
    {
        return *response;
    }
    let reference_id = match resolve_client_reference(&state.config, &context).await {
        Ok(value) => value,
        Err(response) => return *response,
    };
    let user_id = reference_id.is_none().then_some(session.user.id);
    match state
        .store
        .list_oauth_clients(user_id, reference_id.as_deref())
        .await
    {
        Ok(clients) => Json(Value::Array(
            clients
                .iter()
                .map(|client| client_json(&state.config, client, None, None))
                .collect(),
        ))
        .into_response(),
        Err(error) => auth_error(error),
    }
}

pub(super) async fn update_client(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<ManagementState>,
    headers: HeaderMap,
    JsonOnly(mut input): JsonOnly<UpdateClientInput>,
) -> Response {
    normalize_input(
        &state.config,
        &mut input.update,
        RegistrationSource::OwnerUpdate,
    );
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let context = callback_context(&headers, Some(&session), input.update.scope.as_deref());
    if let Err(response) =
        authorize_client_action(&state.config, OAuthClientAction::Update, &context).await
    {
        return *response;
    }
    if state
        .config
        .cached_trusted_clients
        .contains(&input.client_id)
    {
        return endpoint_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_client",
            "trusted clients must be updated manually",
        );
    }
    let mut client = match resolve_provider_client(&state, &headers, &input.client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => return endpoint_error(StatusCode::NOT_FOUND, "not_found", "client not found"),
        Err(error) => return oauth_error(&error),
    };
    if !owns_client(&state.config, &client, &session, &context).await {
        return auth_error(AuthError::Unauthorized);
    }
    let merged = merged_client_metadata(&client, &input.update);
    if let Err(error) = validate_metadata(
        &service,
        &state.config,
        &merged,
        RegistrationSource::OwnerUpdate,
        &context,
    )
    .await
    {
        return metadata_protocol_error(error, false);
    }
    apply_update(&mut client, input.update);
    client.updated_at = Some(second_precision_now());
    match state.store.update_oauth_client(client).await {
        Ok(Some(client)) => Json(client_json(&state.config, &client, None, None)).into_response(),
        Ok(None) => endpoint_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_client",
            "unable to update client",
        ),
        Err(error) => auth_error(error),
    }
}

pub(super) async fn rotate_secret(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<ManagementState>,
    headers: HeaderMap,
    JsonOnly(input): JsonOnly<ClientIdInput>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let context = callback_context(&headers, Some(&session), None);
    if let Err(response) =
        authorize_client_action(&state.config, OAuthClientAction::Rotate, &context).await
    {
        return *response;
    }
    if state
        .config
        .cached_trusted_clients
        .contains(&input.client_id)
    {
        return endpoint_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_client",
            "trusted clients must be updated manually",
        );
    }
    let mut client = match resolve_provider_client(&state, &headers, &input.client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => return endpoint_error(StatusCode::NOT_FOUND, "not_found", "client not found"),
        Err(error) => return oauth_error(&error),
    };
    if !owns_client(&state.config, &client, &session, &context).await {
        return auth_error(AuthError::Unauthorized);
    }
    if client.token_endpoint_auth_method.as_deref() == Some("none")
        || client.client_secret.is_none()
    {
        return endpoint_error(
            StatusCode::BAD_REQUEST,
            "invalid_client",
            "secret rotation is only available for clients using client_secret authentication",
        );
    }
    let plaintext = match generate_secret(&state.config).await {
        Ok(secret) => secret,
        Err(error) => return auth_error(error),
    };
    client.client_secret = match store_client_secret(&service, &state.config, &plaintext).await {
        Ok(secret) => Some(secret),
        Err(error) => return auth_error(error),
    };
    client.updated_at = Some(second_precision_now());
    match state.store.update_oauth_client(client).await {
        Ok(Some(client)) => {
            let exposed = format!(
                "{}{}",
                state.config.prefix.client_secret.as_deref().unwrap_or(""),
                plaintext
            );
            no_store(
                Json(client_json(&state.config, &client, Some(&exposed), None)).into_response(),
            )
        }
        Ok(None) => endpoint_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_client",
            "unable to update client",
        ),
        Err(error) => auth_error(error),
    }
}

pub(super) async fn delete_client(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<ManagementState>,
    headers: HeaderMap,
    JsonOnly(input): JsonOnly<ClientIdInput>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let context = callback_context(&headers, Some(&session), None);
    if let Err(response) =
        authorize_client_action(&state.config, OAuthClientAction::Delete, &context).await
    {
        return *response;
    }
    if state
        .config
        .cached_trusted_clients
        .contains(&input.client_id)
    {
        return endpoint_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid_client",
            "trusted clients must be updated manually",
        );
    }
    let client = match resolve_provider_client(&state, &headers, &input.client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => return endpoint_error(StatusCode::NOT_FOUND, "not_found", "client not found"),
        Err(error) => return oauth_error(&error),
    };
    if !owns_client(&state.config, &client, &session, &context).await {
        return auth_error(AuthError::Unauthorized);
    }
    match state.store.delete_oauth_client(&input.client_id).await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(error) => auth_error(error),
    }
}
