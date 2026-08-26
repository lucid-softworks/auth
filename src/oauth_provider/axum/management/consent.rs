use super::wire::endpoint_error;
use super::{ManagementState, resolve_provider_client, second_precision_now};
use crate::{
    AuthError, AuthService,
    axum::http::{auth_error, current_session},
};
use axum::{
    Extension, Json,
    extract::Query,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use std::sync::Arc;
use uuid::Uuid;

use super::super::super::OAuthProviderError;
use super::super::body::JsonOnly;
use super::super::response::oauth_error;

#[derive(Deserialize)]
pub(super) struct ConsentQuery {
    id: String,
}

#[derive(Deserialize)]
pub(super) struct ConsentInput {
    id: String,
}

#[derive(Deserialize)]
pub(super) struct UpdateConsentInput {
    id: String,
    update: ConsentUpdate,
}

#[derive(Deserialize)]
struct ConsentUpdate {
    scopes: Vec<String>,
}

pub(super) async fn get(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<ManagementState>,
    headers: HeaderMap,
    Query(input): Query<ConsentQuery>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let Ok(id) = Uuid::parse_str(&input.id) else {
        return endpoint_error(StatusCode::NOT_FOUND, "not_found", "no consent");
    };
    match state.store.find_oauth_consent(id).await {
        Ok(Some(consent)) if consent.user_id == Some(session.user.id) => {
            Json(consent).into_response()
        }
        Ok(Some(_)) => auth_error(AuthError::Unauthorized),
        Ok(None) => endpoint_error(StatusCode::NOT_FOUND, "not_found", "no consent"),
        Err(error) => auth_error(error),
    }
}

pub(super) async fn list(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<ManagementState>,
    headers: HeaderMap,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    match state.store.list_oauth_consents(&session.user.id).await {
        Ok(consents) => Json(consents).into_response(),
        Err(error) => auth_error(error),
    }
}

pub(super) async fn update(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<ManagementState>,
    headers: HeaderMap,
    JsonOnly(input): JsonOnly<UpdateConsentInput>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let Ok(id) = Uuid::parse_str(&input.id) else {
        return endpoint_error(StatusCode::NOT_FOUND, "not_found", "no consent");
    };
    let mut consent = match state.store.find_oauth_consent(id).await {
        Ok(Some(consent)) if consent.user_id == Some(session.user.id) => consent,
        Ok(Some(_)) => return auth_error(AuthError::Unauthorized),
        Ok(None) => return endpoint_error(StatusCode::NOT_FOUND, "not_found", "no consent"),
        Err(error) => return auth_error(error),
    };
    let client = match resolve_provider_client(&state, &headers, &consent.client_id).await {
        Ok(Some(client)) => client,
        Ok(None) => return endpoint_error(StatusCode::NOT_FOUND, "not_found", "client not found"),
        Err(error) => return oauth_error(&error),
    };
    let allowed = client.scopes.as_ref().unwrap_or(&state.config.scopes);
    if !input
        .update
        .scopes
        .iter()
        .all(|scope| allowed.contains(scope))
    {
        let owner = client
            .reference_id
            .as_deref()
            .map(str::to_owned)
            .or_else(|| client.user_id.map(|id| id.to_string()))
            .unwrap_or_default();
        return oauth_error(&OAuthProviderError::InvalidRequest(format!(
            "unable to provide scopes to {owner}"
        )));
    }
    consent.scopes = input.update.scopes;
    consent.updated_at = second_precision_now();
    match state.store.upsert_oauth_consent(consent).await {
        Ok(consent) => Json(consent).into_response(),
        Err(error) => auth_error(error),
    }
}

pub(super) async fn delete(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<ManagementState>,
    headers: HeaderMap,
    JsonOnly(input): JsonOnly<ConsentInput>,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    let Ok(id) = Uuid::parse_str(&input.id) else {
        return endpoint_error(StatusCode::NOT_FOUND, "not_found", "no consent");
    };
    match state.store.find_oauth_consent(id).await {
        Ok(Some(consent)) if consent.user_id == Some(session.user.id) => {}
        Ok(Some(_)) => return auth_error(AuthError::Unauthorized),
        Ok(None) => return endpoint_error(StatusCode::NOT_FOUND, "not_found", "no consent"),
        Err(error) => return auth_error(error),
    }
    match state.store.delete_oauth_consent(id).await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(error) => auth_error(error),
    }
}
