use super::super::input::ClientMetadataInput;
use super::super::wire::{
    registration_bearer_error, registration_error, registration_protocol_error,
};
use super::super::{
    ManagementState, authorize_client_action, callback_context, resolve_client_reference,
};
use super::{RegistrationSource, normalize_input, persist_new_client};
use crate::{
    AuthService,
    axum::http::current_session,
    oauth_provider::{
        OAuthCallbackContext, OAuthClientAction, OAuthInitialAccessTokenAuthorization,
        OAuthProviderConfig,
    },
};
use axum::{
    Extension, Json,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde_json::{Value, json};
use std::sync::Arc;
use uuid::Uuid;

use super::super::super::body::JsonOnly;
use super::super::super::response::no_store;

pub(in crate::oauth_provider::axum::management) async fn register(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<ManagementState>,
    headers: HeaderMap,
    JsonOnly(mut input): JsonOnly<ClientMetadataInput>,
) -> Response {
    if !state.config.allow_dynamic_client_registration {
        return registration_error(
            StatusCode::FORBIDDEN,
            "access_denied",
            "Client registration is disabled",
        );
    }

    normalize_input(&state.config, &mut input, RegistrationSource::Dynamic);
    let session = current_session(&service, &headers).await;
    let context = callback_context(&headers, session.as_ref(), input.scope.as_deref());
    let metadata = serde_json::to_value(&input).unwrap_or(Value::Null);
    let token_authorization = match registration_token_authorization(
        &state,
        &headers,
        &metadata,
        &context,
        session.is_some(),
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return *response,
    };
    if let Some(response) = anonymous_registration_error(
        &state.config,
        session.is_some(),
        token_authorization.is_some(),
        &input,
    ) {
        return response;
    }
    let (user_id, reference_id) =
        match registration_owner(&state, session.as_ref(), token_authorization, &context).await {
            Ok(owner) => owner,
            Err(response) => return *response,
        };
    match persist_new_client(
        &service,
        &state,
        input,
        user_id,
        reference_id,
        RegistrationSource::Dynamic,
        &context,
    )
    .await
    {
        Ok(value) => no_store((StatusCode::CREATED, Json(value)).into_response()),
        Err(error) => registration_protocol_error(error),
    }
}

async fn registration_token_authorization(
    state: &ManagementState,
    headers: &HeaderMap,
    metadata: &Value,
    context: &OAuthCallbackContext,
    has_session: bool,
) -> Result<Option<OAuthInitialAccessTokenAuthorization>, Box<Response>> {
    if has_session {
        Ok(None)
    } else {
        authorize_initial_access_token(&state.config, headers, metadata, context).await
    }
}

fn anonymous_registration_error(
    config: &OAuthProviderConfig,
    has_session: bool,
    token_authorized: bool,
    input: &ClientMetadataInput,
) -> Option<Response> {
    if !has_session && !token_authorized && !config.allow_unauthenticated_client_registration {
        let mut response = no_store(
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({
                    "error_description": "Authentication required for client registration"
                })),
            )
                .into_response(),
        );
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        return Some(response);
    }
    let has_client_credentials = input
        .grant_types
        .as_ref()
        .is_some_and(|grants| grants.iter().any(|grant| grant == "client_credentials"));
    (!has_session && !token_authorized && has_client_credentials).then(|| {
        registration_error(
            StatusCode::BAD_REQUEST,
            "invalid_client_metadata",
            "client_credentials grant requires authenticated registration",
        )
    })
}

async fn registration_owner(
    state: &ManagementState,
    session: Option<&crate::SessionWithUser>,
    token_authorization: Option<OAuthInitialAccessTokenAuthorization>,
    context: &OAuthCallbackContext,
) -> Result<(Option<Uuid>, Option<String>), Box<Response>> {
    if session.is_some() {
        authorize_client_action(&state.config, OAuthClientAction::Create, context).await?;
    }
    let reference_id = if let Some(authorization) = token_authorization {
        authorization.reference_id
    } else if session.is_some() {
        resolve_client_reference(&state.config, context).await?
    } else {
        None
    };
    let user_id = reference_id
        .is_none()
        .then(|| session.map(|session| session.user.id))
        .flatten();
    Ok((user_id, reference_id))
}

async fn authorize_initial_access_token(
    config: &OAuthProviderConfig,
    headers: &HeaderMap,
    metadata: &Value,
    context: &OAuthCallbackContext,
) -> Result<Option<OAuthInitialAccessTokenAuthorization>, Box<Response>> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let Ok(value) = value.to_str() else {
        return Err(Box::new(registration_bearer_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Malformed initial access token Authorization header",
        )));
    };
    let mut parts = value.split_whitespace();
    let Some(scheme) = parts.next() else {
        return Ok(None);
    };
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Ok(None);
    }
    let Some(token) = parts.next().filter(|_| parts.next().is_none()) else {
        return Err(Box::new(registration_bearer_error(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Malformed initial access token Authorization header",
        )));
    };
    let Some(validator) = &config.callbacks.validate_initial_access_token else {
        return Err(Box::new(registration_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Invalid initial access token",
        )));
    };
    match validator.validate(token, metadata, context).await {
        Ok(Some(authorization)) => Ok(Some(authorization)),
        Ok(None) => Err(Box::new(registration_bearer_error(
            StatusCode::UNAUTHORIZED,
            "invalid_token",
            "Invalid initial access token",
        ))),
        Err(_) => Err(Box::new(registration_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Initial access token validation failed",
        ))),
    }
}
