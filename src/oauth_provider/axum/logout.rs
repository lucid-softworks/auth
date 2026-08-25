use crate::{AuthService, AxumPluginRoute, axum::body::OptionalBetterAuthBody};
use axum::{
    Extension,
    extract::Query,
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::get,
};
use std::{convert::Infallible, sync::Arc};

use super::super::{OAuthProviderConfig, OAuthProviderError, OAuthProviderStore};

mod input;
mod presentation;
mod remote_jwks;
mod state;
mod validation;

use super::body::FormOnly;
use input::{ConfirmationInput, EndSessionInput};
use presentation::{complete_response, confirmation_required, protocol_error};
use state::{clear_confirmation, confirmation_context, read_confirmation};
use validation::{
    current_session, delete_session, hinted_session, logout_client, resolve_hint_client,
    validate_redirect, verify_hint,
};

pub(super) fn routes(
    config: Arc<OAuthProviderConfig>,
    store: Arc<dyn OAuthProviderStore>,
) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new(
            "/oauth2/end-session",
            with_extensions(
                get(end_session_get).post(end_session_post),
                config.clone(),
                store.clone(),
            ),
        ),
        AxumPluginRoute::new(
            "/oauth2/end-session/confirm",
            with_extensions(axum::routing::post(confirm), config, store),
        ),
    ]
}

fn with_extensions(
    route: axum::routing::MethodRouter,
    config: Arc<OAuthProviderConfig>,
    store: Arc<dyn OAuthProviderStore>,
) -> axum::routing::MethodRouter {
    route
        .layer::<_, Infallible>(Extension(store))
        .layer::<_, Infallible>(Extension(config))
}

async fn end_session_get(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<OAuthProviderConfig>>,
    Extension(store): Extension<Arc<dyn OAuthProviderStore>>,
    headers: HeaderMap,
    Query(input): Query<EndSessionInput>,
) -> Response {
    end_session(&service, &config, store.as_ref(), &headers, input).await
}

async fn end_session_post(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<OAuthProviderConfig>>,
    Extension(store): Extension<Arc<dyn OAuthProviderStore>>,
    headers: HeaderMap,
    Query(query): Query<EndSessionInput>,
    OptionalBetterAuthBody(body): OptionalBetterAuthBody<EndSessionInput>,
) -> Response {
    end_session(
        &service,
        &config,
        store.as_ref(),
        &headers,
        query.merge(body),
    )
    .await
}

async fn end_session(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
    input: EndSessionInput,
) -> Response {
    let current = match current_session(service, headers).await {
        Ok(current) => current,
        Err(error) => return protocol_error(headers, &error),
    };
    let Some(hint) = input.id_token_hint.as_deref() else {
        let context = if let Some(client_id) = input.client_id.as_deref() {
            let client = match logout_client(config, store, headers, client_id).await {
                Ok(client) => client,
                Err(error) => return protocol_error(headers, &error),
            };
            confirmation_context(&client, &input)
        } else {
            Default::default()
        };
        return confirmation_required(service, headers, current.as_ref(), context);
    };
    let client = match resolve_hint_client(config, store, headers, hint, input.client_id.as_deref())
        .await
    {
        Ok(Some(client)) => client,
        Ok(None) if current.is_some() && presentation::is_browser_navigation(headers) => {
            return confirmation_required(service, headers, current.as_ref(), Default::default());
        }
        Ok(None) => {
            return protocol_error(
                headers,
                &OAuthProviderError::InvalidClient("The logout client does not exist".into()),
            );
        }
        Err(error) => return protocol_error(headers, &error),
    };
    let payload = match verify_hint(service, config, headers, hint, &client).await {
        Ok(Some(payload)) => payload,
        Ok(None) if current.is_some() && presentation::is_browser_navigation(headers) => {
            let context = input
                .client_id
                .as_ref()
                .map(|_| confirmation_context(&client, &input))
                .unwrap_or_default();
            return confirmation_required(service, headers, current.as_ref(), context);
        }
        Ok(None) => {
            return protocol_error(
                headers,
                &OAuthProviderError::UnchallengedInvalidToken(
                    "The id_token_hint is invalid".into(),
                ),
            );
        }
        Err(error) => return protocol_error(headers, &error),
    };
    complete_hint_logout(service, headers, input, current, client, payload).await
}

async fn complete_hint_logout(
    service: &AuthService,
    headers: &HeaderMap,
    input: EndSessionInput,
    current: Option<crate::AuthSession>,
    client: crate::oauth_provider::OAuthProviderClient,
    payload: serde_json::Map<String, serde_json::Value>,
) -> Response {
    let session_id = payload
        .get("sid")
        .and_then(serde_json::Value::as_str)
        .and_then(|value| uuid::Uuid::parse_str(value).ok());
    let matches_current = current
        .as_ref()
        .is_some_and(|session| Some(session.id) == session_id);
    if current.is_some() && !matches_current {
        return confirmation_required(
            service,
            headers,
            current.as_ref(),
            confirmation_context(&client, &input),
        );
    }
    let redirect = validate_redirect(&client, &input);
    let hinted = match session_id {
        Some(id) => match hinted_session(service, id).await {
            Ok(session) => session,
            Err(error) => return protocol_error(headers, &error),
        },
        None => None,
    };
    if let Some(session) = hinted.or_else(|| matches_current.then(|| current.clone()).flatten())
        && let Err(error) = delete_session(service, &session).await
    {
        return protocol_error(headers, &error);
    }
    let response = complete_response(headers, &redirect);
    let response = clear_confirmation(service, response);
    if matches_current {
        crate::axum::http::clear_session_cookie_from_request(service, headers, response)
    } else {
        response
    }
}

async fn confirm(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<OAuthProviderConfig>>,
    Extension(store): Extension<Arc<dyn OAuthProviderStore>>,
    headers: HeaderMap,
    FormOnly(input): FormOnly<ConfirmationInput>,
) -> Response {
    if input.action != "confirm" {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "error": "invalid_request",
                "error_description": "action must be one of: confirm"
            })),
        )
            .into_response();
    }
    confirm_logout(&service, &config, store.as_ref(), &headers).await
}

async fn confirm_logout(
    service: &AuthService,
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    headers: &HeaderMap,
) -> Response {
    let Some(state) = read_confirmation(service, headers) else {
        return protocol_error(
            headers,
            &OAuthProviderError::InvalidRequest(
                "The logout confirmation is invalid or expired".into(),
            ),
        );
    };
    let current = match current_session(service, headers).await {
        Ok(current) => current,
        Err(error) => return protocol_error(headers, &error),
    };
    let redirect = validation::confirmed_redirect(config, store, headers, &state).await;
    let Some(current) = current else {
        if redirect.uri.is_some() || presentation::is_browser_navigation(headers) {
            let response = complete_response(headers, &redirect);
            return clear_confirmation(service, response);
        }
        return clear_confirmation(
            service,
            protocol_error(
                headers,
                &OAuthProviderError::InvalidRequest(
                    "No active session is available for logout".into(),
                ),
            ),
        );
    };
    if state.session_id.is_some_and(|id| id != current.id) {
        return protocol_error(
            headers,
            &OAuthProviderError::InvalidRequest(
                "The logout confirmation is invalid or expired".into(),
            ),
        );
    }
    if let Err(error) = delete_session(service, &current).await {
        return protocol_error(headers, &error);
    }
    let response = complete_response(headers, &redirect);
    let response = clear_confirmation(service, response);
    crate::axum::http::clear_session_cookie_from_request(service, headers, response)
}
