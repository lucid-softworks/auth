use super::super::{ChargebeeRouteState, support};
use axum::{
    Extension,
    body::Bytes,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{MethodRouter, post},
};

pub(super) fn route() -> MethodRouter {
    post(handle)
}

async fn handle(
    Extension(state): Extension<ChargebeeRouteState>,
    headers: HeaderMap,
    payload: Bytes,
) -> Response {
    let authorization = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok());
    let event = match state
        .options
        .client
        .parse_webhook(&payload, authorization, state.options.webhook_credentials())
        .await
    {
        Ok(event) => event,
        Err(error)
            if error.kind
                == crate::chargebee::ChargebeeProviderErrorKind::WebhookAuthentication =>
        {
            return (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
        }
        Err(error) => {
            tracing::error!(%error, "Chargebee webhook payload was not processed");
            return received();
        }
    };
    let dispatcher = super::super::super::webhook::ChargebeeWebhookDispatcher::new(
        state.options.clone(),
        state.store.clone(),
    );
    match dispatcher.handle(event).await {
        Ok(()) => received(),
        Err(
            error @ crate::chargebee::webhook::ChargebeeWebhookProcessingError::QueuePublish {
                ..
            },
        ) => support::literal_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_SERVER_ERROR",
            error.to_string(),
        ),
        Err(error) => support::literal_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL_SERVER_ERROR",
            error.to_string(),
        ),
    }
}

fn received() -> Response {
    support::success(serde_json::json!({"received": true}))
}
