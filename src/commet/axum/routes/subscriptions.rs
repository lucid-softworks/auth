use super::{
    super::{input, support},
    body::CommetBody,
    common, projection,
};
use crate::{AxumPluginRoute, CommetSubscriptionCancel, commet::CommetPlugin};
use axum::{
    Extension,
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{MethodRouter, get, post},
};
use std::sync::Arc;

pub(super) fn routes(layer: &impl Fn(MethodRouter) -> MethodRouter) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new("/commet/subscription", layer(get(get_subscription))),
        AxumPluginRoute::new(
            "/commet/subscription/cancel",
            layer(post(cancel_subscription)),
        ),
    ]
}

async fn get_subscription(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(plugin): Extension<CommetPlugin>,
    headers: HeaderMap,
) -> Response {
    let session = match common::required_session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    match plugin
        .options()
        .client
        .get_active_subscription(&session.user.id.to_string())
        .await
    {
        Ok(value) => support::json(value),
        Err(error) => common::provider_error(error, "Failed to retrieve subscription"),
    }
}

async fn cancel_subscription(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(plugin): Extension<CommetPlugin>,
    headers: HeaderMap,
    CommetBody(body): CommetBody,
) -> Response {
    let input = match input::cancel(body) {
        Ok(input) => input,
        Err(error) => return common::validation(error),
    };
    let session = match common::required_session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let active = match plugin
        .options()
        .client
        .get_active_subscription(&session.user.id.to_string())
        .await
    {
        Ok(value) => value,
        Err(error) => return common::provider_error(error, "Failed to cancel subscription"),
    };
    if !projection::is_truthy(&active) {
        return support::message(StatusCode::BAD_REQUEST, "No active subscription found");
    }
    let id = projection::property_string(&active, "id");
    match plugin
        .options()
        .client
        .cancel_subscription(
            &id,
            CommetSubscriptionCancel {
                reason: input.reason,
                immediate: input.immediate,
            },
        )
        .await
    {
        Ok(value) => support::json(value),
        Err(error) => common::provider_error(error, "Failed to cancel subscription"),
    }
}
