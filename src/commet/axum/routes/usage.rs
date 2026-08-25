use super::{
    super::{input, support},
    body::CommetBody,
    common,
};
use crate::{AxumPluginRoute, CommetUsageEvent, CommetUsageProperty, commet::CommetPlugin};
use axum::{
    Extension,
    http::HeaderMap,
    response::Response,
    routing::{MethodRouter, post},
};
use std::sync::Arc;

pub(super) fn routes(layer: &impl Fn(MethodRouter) -> MethodRouter) -> Vec<AxumPluginRoute> {
    vec![AxumPluginRoute::new(
        "/commet/usage/track",
        layer(post(track)),
    )]
}

async fn track(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(plugin): Extension<CommetPlugin>,
    headers: HeaderMap,
    CommetBody(body): CommetBody,
) -> Response {
    let input = match input::usage(body) {
        Ok(input) => input,
        Err(error) => return common::validation(error),
    };
    let session = match common::required_session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let idempotency_key = input
        .idempotency_key
        .as_deref()
        .filter(|key| !key.is_empty());
    let request = CommetUsageEvent {
        feature_code: input.feature,
        customer_id: session.user.id.to_string(),
        value: input.value,
        properties: input.properties.map(|properties| {
            properties
                .into_iter()
                .map(|(property, value)| CommetUsageProperty { property, value })
                .collect()
        }),
    };
    match plugin
        .options()
        .client
        .create_usage_event(request, idempotency_key)
        .await
    {
        Ok(value) => support::json(value),
        Err(error) => common::provider_error(error, "Failed to track usage"),
    }
}
