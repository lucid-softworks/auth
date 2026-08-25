use super::{
    super::{input, support},
    body::CommetBody,
    common, projection,
};
use crate::{AxumPluginRoute, CommetSeatMutation, CommetSeatSetAll, commet::CommetPlugin};
use axum::{
    Extension,
    http::HeaderMap,
    response::Response,
    routing::{MethodRouter, get, post},
};
use serde_json::Value;
use std::{future::Future, sync::Arc};

pub(super) fn routes(layer: &impl Fn(MethodRouter) -> MethodRouter) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new("/commet/seats", layer(get(list))),
        AxumPluginRoute::new("/commet/seats/add", layer(post(add))),
        AxumPluginRoute::new("/commet/seats/remove", layer(post(remove))),
        AxumPluginRoute::new("/commet/seats/set", layer(post(set))),
        AxumPluginRoute::new("/commet/seats/set-all", layer(post(set_all))),
    ]
}

async fn list(
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
        .list_seat_balances(&session.user.id.to_string())
        .await
    {
        Ok(value) => projection::json_field(value, "balances"),
        Err(error) => common::provider_error(error, "Failed to list seats"),
    }
}

async fn add(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(plugin): Extension<CommetPlugin>,
    headers: HeaderMap,
    body: CommetBody,
) -> Response {
    mutate(
        service,
        plugin,
        headers,
        body,
        |client, request| async move { client.add_seats(request).await },
        "Failed to add seats",
    )
    .await
}

async fn remove(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(plugin): Extension<CommetPlugin>,
    headers: HeaderMap,
    body: CommetBody,
) -> Response {
    mutate(
        service,
        plugin,
        headers,
        body,
        |client, request| async move { client.remove_seats(request).await },
        "Failed to remove seats",
    )
    .await
}

async fn set(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(plugin): Extension<CommetPlugin>,
    headers: HeaderMap,
    body: CommetBody,
) -> Response {
    mutate(
        service,
        plugin,
        headers,
        body,
        |client, request| async move { client.set_seats(request).await },
        "Failed to set seats",
    )
    .await
}

async fn mutate<F, Fut>(
    service: Arc<crate::AuthService>,
    plugin: CommetPlugin,
    headers: HeaderMap,
    CommetBody(body): CommetBody,
    operation: F,
    failure: &'static str,
) -> Response
where
    F: FnOnce(Arc<dyn crate::CommetClient>, CommetSeatMutation) -> Fut,
    Fut: Future<Output = Result<Value, crate::CommetProviderError>>,
{
    let input = match input::seat(body) {
        Ok(input) => input,
        Err(error) => return common::validation(error),
    };
    let session = match common::required_session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let request = CommetSeatMutation {
        customer_id: session.user.id.to_string(),
        feature_code: input.feature_code,
        count: input.count,
    };
    match operation(plugin.options().client.clone(), request).await {
        Ok(value) => support::json(value),
        Err(error) => common::provider_error(error, failure),
    }
}

async fn set_all(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(plugin): Extension<CommetPlugin>,
    headers: HeaderMap,
    CommetBody(body): CommetBody,
) -> Response {
    let input = match input::set_all(body) {
        Ok(input) => input,
        Err(error) => return common::validation(error),
    };
    let session = match common::required_session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    match plugin
        .options()
        .client
        .set_all_seats(CommetSeatSetAll {
            customer_id: session.user.id.to_string(),
            seats: input.seats,
        })
        .await
    {
        Ok(value) => projection::json_field(value, "data"),
        Err(error) => common::provider_error(error, "Failed to set all seats"),
    }
}
