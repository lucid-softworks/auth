use super::super::{PolarRouteState, input, support};
use crate::{
    AxumPluginRoute,
    polar::{PolarCustomerSessionCreate, PolarEventIngest, PolarEventsIngest},
};
use axum::{
    Extension, Json,
    extract::RawQuery,
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::Value;

pub(super) fn routes(state: PolarRouteState) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new(
            "/usage/meters/list",
            get(meters).layer(Extension(state.clone())),
        ),
        AxumPluginRoute::new("/usage/ingest", post(ingest).layer(Extension(state))),
    ]
}

async fn meters(
    Extension(service): Extension<std::sync::Arc<crate::AuthService>>,
    Extension(state): Extension<PolarRouteState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    let query = match input::page_query(raw.as_deref()) {
        Ok(query) => query,
        Err(error) => return support::bad_input(error),
    };
    let session = match required_session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let customer_session = match state
        .client
        .create_customer_session(PolarCustomerSessionCreate {
            external_customer_id: session.user.id.to_string(),
            return_url: None,
        })
        .await
    {
        Ok(session) => session,
        Err(error) => return provider_failure(error, "Meters list failed"),
    };
    match state
        .client
        .list_meters(&customer_session.token, query)
        .await
    {
        Ok(value) => Json(value).into_response(),
        Err(error) => provider_failure(error, "Meters list failed"),
    }
}

async fn ingest(
    Extension(service): Extension<std::sync::Arc<crate::AuthService>>,
    Extension(state): Extension<PolarRouteState>,
    headers: HeaderMap,
    crate::axum::body::BetterAuthBody(body): crate::axum::body::BetterAuthBody<Value>,
) -> Response {
    let input = match input::IngestInput::parse(body) {
        Ok(input) => input,
        Err(error) => return support::bad_input(error),
    };
    let session = match required_session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    match state
        .client
        .ingest_events(PolarEventsIngest {
            events: vec![PolarEventIngest {
                name: input.event,
                metadata: input.metadata,
                external_customer_id: session.user.id.to_string(),
            }],
        })
        .await
    {
        Ok(value) => Json(value).into_response(),
        Err(error) => provider_failure(error, "Ingestion failed"),
    }
}

async fn required_session(
    service: &crate::AuthService,
    headers: &HeaderMap,
) -> Result<crate::SessionWithUser, Box<Response>> {
    support::optional_session(service, headers)
        .await
        .ok_or_else(|| Box::new(support::bad_request("User not found")))
}

fn provider_failure(error: crate::polar::PolarProviderError, message: &'static str) -> Response {
    tracing::error!(message = %error, "Polar provider request failed");
    support::internal(message)
}
