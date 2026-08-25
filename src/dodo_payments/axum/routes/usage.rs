use super::super::{input, support};
use crate::{
    AxumPluginRoute,
    dodo_payments::{DodoPaymentsPlugin, DodoUsageEvent, DodoUsageIngestRequest},
};
use axum::{
    Extension, Json,
    extract::RawQuery,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{MethodRouter, get, post},
};
use serde_json::{Value, json};
use std::sync::Arc;

pub(super) fn routes(layer: &impl Fn(MethodRouter) -> MethodRouter) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new("/dodopayments/usage/ingest", layer(post(ingest))),
        AxumPluginRoute::new("/dodopayments/usage/meters/list", layer(get(meters))),
    ]
}

async fn ingest(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(plugin): Extension<DodoPaymentsPlugin>,
    headers: HeaderMap,
    crate::axum::body::BetterAuthBody(body): crate::axum::body::BetterAuthBody<Value>,
) -> Response {
    let input = match input::parse_usage_ingest(body) {
        Ok(input) => input,
        Err(error) => return support::validation_error(error.message()),
    };
    let session = match support::required_session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = support::verified_user(&session) {
        return *response;
    }
    let result = async {
        let customer_id = support::customer_id(&plugin, &session).await?;
        let metadata = match input.metadata {
            input::DodoNullableMetadata::Absent => None,
            input::DodoNullableMetadata::Null => Some(None),
            input::DodoNullableMetadata::Object(metadata) => Some(Some(metadata)),
        };
        plugin
            .options()
            .client
            .ingest_usage(DodoUsageIngestRequest {
                events: vec![DodoUsageEvent {
                    customer_id,
                    event_id: input.event_id,
                    event_name: input.event_name,
                    metadata,
                    timestamp: input.timestamp,
                }],
            })
            .await
            .map_err(support::CustomerResolutionError::from)
    }
    .await;
    match result {
        Ok(result) => Json(json!({"ingested_count": result.ingested_count})).into_response(),
        Err(error) => provider_failure(
            error,
            "Failed to record the user usage",
            "User usage ingestion error",
        ),
    }
}

async fn meters(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(plugin): Extension<DodoPaymentsPlugin>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    let query = match input::parse_usage_meter_query(raw.as_deref()) {
        Ok(query) => query,
        Err(error) => return support::validation_error(error.message()),
    };
    let session = match support::required_session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if let Err(response) = support::verified_user(&session) {
        return *response;
    }
    let result = async {
        let customer_id = support::customer_id(&plugin, &session).await?;
        plugin
            .options()
            .client
            .list_usage(query.into_provider(customer_id))
            .await
            .map_err(support::CustomerResolutionError::from)
    }
    .await;
    match result {
        Ok(page) => Json(json!({"items": page.items})).into_response(),
        Err(error) => provider_failure(
            error,
            "Failed to fetch the user usage",
            "User usage meter list error",
        ),
    }
}

fn provider_failure(
    error: support::CustomerResolutionError,
    public_message: &'static str,
    log_message: &'static str,
) -> Response {
    tracing::error!(message = %error, %log_message);
    support::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_SERVER_ERROR",
        public_message,
    )
}
