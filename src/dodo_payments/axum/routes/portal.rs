use super::super::{input, support};
use crate::{AxumPluginRoute, dodo_payments::DodoPaymentsPlugin};
use axum::{
    Extension, Json,
    extract::RawQuery,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{MethodRouter, get},
};
use serde_json::json;
use std::sync::Arc;

pub(super) fn routes(layer: &impl Fn(MethodRouter) -> MethodRouter) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new("/dodopayments/customer/portal", layer(get(customer_portal))),
        AxumPluginRoute::new(
            "/dodopayments/customer/subscriptions/list",
            layer(get(subscriptions)),
        ),
        AxumPluginRoute::new("/dodopayments/customer/payments/list", layer(get(payments))),
    ]
}

async fn customer_portal(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(plugin): Extension<DodoPaymentsPlugin>,
    headers: HeaderMap,
) -> Response {
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
            .create_customer_portal(&customer_id)
            .await
            .map_err(support::CustomerResolutionError::from)
    }
    .await;
    match result {
        Ok(portal) => Json(json!({"url": portal.link, "redirect": true})).into_response(),
        Err(error) => provider_failure(
            error,
            "Customer portal creation failed",
            "DodoPayments customer portal creation failed",
        ),
    }
}

async fn subscriptions(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(plugin): Extension<DodoPaymentsPlugin>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    let query = match input::parse_subscription_query(raw.as_deref()) {
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
            .list_subscriptions(query.into_provider(customer_id))
            .await
            .map_err(support::CustomerResolutionError::from)
    }
    .await;
    match result {
        Ok(page) => Json(json!({"items": page.items})).into_response(),
        Err(error) => provider_failure(
            error,
            "DodoPayments subscriptions list failed",
            "DodoPayments subscriptions list failed",
        ),
    }
}

async fn payments(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(plugin): Extension<DodoPaymentsPlugin>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    let query = match input::parse_payment_query(raw.as_deref()) {
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
            .list_payments(query.into_provider(customer_id))
            .await
            .map_err(support::CustomerResolutionError::from)
    }
    .await;
    match result {
        Ok(page) => Json(json!({"items": page.items})).into_response(),
        Err(error) => provider_failure(
            error,
            "Orders list failed",
            "DodoPayments orders list failed",
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
