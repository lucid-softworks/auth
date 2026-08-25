use super::super::{input, support};
use crate::{
    AxumPluginRoute,
    dodo_payments::{DodoPaymentsPlugin, service::DodoCheckoutError},
};
use axum::{
    Extension, Json,
    http::{HeaderMap, StatusCode, Uri},
    response::{IntoResponse, Response},
    routing::{MethodRouter, post},
};
use serde_json::{Value, json};
use std::sync::Arc;

pub(super) fn routes(layer: &impl Fn(MethodRouter) -> MethodRouter) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new("/dodopayments/checkout", layer(post(legacy))),
        AxumPluginRoute::new(
            "/dodopayments/checkout-session",
            layer(post(session_checkout)),
        ),
    ]
}

async fn legacy(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(plugin): Extension<DodoPaymentsPlugin>,
    headers: HeaderMap,
    uri: Uri,
    crate::axum::body::BetterAuthBody(body): crate::axum::body::BetterAuthBody<Value>,
) -> Response {
    let input = match input::parse_legacy_checkout(body) {
        Ok(input) => input,
        Err(error) => return support::validation_error(error.message()),
    };
    let checkout = plugin
        .options()
        .checkout()
        .expect("checkout routes require checkout options");
    let session = support::optional_session(&service, &headers).await;
    let product_id =
        match crate::dodo_payments::service::resolve_product(checkout, input.slug()).await {
            Ok(product_id) => product_id,
            Err(DodoCheckoutError::ProductNotFound) => {
                return support::bad_request("Product not found");
            }
            Err(error) => {
                tracing::error!(message = %error, "DodoPayments product resolution failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
    if checkout.authenticated_users_only && session.is_none() {
        return support::unauthorized("You must be logged in to checkout");
    }
    let reference_id = input.reference_id().map(str::to_owned);
    let success_url = match support::configured_success_url(
        &service,
        &headers,
        &uri,
        checkout.success_url.as_deref(),
    ) {
        Ok(url) => url,
        Err(error) => return checkout_failure(error, false),
    };
    match crate::dodo_payments::service::create_legacy_checkout(
        &*plugin.options().client,
        input.into_body(),
        product_id,
        reference_id,
        session.as_ref(),
        success_url,
    )
    .await
    {
        Ok(url) => Json(json!({"url": url, "redirect": true})).into_response(),
        Err(error) => checkout_failure(error, false),
    }
}

async fn session_checkout(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(plugin): Extension<DodoPaymentsPlugin>,
    headers: HeaderMap,
    uri: Uri,
    crate::axum::body::BetterAuthBody(body): crate::axum::body::BetterAuthBody<Value>,
) -> Response {
    let input = match input::parse_checkout_session(body) {
        Ok(input) => input,
        Err(error) => return support::validation_error(error.message()),
    };
    let checkout = plugin
        .options()
        .checkout()
        .expect("checkout routes require checkout options");
    let session = support::optional_session(&service, &headers).await;
    let product_id =
        match crate::dodo_payments::service::resolve_product(checkout, input.slug()).await {
            Ok(product_id) => product_id,
            Err(DodoCheckoutError::ProductNotFound) => {
                return support::bad_request("Product not found");
            }
            Err(error) => {
                tracing::error!(message = %error, "DodoPayments product resolution failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };
    if checkout.authenticated_users_only && session.is_none() {
        return support::unauthorized("You must be logged in to checkout");
    }
    if product_id.is_none() && input.product_cart().is_none_or(Vec::is_empty) {
        return support::bad_request("Neither product_cart nor slug was provided");
    }
    let reference_id = input.reference_id().map(str::to_owned);
    let success_url = match support::configured_success_url(
        &service,
        &headers,
        &uri,
        checkout.success_url.as_deref(),
    ) {
        Ok(url) => url,
        Err(error) => return checkout_failure(error, true),
    };
    match crate::dodo_payments::service::create_checkout_session(
        &*plugin.options().client,
        input.into_body(),
        product_id,
        reference_id,
        session.as_ref(),
        success_url,
    )
    .await
    {
        Ok(url) => Json(json!({"url": url, "redirect": true})).into_response(),
        Err(error) => checkout_failure(error, true),
    }
}

fn checkout_failure(error: impl std::fmt::Display, session: bool) -> Response {
    tracing::error!(message = %error, "DodoPayments checkout creation failed");
    support::error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_SERVER_ERROR",
        if session {
            "Checkout session creation failed"
        } else {
            "Checkout creation failed"
        },
    )
}
