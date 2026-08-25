use super::super::{CreemRouteState, input::CheckoutInput, support};
use crate::creem::service::{
    CreemCheckoutHeaders, CreemCheckoutInput, CreemCheckoutSession, prepare_checkout,
};
use axum::{
    Extension,
    http::{HeaderMap, header::HOST},
    response::Response,
};
use serde_json::{Map, Value};
use std::sync::Arc;

pub(super) async fn create(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(state): Extension<CreemRouteState>,
    headers: HeaderMap,
    crate::axum::body::BetterAuthBody(body): crate::axum::body::BetterAuthBody<Value>,
) -> Response {
    let input = match CheckoutInput::parse(body) {
        Ok(input) => input,
        Err(message) => return support::validation_error(message),
    };
    if state.options.api_key.is_empty() {
        return support::error(support::API_KEY_ERROR);
    }
    let session = support::session(&service, &headers).await;
    let checkout_session = session.as_ref().map(|session| CreemCheckoutSession {
        user_id: session.user.id.to_string(),
        email: session.user.email.clone(),
    });
    let custom_fields = input.selected_custom_fields();
    let request = prepare_checkout(
        CreemCheckoutInput {
            product_id: input.product_id,
            request_id: input.request_id,
            units: input.units,
            discount_code: input.discount_code,
            customer_email: input.customer.and_then(|customer| customer.email),
            custom_fields,
            custom_field: None,
            success_url: input.success_url,
            metadata: input.metadata,
        },
        checkout_session.as_ref(),
        state.options.default_success_url.as_deref(),
        &checkout_headers(&headers),
        state
            .options
            .persist_subscriptions
            .then_some(state.store.as_ref()),
    )
    .await;
    let request = match request {
        Ok(request) => request,
        Err(error) => {
            tracing::error!(message = %error, "[creem] Failed to create checkout");
            return support::error("Failed to create checkout");
        }
    };
    match state.transport.create_checkout(request).await {
        Ok(checkout) => {
            let mut response = Map::from_iter([("redirect".into(), Value::Bool(true))]);
            if let Some(url) = checkout.checkout_url {
                response.insert("url".into(), Value::String(url));
            }
            support::success(Value::Object(response))
        }
        Err(error) => {
            tracing::error!(message = %error, "[creem] Failed to create checkout");
            support::error("Failed to create checkout")
        }
    }
}

pub(super) async fn portal(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(state): Extension<CreemRouteState>,
    headers: HeaderMap,
    crate::axum::body::OptionalBetterAuthBody(body): crate::axum::body::OptionalBetterAuthBody<
        Value,
    >,
) -> Response {
    let input: super::super::input::PortalInput = match support::parse(body) {
        Ok(input) => input,
        Err(response) => return *response,
    };
    if state.options.api_key.is_empty() {
        return support::error(support::API_KEY_ERROR);
    }
    let Some(session) = support::session(&service, &headers).await else {
        return support::error("User must be logged in");
    };
    let Some(stored_customer_id) = support::user_string(&session, "creemCustomerId") else {
        return support::error("User must have a Creem customer ID");
    };
    let customer_id = support::truthy(input.customer_id.as_deref()).unwrap_or(stored_customer_id);
    match state
        .transport
        .create_portal(crate::creem::CreemPortalRequest {
            customer_id: customer_id.to_owned(),
        })
        .await
    {
        Ok(portal) => support::success(serde_json::json!({
            "url": portal.customer_portal_link,
            "redirect": true
        })),
        Err(error) => {
            tracing::error!(message = %error, "[creem] Failed to create portal");
            support::error("Failed to create portal")
        }
    }
}

fn checkout_headers(headers: &HeaderMap) -> CreemCheckoutHeaders {
    CreemCheckoutHeaders {
        host: header(headers, HOST.as_str()),
        forwarded_host: header(headers, "x-forwarded-host"),
        forwarded_proto: header(headers, "x-forwarded-proto"),
        forwarded_protocol: header(headers, "x-forwarded-protocol"),
    }
}

fn header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}
