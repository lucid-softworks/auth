use super::support;
use crate::{
    AuthorizeReferenceAction, AxumPluginRoute, BillingPortalInput, CustomerType, StripeErrorCode,
    StripePlugin, UrlRedirectResponse,
};
use axum::{
    Extension, Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use serde_json::json;

pub(super) fn route(plugin: StripePlugin) -> AxumPluginRoute {
    AxumPluginRoute::new(
        "/subscription/billing-portal",
        post(handle).layer(Extension(plugin)),
    )
}

async fn handle(
    Extension(service): Extension<std::sync::Arc<crate::AuthService>>,
    Extension(plugin): Extension<StripePlugin>,
    headers: HeaderMap,
    crate::axum::body::BetterAuthBody(input): crate::axum::body::BetterAuthBody<BillingPortalInput>,
) -> Response {
    let session = match support::session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let context = support::callback_context("POST", "/subscription/billing-portal", None, &headers);
    let customer_type = input.effective_customer_type();
    let reference_id = match support::authorize_reference(
        &plugin,
        &session,
        input.reference_id.as_deref(),
        customer_type,
        AuthorizeReferenceAction::BillingPortal,
        &context,
    )
    .await
    {
        Ok(reference_id) => reference_id,
        Err(response) => return response,
    };
    let direct = match customer_type {
        CustomerType::Organization => uuid::Uuid::parse_str(&reference_id)
            .ok()
            .map(|id| plugin.store.organization_customer_id(id)),
        CustomerType::User => Some(plugin.store.user_customer_id(session.user.id)),
    };
    let mut customer_id = match direct {
        Some(future) => match future.await {
            Ok(customer_id) => customer_id,
            Err(error) => return support::store_error(error),
        },
        None => None,
    };
    if customer_id.is_none() {
        customer_id = match plugin.store.list_subscriptions(&reference_id).await {
            Ok(subscriptions) => subscriptions
                .into_iter()
                .find(crate::Subscription::is_active_or_trialing)
                .and_then(|subscription| subscription.stripe_customer_id),
            Err(error) => return support::store_error(error),
        };
    }
    let Some(customer_id) = customer_id else {
        return support::error(StripeErrorCode::CustomerNotFound, StatusCode::NOT_FOUND);
    };
    let mut params = json!({
        "customer": customer_id,
        "return_url": support::absolute_url(&service, &input.return_url),
    });
    if let Some(locale) = input.locale {
        params["locale"] = serde_json::Value::String(locale);
    }
    match plugin
        .options
        .client
        .create_billing_portal_session(params)
        .await
    {
        Ok(portal) => Json(UrlRedirectResponse {
            url: portal.url,
            redirect: !input.disable_redirect,
        })
        .into_response(),
        Err(error) => {
            tracing::error!(message = %error, "Error creating billing portal session");
            support::error(
                StripeErrorCode::UnableToCreateBillingPortal,
                StatusCode::INTERNAL_SERVER_ERROR,
            )
        }
    }
}
