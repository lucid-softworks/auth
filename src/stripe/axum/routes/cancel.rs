#![allow(clippy::result_large_err)] // Axum responses are the deliberate error channel.

use super::support;
use crate::{
    AuthorizeReferenceAction, AxumPluginRoute, CancelSubscriptionInput, StripeErrorCode,
    StripePlugin, StripeSubscription, Subscription, SubscriptionPatch, UrlRedirectResponse,
};
use axum::{
    Extension, Json,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use chrono::Utc;
use serde_json::json;

pub(super) fn route(plugin: StripePlugin) -> AxumPluginRoute {
    AxumPluginRoute::new(
        "/subscription/cancel",
        post(handle).layer(Extension(plugin)),
    )
}

async fn handle(
    Extension(service): Extension<std::sync::Arc<crate::AuthService>>,
    Extension(plugin): Extension<StripePlugin>,
    headers: HeaderMap,
    crate::axum::body::BetterAuthBody(input): crate::axum::body::BetterAuthBody<
        CancelSubscriptionInput,
    >,
) -> Response {
    let session = match support::session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let context = support::callback_context("POST", "/subscription/cancel", None, &headers);
    let reference_id = match support::authorize_reference(
        &plugin,
        &session,
        input.reference_id.as_deref(),
        input.effective_customer_type(),
        AuthorizeReferenceAction::CancelSubscription,
        &context,
    )
    .await
    {
        Ok(reference_id) => reference_id,
        Err(response) => return response,
    };
    match cancel(&service, &plugin, &input, &reference_id).await {
        Ok(result) => Json(result).into_response(),
        Err(response) => response,
    }
}

async fn cancel(
    service: &crate::AuthService,
    plugin: &StripePlugin,
    input: &CancelSubscriptionInput,
    reference_id: &str,
) -> Result<UrlRedirectResponse, Response> {
    let subscription =
        support::selected_subscription(plugin, reference_id, input.subscription_id.as_deref())
            .await?
            .filter(|subscription| subscription.stripe_customer_id.is_some())
            .ok_or_else(|| {
                support::error(
                    StripeErrorCode::SubscriptionNotFound,
                    StatusCode::BAD_REQUEST,
                )
            })?;
    let active = active_subscription(plugin, &subscription).await?;
    let params = json!({
        "customer": subscription.stripe_customer_id,
        "return_url": support::absolute_url(service, &input.return_url),
        "flow_data": {
            "type": "subscription_cancel",
            "subscription_cancel": { "subscription": active.id }
        }
    });
    let portal = match plugin
        .options
        .client
        .create_billing_portal_session(params)
        .await
    {
        Ok(portal) => portal,
        Err(error) => {
            sync_missed_cancellation(plugin, &subscription, &active, &error).await;
            return Err(support::provider_error(error));
        }
    };
    Ok(UrlRedirectResponse {
        url: portal.url,
        redirect: !input.disable_redirect,
    })
}

async fn active_subscription(
    plugin: &StripePlugin,
    subscription: &Subscription,
) -> Result<StripeSubscription, Response> {
    let stripe_id = subscription
        .stripe_subscription_id
        .as_deref()
        .ok_or_else(|| {
            support::error(
                StripeErrorCode::SubscriptionNotFound,
                StatusCode::BAD_REQUEST,
            )
        })?;
    match plugin.options.client.retrieve_subscription(stripe_id).await {
        Ok(subscription) if subscription.is_active_or_trialing() => Ok(subscription),
        Ok(_) => {
            plugin
                .store
                .delete_subscription(subscription.id)
                .await
                .map_err(support::store_error)?;
            Err(support::error(
                StripeErrorCode::SubscriptionNotFound,
                StatusCode::BAD_REQUEST,
            ))
        }
        Err(crate::StripeProviderError {
            code: Some(code), ..
        }) if code == "resource_missing" => {
            plugin
                .store
                .delete_subscription(subscription.id)
                .await
                .map_err(support::store_error)?;
            Err(support::error(
                StripeErrorCode::SubscriptionNotFound,
                StatusCode::BAD_REQUEST,
            ))
        }
        Err(error) => Err(support::provider_error(error)),
    }
}

async fn sync_missed_cancellation(
    plugin: &StripePlugin,
    subscription: &Subscription,
    active: &StripeSubscription,
    error: &crate::StripeProviderError,
) {
    if error.message.contains("already set to be canceled")
        && !subscription.is_pending_cancel()
        && let Ok(stripe) = plugin
            .options
            .client
            .retrieve_subscription(&active.id)
            .await
    {
        let patch = SubscriptionPatch {
            cancel_at_period_end: Some(stripe.cancel_at_period_end),
            cancel_at: Some(timestamp(stripe.cancel_at)),
            canceled_at: Some(timestamp(stripe.canceled_at)),
            ..SubscriptionPatch::default()
        };
        let _ = plugin
            .store
            .update_subscription(subscription.id, patch)
            .await;
    }
}

fn timestamp(value: Option<i64>) -> Option<chrono::DateTime<Utc>> {
    value.and_then(|value| chrono::DateTime::from_timestamp(value, 0))
}
