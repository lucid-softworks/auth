#![allow(clippy::result_large_err)] // Axum responses are the deliberate error channel.

use super::support;
use crate::{
    AuthorizeReferenceAction, AxumPluginRoute, RestoreSubscriptionInput, StripeErrorCode,
    StripePlugin, StripeSubscription, Subscription, SubscriptionPatch,
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
        "/subscription/restore",
        post(handle).layer(Extension(plugin)),
    )
}

async fn handle(
    Extension(service): Extension<std::sync::Arc<crate::AuthService>>,
    Extension(plugin): Extension<StripePlugin>,
    headers: HeaderMap,
    crate::axum::body::BetterAuthBody(input): crate::axum::body::BetterAuthBody<
        RestoreSubscriptionInput,
    >,
) -> Response {
    let session = match support::session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let context = support::callback_context("POST", "/subscription/restore", None, &headers);
    let reference_id = match support::authorize_reference(
        &plugin,
        &session,
        input.reference_id.as_deref(),
        input.effective_customer_type(),
        AuthorizeReferenceAction::RestoreSubscription,
        &context,
    )
    .await
    {
        Ok(reference_id) => reference_id,
        Err(response) => return response,
    };
    match restore(&plugin, &input, &reference_id).await {
        Ok(subscription) => Json(subscription).into_response(),
        Err(response) => response,
    }
}

async fn restore(
    plugin: &StripePlugin,
    input: &RestoreSubscriptionInput,
    reference_id: &str,
) -> Result<StripeSubscription, Response> {
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
    if let Some(response) = validate_pending(&subscription) {
        return Err(response);
    }
    let stripe_id = subscription
        .stripe_subscription_id
        .as_deref()
        .ok_or_else(|| {
            support::error(
                StripeErrorCode::SubscriptionNotFound,
                StatusCode::BAD_REQUEST,
            )
        })?;
    match subscription.stripe_schedule_id.as_deref() {
        Some(schedule_id) => release_schedule(plugin, &subscription, stripe_id, schedule_id).await,
        None => clear_cancellation(plugin, &subscription, stripe_id).await,
    }
}

fn validate_pending(subscription: &Subscription) -> Option<Response> {
    if !subscription.is_active_or_trialing() {
        return Some(support::error(
            StripeErrorCode::SubscriptionNotActive,
            StatusCode::BAD_REQUEST,
        ));
    }
    if !subscription.is_pending_cancel() && subscription.stripe_schedule_id.is_none() {
        return Some(support::error(
            StripeErrorCode::SubscriptionNotPendingChange,
            StatusCode::BAD_REQUEST,
        ));
    }
    None
}

async fn release_schedule(
    plugin: &StripePlugin,
    subscription: &Subscription,
    stripe_id: &str,
    schedule_id: &str,
) -> Result<StripeSubscription, Response> {
    let schedule = plugin
        .options
        .client
        .retrieve_subscription_schedule(schedule_id)
        .await
        .map_err(support::provider_error)?;
    if schedule.status == "active" {
        plugin
            .options
            .client
            .release_subscription_schedule(schedule_id)
            .await
            .map_err(support::provider_error)?;
    }
    plugin
        .store
        .update_subscription(
            subscription.id,
            SubscriptionPatch {
                stripe_schedule_id: Some(None),
                updated_at: Some(Utc::now()),
                ..SubscriptionPatch::default()
            },
        )
        .await
        .map_err(support::store_error)?;
    plugin
        .options
        .client
        .retrieve_subscription(stripe_id)
        .await
        .map_err(support::provider_error)
}

async fn clear_cancellation(
    plugin: &StripePlugin,
    subscription: &Subscription,
    stripe_id: &str,
) -> Result<StripeSubscription, Response> {
    let active = match plugin.options.client.retrieve_subscription(stripe_id).await {
        Ok(active) if active.is_active_or_trialing() => active,
        Ok(_) => {
            return Err(support::error(
                StripeErrorCode::SubscriptionNotFound,
                StatusCode::BAD_REQUEST,
            ));
        }
        Err(crate::StripeProviderError {
            code: Some(code), ..
        }) if code == "resource_missing" => {
            return Err(support::error(
                StripeErrorCode::SubscriptionNotFound,
                StatusCode::BAD_REQUEST,
            ));
        }
        Err(error) => return Err(support::provider_error(error)),
    };
    let params = if active.cancel_at.is_some() {
        json!({ "cancel_at": "" })
    } else if active.cancel_at_period_end {
        json!({ "cancel_at_period_end": false })
    } else {
        json!({})
    };
    let restored = plugin
        .options
        .client
        .update_subscription(&active.id, params)
        .await
        .map_err(support::provider_error)?;
    plugin
        .store
        .update_subscription(
            subscription.id,
            SubscriptionPatch {
                cancel_at_period_end: Some(false),
                cancel_at: Some(None),
                canceled_at: Some(None),
                updated_at: Some(Utc::now()),
                ..SubscriptionPatch::default()
            },
        )
        .await
        .map_err(support::store_error)?;
    Ok(restored)
}
