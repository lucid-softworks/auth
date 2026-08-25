#![allow(clippy::result_large_err)] // Axum responses are the deliberate error channel.

use super::super::{ChargebeeRouteState, input, support};
use crate::chargebee::{
    ChargebeeProviderSubscription, ChargebeeReferenceAction, ChargebeeSubscription,
    ChargebeeSubscriptionListRequest, ChargebeeSubscriptionPatch,
};
use axum::{
    Extension,
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{MethodRouter, post},
};
use chrono::Utc;
use serde_json::Value;
use std::sync::Arc;

pub(super) fn route() -> MethodRouter {
    post(handle)
}

async fn handle(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(state): Extension<ChargebeeRouteState>,
    headers: HeaderMap,
    crate::axum::body::BetterAuthBody(body): crate::axum::body::BetterAuthBody<Value>,
) -> Response {
    let input = match input::cancel(body) {
        Ok(input) => input,
        Err(error) => return support::validation_error(error.message()),
    };
    let session = match support::session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let context = support::callback_context("POST", "/subscription/cancel", None, &headers);
    if let Err(response) = support::authorize_reference(
        &state,
        &session,
        input.reference_id.as_deref(),
        input.customer_type,
        ChargebeeReferenceAction::CancelSubscription,
        &context,
    )
    .await
    {
        return response;
    }
    if let Err(response) = support::validate_origin(&service, &headers, &input.return_url) {
        return response;
    }
    let reference_id = match support::resolve_reference(
        &state,
        &session,
        input.reference_id.as_deref(),
        input.customer_type,
    ) {
        Ok(reference_id) => reference_id,
        Err(response) => return response,
    };
    match execute(&service, &state, &headers, &reference_id, &input).await {
        Ok(value) => support::success(value),
        Err(response) => response,
    }
}

async fn execute(
    service: &crate::AuthService,
    state: &ChargebeeRouteState,
    headers: &HeaderMap,
    reference_id: &str,
    input: &input::CancelInput,
) -> Result<Value, Response> {
    let subscription = selected_subscription(state, reference_id, input.subscription_id.as_deref())
        .await?
        .filter(|subscription| subscription.chargebee_customer_id.is_some())
        .ok_or_else(subscription_not_found)?;
    let customer_id = subscription
        .chargebee_customer_id
        .as_deref()
        .expect("selected subscription has a customer ID");
    let provider = state
        .options
        .client
        .list_subscriptions(ChargebeeSubscriptionListRequest {
            customer_id: customer_id.to_owned(),
            limit: Some(100),
        })
        .await
        .map_err(support::internal_error)?;
    let active = provider
        .into_iter()
        .filter(provider_is_active)
        .collect::<Vec<_>>();
    if active.is_empty() {
        state
            .store
            .delete_subscriptions_by_reference(reference_id)
            .await
            .map_err(support::internal_error)?;
        return Err(subscription_not_found());
    }
    let active = active
        .into_iter()
        .find(|provider| {
            subscription
                .chargebee_subscription_id
                .as_deref()
                .is_some_and(|id| provider.id == id)
        })
        .ok_or_else(subscription_not_found)?;
    let callback = format!(
        "/subscription/cancel/callback?callbackURL={}&subscriptionId={}",
        support::encode_component(&input.return_url),
        support::encode_component(&subscription.id.to_string()),
    );
    let result = state
        .options
        .client
        .create_portal_session(serde_json::json!({
            "customer": {"id": customer_id},
            "redirect_url": support::absolute_url(service, headers, &callback),
        }))
        .await;
    match result {
        Ok(portal) => Ok(serde_json::json!({
            "url": portal.access_url,
            "redirect": !input.disable_redirect,
        })),
        Err(error) => {
            if (error.message.contains("already") || error.message.contains("cancel"))
                && !pending_cancel(&subscription)
            {
                reconcile(state, &subscription, &active).await;
            }
            Err(support::provider_error(error))
        }
    }
}

async fn selected_subscription(
    state: &ChargebeeRouteState,
    reference_id: &str,
    provider_id: Option<&str>,
) -> Result<Option<ChargebeeSubscription>, Response> {
    if let Some(provider_id) = provider_id {
        return state
            .store
            .find_subscription_by_chargebee_id(provider_id)
            .await
            .map(|subscription| {
                subscription.filter(|subscription| subscription.reference_id == reference_id)
            })
            .map_err(support::internal_error);
    }
    state
        .store
        .list_subscriptions_by_reference(reference_id)
        .await
        .map(|subscriptions| {
            subscriptions
                .into_iter()
                .find(ChargebeeSubscription::is_active)
        })
        .map_err(support::internal_error)
}

async fn reconcile(
    state: &ChargebeeRouteState,
    local: &ChargebeeSubscription,
    active: &ChargebeeProviderSubscription,
) {
    let provider = match state.options.client.retrieve_subscription(&active.id).await {
        Ok(provider) => provider,
        Err(error) => {
            tracing::error!(%error, "Error retrieving subscription from Chargebee");
            return;
        }
    };
    let canceled_at = provider
        .cancelled_at
        .filter(|value| *value != 0)
        .and_then(|value| chrono::DateTime::from_timestamp(value, 0))
        .unwrap_or_else(Utc::now);
    if let Err(error) = state
        .store
        .update_subscription(
            local.id,
            ChargebeeSubscriptionPatch {
                canceled_at: Some(Some(canceled_at)),
                ..ChargebeeSubscriptionPatch::default()
            },
        )
        .await
    {
        tracing::error!(%error, "Chargebee persistence failed");
    }
}

pub(super) fn pending_cancel(subscription: &ChargebeeSubscription) -> bool {
    subscription.canceled_at.is_some()
        && subscription
            .period_end
            .is_some_and(|period_end| period_end > Utc::now())
}

fn provider_is_active(subscription: &ChargebeeProviderSubscription) -> bool {
    matches!(
        subscription.status.as_str(),
        "active" | "in_trial" | "non_renewing"
    )
}

fn subscription_not_found() -> Response {
    support::error(
        crate::chargebee::ChargebeeErrorCode::SubscriptionNotFound,
        StatusCode::BAD_REQUEST,
    )
}
