#![allow(clippy::result_large_err)] // Axum responses are the deliberate error channel.

use super::super::{ChargebeeRouteState, input, support};
use crate::chargebee::{
    ChargebeeReferenceAction, ChargebeeSubscription, ChargebeeSubscriptionPatch,
    ChargebeeSubscriptionStatus,
};
use axum::{
    Extension,
    http::HeaderMap,
    response::Response,
    routing::{MethodRouter, post},
};
use serde_json::Value;
use std::sync::Arc;

mod checkout;

pub(super) fn route() -> MethodRouter {
    post(handle)
}

async fn handle(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(state): Extension<ChargebeeRouteState>,
    headers: HeaderMap,
    crate::axum::body::BetterAuthBody(body): crate::axum::body::BetterAuthBody<Value>,
) -> Response {
    let input = match input::create(body) {
        Ok(input) => input,
        Err(error) => return support::validation_error(error.message()),
    };
    let session = match support::session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let context = support::callback_context("POST", "/subscription/create", None, &headers);
    if let Err(response) = support::authorize_reference(
        &state,
        &session,
        input.reference_id.as_deref(),
        input.customer_type,
        ChargebeeReferenceAction::CreateSubscription,
        &context,
    )
    .await
    {
        return response;
    }
    for value in [&input.success_url, &input.cancel_url] {
        if let Err(response) = support::validate_origin(&service, &headers, value) {
            return response;
        }
    }
    match execute(&service, &state, &session, &headers, &input, &context).await {
        Ok(value) => support::success(value),
        Err(response) => response,
    }
}

async fn execute(
    service: &crate::AuthService,
    state: &ChargebeeRouteState,
    session: &crate::SessionWithUser,
    headers: &HeaderMap,
    input: &input::CreateInput,
    context: &crate::chargebee::ChargebeeCallbackContext,
) -> Result<Value, Response> {
    let options = support::require_subscription(state)?;
    validate_request(options, session, input)?;
    let plan = matched_plan(options, &input.item_price_ids).await?;
    let (reference_id, customer_id) =
        resolve_customer(service, state, session, input, context).await?;
    let (subscription, existing, quantity) =
        local_subscription(state, &reference_id, &customer_id, input.seats).await?;
    let user = support::user_snapshot(session);
    let session_snapshot = support::session_snapshot(session);
    let custom = match options.get_hosted_page_params.as_ref() {
        Some(provider) => Some(
            provider
                .params(
                    &user,
                    &session_snapshot,
                    plan.as_ref(),
                    &subscription,
                    context,
                )
                .await
                .map_err(support::internal_error)?,
        ),
        None => None,
    };
    update_pending_metadata(state, &customer_id, &subscription, &reference_id, &user.id).await;
    let trial_end = checkout::trial_end(
        input,
        options.prevent_duplicate_trials,
        plan.as_ref(),
        &existing,
    );
    let mut request = checkout::request(
        service,
        headers,
        input,
        &customer_id,
        &subscription,
        quantity,
        trial_end,
    );
    if let Some(custom) = custom {
        super::super::super::customer::merge_object_spread(&mut request, custom);
    }
    let page = state
        .options
        .client
        .checkout_new_for_items(Value::Object(request))
        .await
        .map_err(support::provider_error)?;
    Ok(serde_json::json!({
        "url": page.url.unwrap_or_default(),
        "id": page.id.unwrap_or_default(),
        "redirect": !input.disable_redirect,
    }))
}

fn validate_request(
    options: &crate::chargebee::ChargebeeSubscriptionOptions,
    session: &crate::SessionWithUser,
    input: &input::CreateInput,
) -> Result<(), Response> {
    if options.require_email_verification && !session.user.email_verified {
        return Err(support::error(
            crate::chargebee::ChargebeeErrorCode::EmailVerificationRequired,
            axum::http::StatusCode::BAD_REQUEST,
        ));
    }
    validate_item_prices(&input.item_price_ids)
}

pub(super) fn validate_item_prices(item_price_ids: &[String]) -> Result<(), Response> {
    let Some(primary) = item_price_ids.first() else {
        return Err(support::literal_error(
            axum::http::StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "At least one item price ID is required",
        ));
    };
    if primary.is_empty() {
        return Err(support::literal_error(
            axum::http::StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "Invalid item price ID",
        ));
    }
    Ok(())
}

pub(super) async fn matched_plan(
    options: &crate::chargebee::ChargebeeSubscriptionOptions,
    item_price_ids: &[String],
) -> Result<Option<crate::chargebee::ChargebeePlan>, Response> {
    let plans = options
        .plans
        .plans()
        .await
        .map_err(support::internal_error)?;
    Ok(plans
        .into_iter()
        .find(|plan| plan.item_price_id == item_price_ids[0]))
}

async fn resolve_customer(
    service: &crate::AuthService,
    state: &ChargebeeRouteState,
    session: &crate::SessionWithUser,
    input: &input::CreateInput,
    context: &crate::chargebee::ChargebeeCallbackContext,
) -> Result<(String, String), Response> {
    let reference_id = support::resolve_reference(
        state,
        session,
        input.reference_id.as_deref(),
        input.customer_type,
    )?;
    let customer_id = support::customer_id(support::CustomerRequest {
        service,
        state,
        session,
        customer_type: input.customer_type,
        reference_id: &reference_id,
        metadata: input.metadata.as_ref(),
        existing_customer_id: None,
        context,
    })
    .await?;
    Ok((reference_id, customer_id))
}

async fn local_subscription(
    state: &ChargebeeRouteState,
    reference_id: &str,
    customer_id: &str,
    seats: Option<f64>,
) -> Result<(ChargebeeSubscription, Vec<ChargebeeSubscription>, f64), Response> {
    let existing = state
        .store
        .list_subscriptions_by_reference(reference_id)
        .await
        .map_err(support::internal_error)?;
    if existing.iter().any(ChargebeeSubscription::is_active) {
        return Err(support::error(
            crate::chargebee::ChargebeeErrorCode::AlreadySubscribed,
            axum::http::StatusCode::BAD_REQUEST,
        ));
    }
    let quantity = support::javascript_quantity(seats);
    let subscription =
        reuse_or_create_future(state, reference_id, customer_id, quantity, &existing).await?;
    Ok((subscription, existing, quantity))
}

async fn reuse_or_create_future(
    state: &ChargebeeRouteState,
    reference_id: &str,
    customer_id: &str,
    quantity: f64,
    existing: &[ChargebeeSubscription],
) -> Result<ChargebeeSubscription, Response> {
    if let Some(future) = existing
        .iter()
        .find(|subscription| subscription.status == ChargebeeSubscriptionStatus::Future)
    {
        return state
            .store
            .update_subscription(
                future.id,
                ChargebeeSubscriptionPatch {
                    seats: Some(Some(quantity)),
                    ..ChargebeeSubscriptionPatch::default()
                },
            )
            .await
            .map_err(support::internal_error)
            .map(|updated| updated.unwrap_or_else(|| future.clone()));
    }
    let mut subscription = ChargebeeSubscription::future(reference_id);
    subscription.chargebee_customer_id = Some(customer_id.to_owned());
    subscription.seats = Some(quantity);
    state
        .store
        .create_subscription(subscription)
        .await
        .map_err(support::internal_error)
}

pub(super) async fn update_pending_metadata(
    state: &ChargebeeRouteState,
    customer_id: &str,
    subscription: &ChargebeeSubscription,
    reference_id: &str,
    user_id: &str,
) {
    let result = state
        .options
        .client
        .update_customer(
            customer_id,
            serde_json::json!({
                "meta_data": {
                    "pendingSubscriptionId": subscription.id.to_string(),
                    "pendingReferenceId": reference_id,
                    "userId": user_id,
                }
            }),
        )
        .await;
    if let Err(error) = result {
        tracing::warn!(%error, "Failed to update customer metadata");
    }
}
