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
use serde_json::{Map, Value};
use std::sync::Arc;

mod selection;

struct UpdateExecution<'a> {
    service: &'a crate::AuthService,
    state: &'a ChargebeeRouteState,
    session: &'a crate::SessionWithUser,
    headers: &'a HeaderMap,
    input: &'a input::UpdateInput,
    context: &'a crate::chargebee::ChargebeeCallbackContext,
    reference_id: &'a str,
    user: &'a crate::chargebee::ChargebeeUserSnapshot,
}

pub(super) fn route() -> MethodRouter {
    post(handle)
}

async fn handle(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(state): Extension<ChargebeeRouteState>,
    headers: HeaderMap,
    crate::axum::body::BetterAuthBody(body): crate::axum::body::BetterAuthBody<Value>,
) -> Response {
    let input = match input::update(body) {
        Ok(input) => input,
        Err(error) => return support::validation_error(error.message()),
    };
    let session = match support::session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let context = support::callback_context("POST", "/subscription/update", None, &headers);
    if let Err(response) = support::authorize_reference(
        &state,
        &session,
        input.reference_id.as_deref(),
        input.customer_type,
        ChargebeeReferenceAction::UpgradeSubscription,
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
    input: &input::UpdateInput,
    context: &crate::chargebee::ChargebeeCallbackContext,
) -> Result<Value, Response> {
    let options = support::require_subscription(state)?;
    if options.require_email_verification && !session.user.email_verified {
        return Err(support::error(
            crate::chargebee::ChargebeeErrorCode::EmailVerificationRequired,
            StatusCode::BAD_REQUEST,
        ));
    }
    super::create::validate_item_prices(&input.item_price_ids)?;
    let plan = super::create::matched_plan(options, &input.item_price_ids).await?;
    let reference_id = support::resolve_reference(
        state,
        session,
        input.reference_id.as_deref(),
        input.customer_type,
    )?;
    let selected =
        owned_subscription(state, input.subscription_id.as_deref(), &reference_id).await?;
    let user = support::user_snapshot(session);
    let execution = UpdateExecution {
        service,
        state,
        session,
        headers,
        input,
        context,
        reference_id: &reference_id,
        user: &user,
    };
    let customer_id = resolve_customer(&execution, selected.as_ref()).await?;
    let active_local = active_local(state, &reference_id, selected.as_ref()).await?;
    let active_provider = active_provider(
        state,
        &customer_id,
        input.subscription_id.as_deref(),
        selected.as_ref(),
        active_local.as_ref(),
    )
    .await?;
    let quantity = support::javascript_quantity(input.seats);
    if selection::already_subscribed(
        &input.item_price_ids,
        quantity,
        active_local.as_ref(),
        &active_provider,
    ) {
        return Err(support::error(
            crate::chargebee::ChargebeeErrorCode::AlreadySubscribed,
            StatusCode::BAD_REQUEST,
        ));
    }
    let local = synchronize_local(state, &active_provider, active_local, selected).await?;
    complete_checkout(
        &execution,
        plan.as_ref(),
        &customer_id,
        &active_provider,
        &local,
        quantity,
    )
    .await
}

async fn complete_checkout(
    execution: &UpdateExecution<'_>,
    plan: Option<&crate::chargebee::ChargebeePlan>,
    customer_id: &str,
    active_provider: &ChargebeeProviderSubscription,
    local: &ChargebeeSubscription,
    quantity: f64,
) -> Result<Value, Response> {
    let options = support::require_subscription(execution.state)?;
    let session_snapshot = support::session_snapshot(execution.session);
    let custom = match options.get_hosted_page_params.as_ref() {
        Some(provider) => Some(
            provider
                .params(
                    execution.user,
                    &session_snapshot,
                    plan,
                    local,
                    execution.context,
                )
                .await
                .map_err(support::internal_error)?,
        ),
        None => None,
    };
    super::create::update_pending_metadata(
        execution.state,
        customer_id,
        local,
        execution.reference_id,
        &execution.user.id,
    )
    .await;
    let mut request = checkout_request(
        execution.service,
        execution.headers,
        execution.input,
        active_provider,
        local,
        quantity,
    );
    if let Some(custom) = custom {
        super::super::super::customer::merge_object_spread(&mut request, custom);
    }
    let page = execution
        .state
        .options
        .client
        .checkout_existing_for_items(Value::Object(request))
        .await
        .map_err(support::provider_error)?;
    Ok(serde_json::json!({
        "url": page.url.unwrap_or_default(),
        "id": page.id.unwrap_or_default(),
        "redirect": !execution.input.disable_redirect,
    }))
}

async fn owned_subscription(
    state: &ChargebeeRouteState,
    provider_id: Option<&str>,
    reference_id: &str,
) -> Result<Option<ChargebeeSubscription>, Response> {
    let selected = match provider_id {
        Some(id) => state
            .store
            .find_subscription_by_chargebee_id(id)
            .await
            .map_err(support::internal_error)?,
        None => None,
    };
    if provider_id.is_some()
        && selected
            .as_ref()
            .is_none_or(|subscription| subscription.reference_id != reference_id)
    {
        Err(subscription_not_found())
    } else {
        Ok(selected)
    }
}

async fn resolve_customer(
    execution: &UpdateExecution<'_>,
    selected: Option<&ChargebeeSubscription>,
) -> Result<String, Response> {
    let existing = selected
        .and_then(|subscription| subscription.chargebee_customer_id.as_deref())
        .or_else(|| {
            (execution.input.customer_type == input::CustomerType::User)
                .then_some(execution.user.chargebee_customer_id.as_deref())
                .flatten()
        });
    support::customer_id(support::CustomerRequest {
        service: execution.service,
        state: execution.state,
        session: execution.session,
        customer_type: execution.input.customer_type,
        reference_id: execution.reference_id,
        metadata: execution.input.metadata.as_ref(),
        existing_customer_id: existing,
        context: execution.context,
    })
    .await
}

async fn active_local(
    state: &ChargebeeRouteState,
    reference_id: &str,
    selected: Option<&ChargebeeSubscription>,
) -> Result<Option<ChargebeeSubscription>, Response> {
    let subscriptions = match selected {
        Some(subscription) => vec![subscription.clone()],
        None => state
            .store
            .list_subscriptions_by_reference(reference_id)
            .await
            .map_err(support::internal_error)?,
    };
    Ok(subscriptions
        .into_iter()
        .find(ChargebeeSubscription::is_active))
}

async fn active_provider(
    state: &ChargebeeRouteState,
    customer_id: &str,
    requested_id: Option<&str>,
    selected: Option<&ChargebeeSubscription>,
    active_local: Option<&ChargebeeSubscription>,
) -> Result<ChargebeeProviderSubscription, Response> {
    let subscriptions = state
        .options
        .client
        .list_subscriptions(ChargebeeSubscriptionListRequest {
            customer_id: customer_id.to_owned(),
            limit: Some(100),
        })
        .await
        .map_err(support::internal_error)?;
    subscriptions
        .into_iter()
        .filter(selection::provider_is_active)
        .find(|provider| provider_matches(provider, requested_id, selected, active_local))
        .ok_or_else(subscription_not_found)
}

fn provider_matches(
    provider: &ChargebeeProviderSubscription,
    requested_id: Option<&str>,
    selected: Option<&ChargebeeSubscription>,
    active_local: Option<&ChargebeeSubscription>,
) -> bool {
    let selected_id = selected.and_then(|value| value.chargebee_subscription_id.as_deref());
    if selected_id.is_some() || requested_id.is_some() {
        return selected_id.is_some_and(|id| provider.id == id)
            || requested_id.is_some_and(|id| provider.id == id);
    }
    active_local
        .and_then(|value| value.chargebee_subscription_id.as_deref())
        .is_some_and(|id| provider.id == id)
}

async fn synchronize_local(
    state: &ChargebeeRouteState,
    provider: &ChargebeeProviderSubscription,
    active_local: Option<ChargebeeSubscription>,
    selected: Option<ChargebeeSubscription>,
) -> Result<ChargebeeSubscription, Response> {
    let mut local = state
        .store
        .find_subscription_by_chargebee_id(&provider.id)
        .await
        .map_err(support::internal_error)?;
    if local.is_none()
        && let Some(active) = &active_local
    {
        state
            .store
            .update_subscription(
                active.id,
                ChargebeeSubscriptionPatch {
                    chargebee_subscription_id: Some(Some(provider.id.clone())),
                    updated_at: Some(Utc::now()),
                    ..ChargebeeSubscriptionPatch::default()
                },
            )
            .await
            .map_err(support::internal_error)?;
        local = Some(active.clone());
    }
    local.or(active_local).or(selected).ok_or_else(|| {
        support::error(
            crate::chargebee::ChargebeeErrorCode::SubscriptionNotFound,
            StatusCode::NOT_FOUND,
        )
    })
}

fn checkout_request(
    service: &crate::AuthService,
    headers: &HeaderMap,
    input: &input::UpdateInput,
    provider: &ChargebeeProviderSubscription,
    local: &ChargebeeSubscription,
    quantity: f64,
) -> Map<String, Value> {
    let items = input
        .item_price_ids
        .iter()
        .map(|id| {
            serde_json::json!({
                "item_price_id": id,
                "quantity": support::json_number(quantity),
            })
        })
        .collect::<Vec<_>>();
    let callback = format!(
        "/subscription/success?callbackURL={}&subscriptionId={}",
        support::encode_component(&input.success_url),
        support::encode_component(&local.id.to_string()),
    );
    Map::from_iter([
        (
            "subscription".into(),
            serde_json::json!({"id": provider.id}),
        ),
        ("subscription_items".into(), Value::Array(items)),
        (
            "redirect_url".into(),
            Value::String(support::absolute_url(service, headers, &callback)),
        ),
        (
            "cancel_url".into(),
            Value::String(support::absolute_url(service, headers, &input.cancel_url)),
        ),
    ])
}

fn subscription_not_found() -> Response {
    support::error(
        crate::chargebee::ChargebeeErrorCode::SubscriptionNotFound,
        StatusCode::BAD_REQUEST,
    )
}
