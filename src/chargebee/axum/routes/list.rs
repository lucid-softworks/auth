#![allow(clippy::result_large_err)] // Axum responses are the deliberate error channel.

use super::super::{ChargebeeRouteState, input, support};
use crate::chargebee::{ChargebeeItemType, ChargebeeReferenceAction};
use axum::{
    Extension,
    extract::{Query, RawQuery},
    http::HeaderMap,
    response::Response,
    routing::{MethodRouter, get},
};
use serde_json::Value;
use std::sync::Arc;

pub(super) fn route() -> MethodRouter {
    get(handle)
}

async fn handle(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(state): Extension<ChargebeeRouteState>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    Query(query): Query<input::ListQuery>,
) -> Response {
    let session = match support::session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let customer_type = query.customer_type.unwrap_or_default();
    let context =
        support::callback_context("GET", "/subscription/list", raw_query.as_deref(), &headers);
    if let Err(response) = support::authorize_reference(
        &state,
        &session,
        query.reference_id.as_deref(),
        customer_type,
        ChargebeeReferenceAction::ListSubscription,
        &context,
    )
    .await
    {
        return response;
    }
    let reference_id = match support::resolve_reference(
        &state,
        &session,
        query.reference_id.as_deref(),
        customer_type,
    ) {
        Ok(reference_id) => reference_id,
        Err(response) => return response,
    };
    match execute(&state, &reference_id).await {
        Ok(value) => support::success(value),
        Err(response) => response,
    }
}

async fn execute(state: &ChargebeeRouteState, reference_id: &str) -> Result<Value, Response> {
    let subscriptions = state
        .store
        .list_subscriptions_by_reference(reference_id)
        .await
        .map_err(support::internal_error)?;
    if subscriptions.is_empty() {
        return Ok(Value::Array(Vec::new()));
    }
    let plans = state
        .options
        .plans()
        .await
        .map_err(support::internal_error)?;
    let mut listed = Vec::new();
    for subscription in subscriptions
        .into_iter()
        .filter(crate::chargebee::ChargebeeSubscription::is_active)
    {
        let items = state
            .store
            .list_subscription_items(subscription.id)
            .await
            .map_err(support::internal_error)?;
        let primary = items
            .iter()
            .find(|item| item.item_type == ChargebeeItemType::Plan)
            .or_else(|| items.first());
        let plan = primary.and_then(|primary| {
            plans
                .iter()
                .find(|plan| plan.item_price_id == primary.item_price_id)
        });
        let mut value = serde_json::to_value(subscription)
            .expect("Chargebee subscription serialization cannot fail");
        if let Some(object) = value.as_object_mut() {
            if let Some(limits) = plan.and_then(|plan| plan.limits.clone()) {
                object.insert("limits".into(), limits);
            }
            if let Some(primary) = primary {
                object.insert(
                    "itemPriceId".into(),
                    Value::String(primary.item_price_id.clone()),
                );
            }
        }
        listed.push(value);
    }
    Ok(Value::Array(listed))
}
