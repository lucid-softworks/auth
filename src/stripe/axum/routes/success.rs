use super::support;
use crate::{AxumPluginRoute, StripePlugin, SubscriptionPatch, SubscriptionSuccessQuery};
use axum::{
    Extension,
    extract::{Query, RawQuery},
    http::HeaderMap,
    response::Response,
    routing::get,
};
use chrono::Utc;
use uuid::Uuid;

pub(super) fn route(plugin: StripePlugin) -> AxumPluginRoute {
    AxumPluginRoute::new(
        "/subscription/success",
        get(handle).layer(Extension(plugin)),
    )
}

async fn handle(
    Extension(service): Extension<std::sync::Arc<crate::AuthService>>,
    Extension(plugin): Extension<StripePlugin>,
    headers: HeaderMap,
    RawQuery(_raw_query): RawQuery,
    Query(query): Query<SubscriptionSuccessQuery>,
) -> Response {
    let mut callback = query.effective_callback_url().to_owned();
    if crate::axum::http::current_session(&service, &headers)
        .await
        .is_none()
    {
        return support::redirect(support::absolute_url(&service, &callback));
    }
    let Some(checkout_id) = query.checkout_session_id() else {
        return support::redirect(support::absolute_url(&service, &callback));
    };
    callback = callback.replace("{CHECKOUT_SESSION_ID}", checkout_id);
    reconcile(&plugin, checkout_id).await;
    support::redirect(support::absolute_url(&service, &callback))
}

async fn reconcile(plugin: &StripePlugin, checkout_id: &str) {
    let checkout = match plugin
        .options
        .client
        .retrieve_checkout_session(checkout_id)
        .await
    {
        Ok(checkout) => checkout,
        Err(error) => {
            tracing::error!(message = %error, "Error retrieving checkout session from Stripe");
            return;
        }
    };
    let Some(local_id) = checkout
        .metadata
        .get("subscriptionId")
        .and_then(serde_json::Value::as_str)
        .and_then(|id| Uuid::parse_str(id).ok())
    else {
        tracing::warn!(checkout_session_id = %checkout.id, "No subscriptionId in checkout session metadata");
        return;
    };
    let local = match plugin.store.find_subscription(local_id).await {
        Ok(Some(subscription)) => subscription,
        Ok(None) => {
            tracing::warn!(subscription_id = %local_id, "Subscription record not found");
            return;
        }
        Err(error) => {
            tracing::error!(message = %error, "Stripe persistence failed");
            return;
        }
    };
    if local.is_active_or_trialing() {
        return;
    }
    let Some(stripe_id) = checkout.subscription_id() else {
        return;
    };
    if checkout.payment_status.as_deref() == Some("unpaid") {
        return;
    }
    let stripe = match plugin.options.client.retrieve_subscription(stripe_id).await {
        Ok(subscription) => subscription,
        Err(error) => {
            tracing::error!(message = %error, "Error fetching subscription from Stripe");
            return;
        }
    };
    apply_subscription(plugin, local.id, &stripe).await;
}

async fn apply_subscription(
    plugin: &StripePlugin,
    local_id: Uuid,
    stripe: &crate::StripeSubscription,
) {
    let plans = match plugin.options.plans().await {
        Ok(plans) => plans,
        Err(error) => {
            tracing::error!(message = %error, "Error resolving Stripe plans");
            return;
        }
    };
    let Some(resolved) =
        crate::stripe::webhook::transition::resolve_plan_item(&plans, &stripe.items.data)
    else {
        tracing::warn!(stripe_subscription_id = %stripe.id, "No subscription items found");
        return;
    };
    let Some(plan) = resolved.plan else {
        tracing::warn!(price_id = %resolved.item.price.id, "Plan not found for Stripe price");
        return;
    };
    let seats = crate::stripe::webhook::transition::resolve_quantity(stripe, resolved.item, plan);
    let patch = SubscriptionPatch {
        plan: Some(plan.persisted_name()),
        stripe_subscription_id: Some(Some(stripe.id.clone())),
        status: Some(stripe.status),
        period_start: Some(chrono::DateTime::from_timestamp(
            resolved.item.current_period_start,
            0,
        )),
        period_end: Some(chrono::DateTime::from_timestamp(
            resolved.item.current_period_end,
            0,
        )),
        trial_start: complete_trial(stripe.trial_start, stripe.trial_end)
            .map(|(start, _)| Some(start)),
        trial_end: complete_trial(stripe.trial_start, stripe.trial_end).map(|(_, end)| Some(end)),
        cancel_at_period_end: Some(stripe.cancel_at_period_end),
        cancel_at: Some(timestamp(stripe.cancel_at)),
        canceled_at: Some(timestamp(stripe.canceled_at)),
        seats: Some(Some(seats)),
        billing_interval: Some(
            resolved
                .item
                .price
                .recurring
                .as_ref()
                .map(|value| value.interval),
        ),
        ..SubscriptionPatch::default()
    };
    if let Err(error) = plugin.store.update_subscription(local_id, patch).await {
        tracing::error!(message = %error, "Stripe persistence failed");
    }
}

fn timestamp(value: Option<i64>) -> Option<chrono::DateTime<Utc>> {
    value
        .filter(|value| *value != 0)
        .and_then(|value| chrono::DateTime::from_timestamp(value, 0))
}

fn complete_trial(
    start: Option<i64>,
    end: Option<i64>,
) -> Option<(chrono::DateTime<Utc>, chrono::DateTime<Utc>)> {
    Some((timestamp(start)?, timestamp(end)?))
}
