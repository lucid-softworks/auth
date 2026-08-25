use super::support;
use crate::{
    AuthorizeReferenceAction, AxumPluginRoute, ListSubscriptionsQuery, ListedSubscription,
    StripePlugin, SubscriptionConfiguration,
};
use axum::{
    Extension, Json,
    extract::{Query, RawQuery},
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::get,
};

pub(super) fn route(plugin: StripePlugin) -> AxumPluginRoute {
    AxumPluginRoute::new("/subscription/list", get(handle).layer(Extension(plugin)))
}

async fn handle(
    Extension(service): Extension<std::sync::Arc<crate::AuthService>>,
    Extension(plugin): Extension<StripePlugin>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    Query(query): Query<ListSubscriptionsQuery>,
) -> Response {
    let session = match support::session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let context =
        support::callback_context("GET", "/subscription/list", raw_query.as_deref(), &headers);
    let reference_id = match support::authorize_reference(
        &plugin,
        &session,
        query.reference_id.as_deref(),
        query.effective_customer_type(),
        AuthorizeReferenceAction::ListSubscription,
        &context,
    )
    .await
    {
        Ok(reference_id) => reference_id,
        Err(response) => return response,
    };
    let subscriptions = match plugin.store.list_subscriptions(&reference_id).await {
        Ok(subscriptions) => subscriptions,
        Err(error) => return support::store_error(error),
    };
    if subscriptions.is_empty() {
        return Json(Vec::<ListedSubscription<crate::Subscription>>::new()).into_response();
    }
    let SubscriptionConfiguration::Enabled(options) = &plugin.options.subscription else {
        return Json(Vec::<ListedSubscription<crate::Subscription>>::new()).into_response();
    };
    let plans = match options.plans.plans().await {
        Ok(plans) => plans,
        Err(error) => {
            tracing::error!(message = %error, "Stripe plans callback failed");
            return crate::axum::api_error(
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_SERVER_ERROR",
                error.message,
            );
        }
    };
    let listed = subscriptions
        .into_iter()
        .map(|subscription| {
            let plan = plans
                .iter()
                .find(|plan| plan.matches_name(&subscription.plan));
            let price_id = plan.and_then(|plan| {
                if subscription.billing_interval == Some(crate::BillingInterval::Year) {
                    plan.annual_discount_price_id
                        .clone()
                        .or_else(|| plan.price_id.clone())
                } else {
                    plan.price_id.clone()
                }
            });
            ListedSubscription {
                limits: plan.and_then(|plan| {
                    plan.limits
                        .as_ref()
                        .and_then(|limits| serde_json::to_value(limits).ok())
                }),
                subscription,
                price_id,
            }
        })
        .filter(|subscription| subscription.subscription.is_active_or_trialing())
        .collect::<Vec<_>>();
    Json(listed).into_response()
}
