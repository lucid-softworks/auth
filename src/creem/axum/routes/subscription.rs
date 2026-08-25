use super::super::{
    CreemRouteState,
    input::{IdInput, SearchInput},
    support,
};
use crate::creem::{
    CreemTransactionSearch,
    service::{
        CreemSubscriptionSelectionError, cancel_subscription_id, check_access,
        retrieve_subscription_id,
    },
};
use axum::{Extension, http::HeaderMap, response::Response};
use chrono::Utc;
use serde_json::Value;
use std::sync::Arc;

pub(super) async fn cancel(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(state): Extension<CreemRouteState>,
    headers: HeaderMap,
    crate::axum::body::OptionalBetterAuthBody(body): crate::axum::body::OptionalBetterAuthBody<
        Value,
    >,
) -> Response {
    let input: IdInput = match support::parse(body) {
        Ok(input) => input,
        Err(response) => return *response,
    };
    if state.options.api_key.is_empty() {
        return support::error(support::API_KEY_ERROR);
    }
    let Some(session) = support::session(&service, &headers).await else {
        return support::error("User must be logged in");
    };
    let id = cancel_subscription_id(
        state.store.as_ref(),
        &session.user.id.to_string(),
        input.id.as_deref(),
        state.options.persist_subscriptions,
    )
    .await;
    let id = match id {
        Ok(id) => id,
        Err(
            error @ (CreemSubscriptionSelectionError::NoActiveSubscription
            | CreemSubscriptionSelectionError::NoSubscription
            | CreemSubscriptionSelectionError::PersistenceDisabledIdRequired),
        ) => {
            return support::error(&error.to_string());
        }
        Err(error) => {
            tracing::error!(message = %error, "[creem] Failed to cancel subscription");
            return support::error("Failed to cancel subscription");
        }
    };
    match state.transport.cancel_subscription(&id).await {
        Ok(_) => support::success(serde_json::json!({
            "success": true,
            "message": "Subscription cancelled successfully"
        })),
        Err(error) => {
            tracing::error!(message = %error, "[creem] Failed to cancel subscription");
            support::error("Failed to cancel subscription")
        }
    }
}

pub(super) async fn retrieve(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(state): Extension<CreemRouteState>,
    headers: HeaderMap,
    crate::axum::body::OptionalBetterAuthBody(body): crate::axum::body::OptionalBetterAuthBody<
        Value,
    >,
) -> Response {
    let input: IdInput = match support::parse(body) {
        Ok(input) => input,
        Err(response) => return *response,
    };
    if state.options.api_key.is_empty() {
        return support::error(support::API_KEY_ERROR);
    }
    let Some(session) = support::session(&service, &headers).await else {
        return support::error("User must be logged in");
    };
    let id = retrieve_subscription_id(
        state.store.as_ref(),
        &session.user.id.to_string(),
        input.id.as_deref(),
        state.options.persist_subscriptions,
    )
    .await;
    let id = match id {
        Ok(id) => id,
        Err(
            error @ (CreemSubscriptionSelectionError::NoSubscription
            | CreemSubscriptionSelectionError::PersistenceDisabledIdRequired),
        ) => {
            return support::error(&error.to_string());
        }
        Err(error) => {
            tracing::error!(message = %error, "[creem] Failed to retrieve subscription");
            return support::error("Failed to retrieve subscription");
        }
    };
    match state.transport.retrieve_subscription(&id).await {
        Ok(subscription) => support::success(subscription.value),
        Err(error) => {
            tracing::error!(message = %error, "[creem] Failed to retrieve subscription");
            support::error("Failed to retrieve subscription")
        }
    }
}

pub(super) async fn search(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(state): Extension<CreemRouteState>,
    headers: HeaderMap,
    crate::axum::body::OptionalBetterAuthBody(body): crate::axum::body::OptionalBetterAuthBody<
        Value,
    >,
) -> Response {
    let input: SearchInput = match support::parse(body) {
        Ok(input) => input,
        Err(response) => return *response,
    };
    if let Err(message) = input.validate() {
        return support::validation_error(message);
    }
    if state.options.api_key.is_empty() {
        return support::error(support::API_KEY_ERROR);
    }
    let Some(session) = support::session(&service, &headers).await else {
        return support::error("User must be logged in");
    };
    let customer_id = support::truthy(input.customer_id.as_deref())
        .or_else(|| support::user_string(&session, "creemCustomerId"));
    let Some(customer_id) = customer_id else {
        return support::error("User must have a Creem customer ID");
    };
    match state
        .transport
        .search_transactions(CreemTransactionSearch {
            customer_id: Some(customer_id.to_owned()),
            order_id: input.order_id,
            product_id: input.product_id,
            page_number: input.page_number,
            page_size: input.page_size,
        })
        .await
    {
        Ok(transactions) => support::success(transactions.value),
        Err(error) => {
            tracing::error!(message = %error, "[creem] Failed to search transactions");
            support::error("Failed to search transactions")
        }
    }
}

pub(super) async fn access(
    Extension(service): Extension<Arc<crate::AuthService>>,
    Extension(state): Extension<CreemRouteState>,
    headers: HeaderMap,
) -> Response {
    let Some(session) = support::session(&service, &headers).await else {
        return support::message("User must be logged in to check subscription status");
    };
    if !state.options.persist_subscriptions {
        return support::message(
            "Database persistence is disabled. Enable 'persistSubscriptions' option or implement custom subscription checking.",
        );
    }
    match check_access(
        state.store.as_ref(),
        &session.user.id.to_string(),
        Utc::now(),
    )
    .await
    {
        Ok(decision) => support::success(
            serde_json::to_value(decision).expect("Creem access response is serializable"),
        ),
        Err(error) => {
            tracing::error!(message = %error, "[creem] Failed to check subscription status");
            support::message("Failed to check subscription status")
        }
    }
}
