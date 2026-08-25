mod checkout;
mod customer;
mod reconciliation;
mod workflow;

use crate::{
    AuthService, AuthorizeReferenceAction, AxumPluginRoute, StripePlugin, UpgradeSubscriptionInput,
    axum::body::BetterAuthBody,
};
use axum::{
    Extension, Json,
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::post,
};
use std::sync::Arc;

pub(super) fn route(plugin: StripePlugin) -> AxumPluginRoute {
    AxumPluginRoute::new(
        "/subscription/upgrade",
        post(handler).layer(Extension(plugin)),
    )
}

async fn handler(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(plugin): Extension<StripePlugin>,
    headers: HeaderMap,
    BetterAuthBody(input): BetterAuthBody<UpgradeSubscriptionInput>,
) -> Response {
    let session = match super::support::session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let context = super::support::callback_context("POST", "/subscription/upgrade", None, &headers);
    let reference_id = match super::support::authorize_reference(
        &plugin,
        &session,
        input.reference_id.as_deref(),
        input.effective_customer_type(),
        AuthorizeReferenceAction::UpgradeSubscription,
        &context,
    )
    .await
    {
        Ok(reference_id) => reference_id,
        Err(response) => return response,
    };
    match workflow::execute(&service, &plugin, &session, &reference_id, &input, &context).await {
        Ok(workflow::UpgradeOutcome::Url(response)) => Json(response).into_response(),
        Ok(workflow::UpgradeOutcome::Checkout(response)) => Json(response).into_response(),
        Err(error) => super::support::runtime_error(error),
    }
}
