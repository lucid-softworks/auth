#![allow(clippy::result_large_err)] // Axum responses are the deliberate error channel.

use super::super::{ChargebeeRouteState, input, support};
use crate::chargebee::ChargebeeReferenceAction;
use axum::{
    Extension,
    http::{HeaderMap, StatusCode},
    response::Response,
    routing::{MethodRouter, post},
};
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
    let input = match input::portal(body) {
        Ok(input) => input,
        Err(error) => return support::validation_error(error.message()),
    };
    let session = match support::session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return response,
    };
    let context = support::callback_context("POST", "/subscription/portal", None, &headers);
    if let Err(response) = support::authorize_reference(
        &state,
        &session,
        input.reference_id.as_deref(),
        input.customer_type,
        ChargebeeReferenceAction::BillingPortal,
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
    match execute(&service, &state, &session, &headers, &reference_id, &input).await {
        Ok(value) => support::success(value),
        Err(response) => response,
    }
}

async fn execute(
    service: &crate::AuthService,
    state: &ChargebeeRouteState,
    session: &crate::SessionWithUser,
    headers: &HeaderMap,
    reference_id: &str,
    input: &input::PortalInput,
) -> Result<Value, Response> {
    let customer_id = match input.customer_type {
        input::CustomerType::User => support::session_customer_id(session).map(str::to_owned),
        input::CustomerType::Organization => {
            let subscriptions = state
                .store
                .list_subscriptions_by_reference(reference_id)
                .await
                .map_err(support::internal_error)?;
            match subscriptions
                .iter()
                .find(|subscription| subscription.is_active())
                .and_then(|subscription| subscription.chargebee_customer_id.clone())
            {
                Some(customer_id) => Some(customer_id),
                None => {
                    support::organization_snapshot(service, state, reference_id)
                        .await?
                        .chargebee_customer_id
                }
            }
        }
    }
    .ok_or_else(|| {
        support::error(
            crate::chargebee::ChargebeeErrorCode::CustomerNotFound,
            StatusCode::BAD_REQUEST,
        )
    })?;
    let portal = state
        .options
        .client
        .create_portal_session(serde_json::json!({
            "customer": {"id": customer_id},
            "redirect_url": support::absolute_url(service, headers, &input.return_url),
        }))
        .await
        .map_err(support::provider_error)?;
    Ok(serde_json::json!({
        "url": portal.access_url,
        "redirect": !input.disable_redirect,
    }))
}
