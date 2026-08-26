#![allow(clippy::result_large_err)] // Axum responses are the deliberate error channel.

use super::{error, internal_error, literal_error};
use crate::chargebee::{
    ChargebeeCallbackContext, ChargebeeErrorCode, ChargebeeReferenceAction,
    ChargebeeSubscriptionOptions,
};
use crate::{AuthService, SessionWithUser, chargebee::axum::ChargebeeRouteState};
use axum::{http::StatusCode, response::Response};

pub(in crate::chargebee::axum) async fn authorize_reference(
    state: &ChargebeeRouteState,
    session: &SessionWithUser,
    explicit_reference_id: Option<&str>,
    customer_type: super::super::input::CustomerType,
    action: ChargebeeReferenceAction,
    context: &ChargebeeCallbackContext,
) -> Result<(), Response> {
    let explicit_reference_id = explicit_reference_id.filter(|value| !value.is_empty());
    let user = super::user_snapshot(session);
    let session_snapshot = super::session_snapshot(session);
    if customer_type == super::super::input::CustomerType::Organization {
        return authorize_organization(
            state,
            &user,
            &session_snapshot,
            explicit_reference_id,
            action,
            context,
        )
        .await;
    }
    authorize_user(
        state,
        session,
        &user,
        &session_snapshot,
        explicit_reference_id,
        action,
        context,
    )
    .await
}

async fn authorize_organization(
    state: &ChargebeeRouteState,
    user: &crate::chargebee::ChargebeeUserSnapshot,
    session: &crate::chargebee::ChargebeeSessionSnapshot,
    explicit_reference_id: Option<&str>,
    action: ChargebeeReferenceAction,
    context: &ChargebeeCallbackContext,
) -> Result<(), Response> {
    let Some(authorizer) = state
        .options
        .subscription
        .as_ref()
        .and_then(|value| value.authorize_reference.as_ref())
    else {
        tracing::error!(
            "Organization subscriptions require authorizeReference to be defined in your chargebee plugin config."
        );
        return Err(literal_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "authorizeReference is required for organization subscriptions",
        ));
    };
    let reference_id = explicit_reference_id
        .map(str::to_owned)
        .or_else(|| session.active_organization_id.clone())
        .ok_or_else(|| {
            error(
                ChargebeeErrorCode::OrganizationNotFound,
                StatusCode::BAD_REQUEST,
            )
        })?;
    let authorized = authorizer
        .authorize(user, session, &reference_id, action, context)
        .await
        .map_err(internal_error)?;
    authorized.then_some(()).ok_or_else(unauthorized)
}

async fn authorize_user(
    state: &ChargebeeRouteState,
    current: &SessionWithUser,
    user: &crate::chargebee::ChargebeeUserSnapshot,
    session: &crate::chargebee::ChargebeeSessionSnapshot,
    explicit_reference_id: Option<&str>,
    action: ChargebeeReferenceAction,
    context: &ChargebeeCallbackContext,
) -> Result<(), Response> {
    let Some(reference_id) = explicit_reference_id else {
        return Ok(());
    };
    if reference_id == current.user.id {
        return Ok(());
    }
    let Some(authorizer) = state
        .options
        .subscription
        .as_ref()
        .and_then(|value| value.authorize_reference.as_ref())
    else {
        tracing::error!(
            "Passing referenceId into a subscription action isn't allowed if subscription.authorizeReference isn't defined in your chargebee plugin config."
        );
        return Err(literal_error(
            StatusCode::BAD_REQUEST,
            "BAD_REQUEST",
            "referenceId not allowed without authorizeReference",
        ));
    };
    let authorized = authorizer
        .authorize(user, session, reference_id, action, context)
        .await
        .map_err(internal_error)?;
    authorized.then_some(()).ok_or_else(unauthorized)
}

fn unauthorized() -> Response {
    error(
        ChargebeeErrorCode::UnauthorizedReference,
        StatusCode::UNAUTHORIZED,
    )
}

pub(in crate::chargebee::axum) fn resolve_reference(
    state: &ChargebeeRouteState,
    session: &SessionWithUser,
    explicit_reference_id: Option<&str>,
    customer_type: super::super::input::CustomerType,
) -> Result<String, Response> {
    if let Some(reference_id) = explicit_reference_id.filter(|value| !value.is_empty()) {
        return Ok(reference_id.to_owned());
    }
    if customer_type == super::super::input::CustomerType::Organization {
        if !state.options.organization_enabled() {
            return Err(error(
                ChargebeeErrorCode::OrganizationSubscriptionNotEnabled,
                StatusCode::BAD_REQUEST,
            ));
        }
        return AuthService::active_organization_id(session)
            .map(|id| id.to_string())
            .ok_or_else(|| {
                error(
                    ChargebeeErrorCode::OrganizationNotFound,
                    StatusCode::BAD_REQUEST,
                )
            });
    }
    Ok(session.user.id.to_string())
}

pub(in crate::chargebee::axum) fn require_subscription(
    state: &ChargebeeRouteState,
) -> Result<&ChargebeeSubscriptionOptions, Response> {
    state.options.subscription.as_ref().ok_or_else(|| {
        internal_error(
            "subscription options are absent while invoking a Chargebee subscription route",
        )
    })
}
