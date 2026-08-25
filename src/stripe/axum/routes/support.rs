#![allow(clippy::result_large_err)] // Axum responses are the deliberate error channel.

use crate::{
    AuthService, AuthorizeReferenceAction, CustomerType, SessionWithUser, StripeCallbackContext,
    StripeError, StripeErrorCode, StripePlugin, StripeSessionSnapshot, StripeUserSnapshot,
    Subscription, SubscriptionConfiguration,
};
use axum::{
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use std::collections::BTreeMap;

pub(super) fn error(code: StripeErrorCode, status: StatusCode) -> Response {
    crate::axum::api_error(status, code.as_str(), code.message())
}

pub(super) fn runtime_error(error: StripeError) -> Response {
    crate::axum::api_error(
        StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
        error.code,
        error.message,
    )
}

pub(super) fn provider_error(error: crate::StripeProviderError) -> Response {
    runtime_error(StripeError::provider_bad_request(
        error.code.as_deref(),
        error.message,
    ))
}

pub(super) async fn session(
    service: &AuthService,
    headers: &HeaderMap,
) -> Result<SessionWithUser, Response> {
    crate::axum::http::current_session(service, headers)
        .await
        .ok_or_else(|| error(StripeErrorCode::Unauthorized, StatusCode::UNAUTHORIZED))
}

pub(super) fn callback_context(
    method: &str,
    path: &str,
    query: Option<&str>,
    headers: &HeaderMap,
) -> StripeCallbackContext {
    StripeCallbackContext {
        method: Some(method.into()),
        path: Some(path.into()),
        query: query.map(str::to_owned),
        headers: headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect::<BTreeMap<_, _>>(),
    }
}

pub(super) fn user_snapshot(
    session: &SessionWithUser,
    customer_id: Option<String>,
) -> StripeUserSnapshot {
    StripeUserSnapshot {
        id: session.user.id.to_string(),
        name: session.user.name.clone(),
        email: session.user.email.clone(),
        email_verified: session.user.email_verified,
        stripe_customer_id: customer_id,
        additional_fields: session.user.additional_fields.clone(),
    }
}

pub(super) fn session_snapshot(session: &SessionWithUser) -> StripeSessionSnapshot {
    StripeSessionSnapshot {
        id: session.session.id.to_string(),
        user_id: session.user.id.to_string(),
        active_organization_id: AuthService::active_organization_id(session)
            .map(|id| id.to_string()),
        additional_fields: session.session.additional_fields.clone(),
    }
}

pub(super) async fn authorize_reference(
    plugin: &StripePlugin,
    session: &SessionWithUser,
    explicit_reference_id: Option<&str>,
    customer_type: CustomerType,
    action: AuthorizeReferenceAction,
    context: &StripeCallbackContext,
) -> Result<String, Response> {
    let SubscriptionConfiguration::Enabled(options) = &plugin.options.subscription else {
        return Err(error(
            StripeErrorCode::SubscriptionNotFound,
            StatusCode::BAD_REQUEST,
        ));
    };
    let customer_id = plugin
        .store
        .user_customer_id(session.user.id)
        .await
        .ok()
        .flatten();
    let user = user_snapshot(session, customer_id);
    let session_snapshot = session_snapshot(session);

    if customer_type == CustomerType::Organization {
        if !plugin.organization_enabled() {
            return Err(error(
                StripeErrorCode::OrganizationSubscriptionNotEnabled,
                StatusCode::BAD_REQUEST,
            ));
        }
        let Some(authorizer) = &options.authorize_reference else {
            tracing::error!(
                "Organization subscriptions require authorizeReference to be defined in your stripe plugin config."
            );
            return Err(error(
                StripeErrorCode::AuthorizeReferenceRequired,
                StatusCode::BAD_REQUEST,
            ));
        };
        let reference_id = explicit_reference_id
            .map(str::to_owned)
            .or_else(|| session_snapshot.active_organization_id.clone())
            .ok_or_else(|| {
                error(
                    StripeErrorCode::OrganizationReferenceIdRequired,
                    StatusCode::BAD_REQUEST,
                )
            })?;
        let authorized = authorizer
            .authorize(&user, &session_snapshot, &reference_id, action, context)
            .await
            .map_err(callback_error)?;
        return authorized
            .then_some(reference_id)
            .ok_or_else(|| error(StripeErrorCode::Unauthorized, StatusCode::UNAUTHORIZED));
    }

    let own_id = session.user.id.to_string();
    let reference_id = explicit_reference_id.unwrap_or(&own_id).to_owned();
    if explicit_reference_id.is_none() || reference_id == own_id {
        return Ok(reference_id);
    }
    let Some(authorizer) = &options.authorize_reference else {
        tracing::error!(
            "Passing referenceId into a subscription action isn't allowed if subscription.authorizeReference isn't defined in your stripe plugin config."
        );
        return Err(error(
            StripeErrorCode::ReferenceIdNotAllowed,
            StatusCode::BAD_REQUEST,
        ));
    };
    let authorized = authorizer
        .authorize(&user, &session_snapshot, &reference_id, action, context)
        .await
        .map_err(callback_error)?;
    authorized
        .then_some(reference_id)
        .ok_or_else(|| error(StripeErrorCode::Unauthorized, StatusCode::UNAUTHORIZED))
}

fn callback_error(error: crate::StripeCallbackError) -> Response {
    tracing::error!(message = %error, "Stripe authorizeReference callback failed");
    crate::axum::api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_SERVER_ERROR",
        "Authentication failed",
    )
}

pub(super) async fn selected_subscription(
    plugin: &StripePlugin,
    reference_id: &str,
    stripe_subscription_id: Option<&str>,
) -> Result<Option<Subscription>, Response> {
    if let Some(stripe_id) = stripe_subscription_id {
        return plugin
            .store
            .find_subscription_by_stripe_id(stripe_id)
            .await
            .map(|subscription| {
                subscription.filter(|subscription| subscription.reference_id == reference_id)
            })
            .map_err(store_error);
    }
    plugin
        .store
        .list_subscriptions(reference_id)
        .await
        .map(|subscriptions| {
            subscriptions
                .into_iter()
                .find(Subscription::is_active_or_trialing)
        })
        .map_err(store_error)
}

pub(super) fn store_error(error: crate::StripeStoreError) -> Response {
    tracing::error!(message = %error, "Stripe persistence failed");
    crate::axum::api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "INTERNAL_SERVER_ERROR",
        "Authentication failed",
    )
}

pub(super) fn absolute_url(service: &AuthService, value: &str) -> String {
    if url::Url::parse(value).is_ok() {
        return value.to_owned();
    }
    let Some(base) = service.configured_base_url() else {
        return value.to_owned();
    };
    format!(
        "{}{}{}",
        base.origin().ascii_serialization(),
        base.path().trim_end_matches('/'),
        if value.starts_with('/') {
            value.to_owned()
        } else {
            format!("/{value}")
        }
    )
}

pub(super) fn redirect(location: String) -> Response {
    match axum::http::HeaderValue::from_str(&location) {
        Ok(value) => {
            let mut response = StatusCode::FOUND.into_response();
            response
                .headers_mut()
                .insert(axum::http::header::LOCATION, value);
            response
        }
        Err(_) => error(StripeErrorCode::InvalidRequestBody, StatusCode::BAD_REQUEST),
    }
}
