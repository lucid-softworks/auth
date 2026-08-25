use super::super::{
    PolarRouteState,
    input::{PortalInput, SubscriptionsInput, order_query, page_query},
    support,
};
use crate::{
    AxumPluginRoute,
    polar::{PolarCustomerSessionCreate, PolarReferenceSubscriptionQuery},
};
use axum::{
    Extension, Json,
    extract::RawQuery,
    http::HeaderMap,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;

pub(super) fn routes(state: PolarRouteState) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new(
            "/customer/portal",
            get(portal_get)
                .merge(post(portal_post))
                .layer(Extension(state.clone())),
        ),
        route("/customer/state", get(state_get), state.clone()),
        route("/customer/benefits/list", get(benefits_get), state.clone()),
        route(
            "/customer/subscriptions/list",
            get(subscriptions_get),
            state.clone(),
        ),
        route("/customer/orders/list", get(orders_get), state),
    ]
}

fn route(
    path: &'static str,
    router: axum::routing::MethodRouter,
    state: PolarRouteState,
) -> AxumPluginRoute {
    AxumPluginRoute::new(path, router.layer(Extension(state)))
}

async fn portal_get(
    Extension(service): Extension<std::sync::Arc<crate::AuthService>>,
    Extension(state): Extension<PolarRouteState>,
    headers: HeaderMap,
) -> Response {
    portal(service, state, headers, PortalInput::default()).await
}

async fn portal_post(
    Extension(service): Extension<std::sync::Arc<crate::AuthService>>,
    Extension(state): Extension<PolarRouteState>,
    headers: HeaderMap,
    crate::axum::body::OptionalBetterAuthBody(input): crate::axum::body::OptionalBetterAuthBody<
        PortalInput,
    >,
) -> Response {
    portal(service, state, headers, input).await
}

async fn portal(
    service: std::sync::Arc<crate::AuthService>,
    state: PolarRouteState,
    headers: HeaderMap,
    input: PortalInput,
) -> Response {
    let session = match required_session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    if session.user.is_anonymous {
        return support::unauthorized("Anonymous users cannot access the portal");
    }
    let options = state
        .portal
        .as_ref()
        .expect("portal route requires portal options");
    let result = state
        .client
        .create_customer_session(PolarCustomerSessionCreate {
            external_customer_id: session.user.id.to_string(),
            return_url: options.resolved_return_url(),
        })
        .await;
    match result {
        Ok(session) => match support::themed_url(
            &session.customer_portal_url,
            options.theme.map(crate::polar::PolarTheme::as_str),
        ) {
            Ok(url) => Json(json!({ "url": url, "redirect": input.redirect() })).into_response(),
            Err(error) => {
                tracing::error!(message = %error, "Polar portal URL was invalid");
                support::internal("Customer portal creation failed")
            }
        },
        Err(error) => provider_failure(error, "Customer portal creation failed"),
    }
}

async fn state_get(
    Extension(service): Extension<std::sync::Arc<crate::AuthService>>,
    Extension(state): Extension<PolarRouteState>,
    headers: HeaderMap,
) -> Response {
    let session = match required_session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    match state
        .client
        .customer_state_external(&session.user.id.to_string())
        .await
    {
        Ok(value) => Json(value).into_response(),
        Err(error) => provider_failure(error, "Subscriptions list failed"),
    }
}

async fn benefits_get(
    Extension(service): Extension<std::sync::Arc<crate::AuthService>>,
    Extension(state): Extension<PolarRouteState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    let query = match page_query(raw.as_deref()) {
        Ok(query) => query,
        Err(error) => return support::bad_input(error),
    };
    let session = match required_session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let token = match customer_token(&state, &session).await {
        Ok(token) => token,
        Err(error) => return provider_failure(error, "Benefits list failed"),
    };
    match state.client.list_benefits(&token, query).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => provider_failure(error, "Benefits list failed"),
    }
}

async fn subscriptions_get(
    Extension(service): Extension<std::sync::Arc<crate::AuthService>>,
    Extension(state): Extension<PolarRouteState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    let input = match SubscriptionsInput::parse(raw.as_deref()) {
        Ok(input) => input,
        Err(error) => return support::bad_input(error),
    };
    let Some(reference_id) = input
        .reference_id
        .as_deref()
        .filter(|reference_id| !reference_id.is_empty())
    else {
        let session = match required_session(&service, &headers).await {
            Ok(session) => session,
            Err(response) => return *response,
        };
        let token = match customer_token(&state, &session).await {
            Ok(token) => token,
            Err(error) => return provider_failure(error, "Polar subscriptions list failed"),
        };
        return match state
            .client
            .list_customer_subscriptions(&token, input.query)
            .await
        {
            Ok(value) => Json(value).into_response(),
            Err(error) => provider_failure(error, "Polar subscriptions list failed"),
        };
    };
    if let Err(response) = required_session(&service, &headers).await {
        return *response;
    }
    match state
        .client
        .list_subscriptions_by_reference(PolarReferenceSubscriptionQuery {
            reference_id: reference_id.to_owned(),
            page: input.query.page,
            limit: input.query.limit,
            active: input.query.active,
        })
        .await
    {
        Ok(value) => Json(value).into_response(),
        Err(error) => provider_failure(error, "Subscriptions list with referenceId failed"),
    }
}

async fn orders_get(
    Extension(service): Extension<std::sync::Arc<crate::AuthService>>,
    Extension(state): Extension<PolarRouteState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    let query = match order_query(raw.as_deref()) {
        Ok(query) => query,
        Err(error) => return support::bad_input(error),
    };
    let session = match required_session(&service, &headers).await {
        Ok(session) => session,
        Err(response) => return *response,
    };
    let token = match customer_token(&state, &session).await {
        Ok(token) => token,
        Err(error) => return provider_failure(error, "Orders list failed"),
    };
    match state.client.list_orders(&token, query).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => provider_failure(error, "Orders list failed"),
    }
}

async fn customer_token(
    state: &PolarRouteState,
    session: &crate::SessionWithUser,
) -> Result<String, crate::polar::PolarProviderError> {
    state
        .client
        .create_customer_session(PolarCustomerSessionCreate {
            external_customer_id: session.user.id.to_string(),
            return_url: None,
        })
        .await
        .map(|session| session.token)
}

async fn required_session(
    service: &crate::AuthService,
    headers: &HeaderMap,
) -> Result<crate::SessionWithUser, Box<Response>> {
    support::optional_session(service, headers)
        .await
        .ok_or_else(|| Box::new(support::bad_request("User not found")))
}

fn provider_failure(error: crate::polar::PolarProviderError, message: &'static str) -> Response {
    tracing::error!(message = %error, "Polar provider request failed");
    support::internal(message)
}
