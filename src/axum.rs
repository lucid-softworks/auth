use crate::{AuthError, AuthService, protocol::better_auth::SignInResponse};
use axum::{
    Extension, Json, Router,
    http::HeaderMap,
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::Arc};

mod account;
mod account_lifecycle;
pub(crate) mod admin;
pub(crate) mod body;
mod cors;
mod database_hooks;
mod email_password;
mod error;
pub(crate) mod http;
mod oauth;
pub(crate) mod oauth_proxy;
mod oauth_sign_in;
mod oauth_state;
mod plugin_hooks;
mod rate_limit;
mod security;
mod session;
mod user_deletion;

pub use self::http::session_token;
pub(crate) use self::oauth::with_provider_account_cookie;
pub(crate) use error::ApiErrorResponse;
pub use error::{api_error, api_error_with_body};

pub fn router<S>(service: Arc<AuthService>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let mut routes = Router::new()
        .route(
            "/get-session",
            get(session::get_session).post(session::get_session),
        )
        .route("/sign-out", post(sign_out))
        .merge(oauth::router())
        .merge(account_lifecycle::router())
        .merge(email_password::router())
        .merge(account::router())
        .merge(user_deletion::router());
    let mut plugin_routes = BTreeMap::new();
    let mut root_plugin_routes = BTreeMap::new();
    for plugin in service.plugins().plugins() {
        for route in plugin.routes(service.clone()) {
            let (path, route) = route.into_parts();
            let route = plugin.middleware(route, service.clone());
            merge_method_route(&mut plugin_routes, path, route);
        }
        for route in plugin.root_routes(service.clone()) {
            let (path, route) = route.into_parts();
            let route = plugin.middleware(route, service.clone());
            merge_method_route(&mut root_plugin_routes, path, route);
        }
    }
    for (path, route) in plugin_routes {
        routes = routes.route_service(&path, route);
    }
    let has_root_routes = !root_plugin_routes.is_empty();
    let mut root_routes = Router::new();
    for (path, route) in root_plugin_routes {
        root_routes = root_routes.route_service(&path, route);
    }
    let routes = with_route_layers(routes, service.clone());
    let app = Router::new().nest(service.base_path(), routes);
    let app = if has_root_routes {
        app.merge(with_route_layers(root_routes, service.clone()))
    } else {
        app
    };
    with_request_layers(app, service)
}

fn merge_method_route(
    routes: &mut BTreeMap<String, axum::routing::MethodRouter>,
    path: String,
    route: axum::routing::MethodRouter,
) {
    match routes.get_mut(&path) {
        Some(existing) => *existing = existing.clone().merge(route),
        None => {
            routes.insert(path, route);
        }
    }
}

fn with_route_layers<S>(routes: Router<S>, service: Arc<AuthService>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    routes
        .layer(middleware::from_fn_with_state(
            service.clone(),
            security::validate_browser_request,
        ))
        .layer(middleware::from_fn_with_state(
            service.clone(),
            cors::credentialed_trusted_origins,
        ))
        .layer(middleware::from_fn(database_hooks::request_context))
}

fn with_request_layers<S>(routes: Router<S>, service: Arc<AuthService>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    routes
        .layer(middleware::from_fn_with_state(
            service.clone(),
            plugin_hooks::before_request,
        ))
        .layer(middleware::from_fn_with_state(
            service.clone(),
            rate_limit::enforce,
        ))
        .layer(middleware::from_fn_with_state(
            service.clone(),
            plugin_hooks::after_response,
        ))
        .layer(Extension(service))
}

pub(crate) async fn sign_in_response(
    service: &AuthService,
    result: crate::SignInResult,
    callback_url: Option<String>,
) -> Result<SignInResponse, AuthError> {
    Ok(SignInResponse {
        redirect: callback_url.is_some(),
        token: result.token,
        url: callback_url,
        user: service.better_auth_user(&result.session.user).await?,
    })
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignOutInput {
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
    disable_redirect: Option<bool>,
    state: Option<String>,
}

#[derive(Serialize)]
struct SignOutResponse {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    redirect: Option<bool>,
}

async fn sign_out(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    body::OptionalBetterAuthBody(input): body::OptionalBetterAuthBody<SignOutInput>,
) -> Response {
    if let Some(token) = session_token(&service, &headers)
        && let result = service
            .sign_out_with_provider_logout(
                &token,
                input.callback_url.as_deref(),
                input.state.as_deref(),
            )
            .await
    {
        let url = result.unwrap_or(None);
        let redirect = url.as_ref().map(|_| input.disable_redirect != Some(true));
        let mut response = Json(SignOutResponse {
            success: true,
            url: url.clone(),
            redirect,
        })
        .into_response();
        if redirect == Some(true)
            && let Some(url) = url
            && let Ok(location) = axum::http::HeaderValue::from_str(&url)
        {
            response
                .headers_mut()
                .insert(axum::http::header::LOCATION, location);
        }
        let response = http::clear_session_cookie_from_request(&service, &headers, response);
        return crate::multi_session::axum::cleanup_sign_out(&service, &headers, response).await;
    }
    let response = http::clear_session_cookie_from_request(
        &service,
        &headers,
        Json(SignOutResponse {
            success: true,
            url: None,
            redirect: None,
        }),
    );
    crate::multi_session::axum::cleanup_sign_out(&service, &headers, response).await
}
