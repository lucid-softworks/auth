use crate::{
    AuthError, AuthService,
    protocol::better_auth::{SignInResponse, SuccessResponse},
};
use axum::{
    Extension, Json, Router,
    http::HeaderMap,
    middleware,
    response::Response,
    routing::{get, post},
};
use std::sync::Arc;

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
mod rate_limit;
mod security;
mod session;
mod user_deletion;

use self::http::auth_error;
pub use self::http::session_token;
pub(crate) use self::oauth::with_provider_account_cookie;

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
    for plugin in service.plugins().plugins() {
        for route in plugin.routes(service.clone()) {
            let (path, route) = route.into_parts();
            let route = plugin.middleware(route, service.clone());
            routes = routes.route_service(path, route);
        }
    }
    let routes = routes
        .layer(middleware::from_fn_with_state(
            service.clone(),
            security::validate_browser_request,
        ))
        .layer(middleware::from_fn_with_state(
            service.clone(),
            rate_limit::enforce,
        ))
        .layer(middleware::from_fn_with_state(
            service.clone(),
            cors::credentialed_trusted_origins,
        ))
        .layer(middleware::from_fn(database_hooks::request_context))
        .layer(Extension(service.clone()));
    Router::new().nest(service.base_path(), routes)
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

async fn sign_out(Extension(service): Extension<Arc<AuthService>>, headers: HeaderMap) -> Response {
    if let Some(token) = session_token(&service, &headers)
        && let Err(error) = service.sign_out(&token).await
    {
        return auth_error(error);
    }
    http::clear_session_cookie_from_request(
        &service,
        &headers,
        Json(SuccessResponse { success: true }),
    )
}
