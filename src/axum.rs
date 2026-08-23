use crate::{
    AuthError, AuthService,
    protocol::better_auth::{
        AnonymousSignInResponse, SessionResponse, SignInResponse, SuccessResponse,
    },
};
use axum::{
    Extension, Json, Router,
    http::{HeaderMap, HeaderValue, header},
    middleware,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use std::sync::Arc;

mod account;
pub(crate) mod admin;
pub(crate) mod body;
mod cors;
mod email_password;
mod error;
pub(crate) mod http;
mod oauth;
mod security;
mod user_deletion;

pub use self::http::session_token;
use self::http::{
    PeerAddress, auth_error, clear_session_cookie, client_ip, user_agent, with_session_cookie,
};

pub fn router<S>(service: Arc<AuthService>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let mut routes = Router::new()
        .route("/get-session", get(get_session))
        .route("/sign-out", post(sign_out))
        .route("/sign-in/anonymous", post(sign_in_anonymous))
        .merge(oauth::router())
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
            cors::credentialed_trusted_origins,
        ))
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

async fn sign_in_anonymous(
    Extension(service): Extension<Arc<AuthService>>,
    peer: PeerAddress,
    headers: HeaderMap,
) -> Response {
    match service
        .sign_in_anonymous(client_ip(&service, &headers, peer), user_agent(&headers))
        .await
    {
        Ok(result) => {
            let user = match service.better_auth_user(&result.session.user).await {
                Ok(user) => user,
                Err(error) => return auth_error(error),
            };
            let response = AnonymousSignInResponse {
                token: result.token.clone(),
                user,
            };
            with_session_cookie(&service, &result.token, Some(true), Json(response))
        }
        Err(error) => auth_error(error),
    }
}

async fn get_session(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
) -> Response {
    let mut response = match session_token(&service, &headers) {
        Some(token) => match service.session(&token).await {
            Ok(Some(session)) => {
                let user = match service.better_auth_user(&session.user).await {
                    Ok(user) => user,
                    Err(error) => return auth_error(error),
                };
                Json(Some(SessionResponse {
                    session: service.better_auth_session(&session.session, token),
                    user,
                }))
                .into_response()
            }
            Ok(None) => Json::<Option<SessionResponse>>(None).into_response(),
            Err(error) => return auth_error(error),
        },
        None => match service.plugin_session(&headers).await {
            Ok(Some(plugin_session)) => {
                let user = match service.better_auth_user(&plugin_session.session.user).await {
                    Ok(user) => user,
                    Err(error) => return auth_error(error),
                };
                Json(Some(SessionResponse {
                    session: service
                        .better_auth_session(&plugin_session.session.session, plugin_session.token),
                    user,
                }))
                .into_response()
            }
            Ok(None) => match service.development_session() {
                Some(session) => {
                    let user = match service.better_auth_user(&session.user).await {
                        Ok(user) => user,
                        Err(error) => return auth_error(error),
                    };
                    Json(Some(SessionResponse {
                        session: service
                            .better_auth_session(&session.session, "development-bypass"),
                        user,
                    }))
                    .into_response()
                }
                None => Json::<Option<SessionResponse>>(None).into_response(),
            },
            Err(error) => return auth_error(error),
        },
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

async fn sign_out(Extension(service): Extension<Arc<AuthService>>, headers: HeaderMap) -> Response {
    if let Some(token) = session_token(&service, &headers)
        && let Err(error) = service.sign_out(&token).await
    {
        return auth_error(error);
    }
    clear_session_cookie(&service, Json(SuccessResponse { success: true }))
}
