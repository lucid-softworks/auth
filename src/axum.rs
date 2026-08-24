use crate::{
    AuthError, AuthService,
    protocol::better_auth::{SessionResponse, SignInResponse, SuccessResponse},
};
use axum::{
    Extension, Json, Router,
    extract::Query,
    http::{HeaderMap, HeaderValue, header},
    middleware,
    response::{IntoResponse, Response},
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
mod user_deletion;

pub use self::http::session_token;
use self::http::{
    auth_error, clear_session_cookie, serialize_cookie, session_data_cookie,
    with_chunked_session_data_cookie, with_cookie, with_session_cookie,
};
use serde::Deserialize;

pub fn router<S>(service: Arc<AuthService>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    let mut routes = Router::new()
        .route("/get-session", get(get_session))
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

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GetSessionQuery {
    disable_cookie_cache: Option<bool>,
    #[allow(dead_code)]
    disable_refresh: Option<bool>,
}

async fn get_session(
    Extension(service): Extension<Arc<AuthService>>,
    headers: HeaderMap,
    Query(query): Query<GetSessionQuery>,
) -> Response {
    let token = session_token(&service, &headers);
    if let Some(response) = cached_session_response(
        &service,
        &headers,
        token.as_deref(),
        query.disable_cookie_cache == Some(true),
    ) {
        return response;
    }
    let mut response = match token {
        Some(token) => match service.session(&token).await {
            Ok(Some(session)) => {
                let user = match service.better_auth_user(&session.user).await {
                    Ok(user) => user,
                    Err(error) => return auth_error(error),
                };
                let response = Json(Some(SessionResponse {
                    session: service.better_auth_session(&session.session, &token),
                    user,
                }));
                with_session_cookie(&service, &token, Some(true), response).await
            }
            Ok(None) => clear_session_cookie(&service, Json::<Option<SessionResponse>>(None)),
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
    set_session_cache_headers(&mut response);
    response
}

fn cached_session_response(
    service: &AuthService,
    headers: &HeaderMap,
    token: Option<&str>,
    disabled: bool,
) -> Option<Response> {
    if disabled {
        return None;
    }
    let token = token?;
    let cache = session_data_cookie(service, headers)?;
    let (value, expires_at) = service.decode_session_cookie_cache(token, &cache)?;
    let mut response = Json(value).into_response();
    if service.should_refresh_cookie_cache(expires_at)
        && let Some(refreshed) = service.refresh_session_cookie_cache(&cache)
    {
        response = with_chunked_session_data_cookie(
            service,
            &refreshed,
            Some(service.cookie_cache_max_age()),
            response,
        );
        response = with_cookie(
            response,
            serialize_cookie(
                &service.session_cookie(),
                &service.signed_cookie_value(token),
                Some(service.session_ttl().num_seconds()),
            ),
        );
    }
    set_session_cache_headers(&mut response);
    Some(response)
}

fn set_session_cache_headers(response: &mut Response) {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
}

async fn sign_out(Extension(service): Extension<Arc<AuthService>>, headers: HeaderMap) -> Response {
    if let Some(token) = session_token(&service, &headers)
        && let Err(error) = service.sign_out(&token).await
    {
        return auth_error(error);
    }
    clear_session_cookie(&service, Json(SuccessResponse { success: true }))
}
