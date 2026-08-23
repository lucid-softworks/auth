use crate::{
    AuthService,
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
mod admin;
pub(crate) mod body;
mod cors;
mod email_password;
mod error;
pub(crate) mod http;
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
        .merge(email_password::router())
        .merge(account::router())
        .merge(user_deletion::router())
        .merge(admin::router());
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

pub(super) fn sign_in_response(
    service: &AuthService,
    result: crate::SignInResult,
    callback_url: Option<String>,
) -> SignInResponse {
    SignInResponse {
        redirect: callback_url.is_some(),
        token: result.token,
        url: callback_url,
        user: service.better_auth_user(&result.session.user),
        two_factor_redirect: result.session.session.assurance
            == crate::Assurance::PasswordPendingPasskey,
        two_factor_methods: if result.mfa_setup_required {
            vec!["passkey".into()]
        } else if result.session.session.assurance == crate::Assurance::PasswordPendingPasskey {
            vec!["passkey".into(), "backup_code".into()]
        } else {
            Vec::new()
        },
        mfa_setup_required: result.mfa_setup_required,
    }
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
            let response = AnonymousSignInResponse {
                token: result.token.clone(),
                user: service.better_auth_user(&result.session.user),
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
                let step_up_required = service.step_up_required(&session.principal());
                Json(Some(
                    SessionResponse {
                        session: crate::protocol::better_auth::BetterAuthSession::from_session(
                            &session.session,
                            token,
                        ),
                        user: service.better_auth_user(&session.user),
                    }
                    .with_step_up_required(step_up_required),
                ))
                .into_response()
            }
            Ok(None) => Json::<Option<SessionResponse>>(None).into_response(),
            Err(error) => return auth_error(error),
        },
        None => match service.plugin_session(&headers).await {
            Ok(Some(plugin_session)) => Json(Some(SessionResponse::new(
                &plugin_session.session,
                plugin_session.token,
            )))
            .into_response(),
            Ok(None) => Json(
                service
                    .development_session()
                    .as_ref()
                    .map(|session| SessionResponse::new(session, "development-bypass")),
            )
            .into_response(),
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
