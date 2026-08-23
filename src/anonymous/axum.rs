use super::{AnonymousPluginConfig, AnonymousSignInContext};
use crate::{
    AuthError, AuthService, AxumPluginRoute,
    axum::http::{
        PeerAddress, auth_error, clear_session_cookie, client_ip, current_session, user_agent,
        with_session_cookie,
    },
    protocol::better_auth::AnonymousSignInResponse,
};
use axum::{
    Extension, Json,
    http::{HeaderMap, header},
    response::Response,
    routing::post,
};
use serde::Serialize;
use std::sync::Arc;

pub(super) fn routes(
    _service: Arc<AuthService>,
    config: Arc<AnonymousPluginConfig>,
) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new(
            "/sign-in/anonymous",
            post(sign_in).layer(Extension(config.clone())),
        ),
        AxumPluginRoute::new(
            "/delete-anonymous-user",
            post(delete_user).layer(Extension(config)),
        ),
    ]
}

async fn sign_in(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<AnonymousPluginConfig>>,
    peer: PeerAddress,
    headers: HeaderMap,
) -> Response {
    if current_session(&service, &headers)
        .await
        .is_some_and(|session| session.user.is_anonymous)
    {
        return auth_error(AuthError::AnonymousSignInAgain);
    }
    let context = AnonymousSignInContext {
        origin: headers
            .get(header::ORIGIN)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        ip_address: client_ip(&service, &headers, peer),
        user_agent: user_agent(&headers),
    };
    match service.sign_in_anonymous_with(&config, context).await {
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

async fn delete_user(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<AnonymousPluginConfig>>,
    headers: HeaderMap,
) -> Response {
    let Some(session) = current_session(&service, &headers).await else {
        return auth_error(AuthError::Unauthorized);
    };
    match service.delete_anonymous_user_with(&config, &session).await {
        Ok(()) => clear_session_cookie(&service, Json(DeleteResponse { success: true })),
        Err(error) => auth_error(error),
    }
}

#[derive(Serialize)]
struct DeleteResponse {
    success: bool,
}
