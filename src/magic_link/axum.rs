use super::{MagicLinkConfig, MagicLinkRequestContext};
use crate::{
    AuthService, AxumPluginRoute,
    axum::body::BetterAuthBody,
    axum::http::{PeerAddress, auth_error, client_ip, user_agent, with_session_cookie},
    protocol::better_auth::{BetterAuthSession, StatusResponse},
    service::magic_link::{MagicLinkRequest, MagicLinkVerificationError},
};
use axum::{
    Extension, Json,
    extract::Query,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::sync::Arc;

#[derive(Debug, Deserialize)]
struct SignInMagicLinkRequest {
    email: String,
    name: Option<String>,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
    #[serde(rename = "newUserCallbackURL")]
    new_user_callback_url: Option<String>,
    #[serde(rename = "errorCallbackURL")]
    error_callback_url: Option<String>,
    metadata: Option<Map<String, Value>>,
}

#[derive(Debug, Deserialize)]
struct VerifyMagicLinkQuery {
    token: String,
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
    #[serde(rename = "newUserCallbackURL")]
    new_user_callback_url: Option<String>,
    #[serde(rename = "errorCallbackURL")]
    error_callback_url: Option<String>,
}

pub(super) fn routes(
    _service: Arc<AuthService>,
    config: Arc<MagicLinkConfig>,
) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new(
            "/sign-in/magic-link",
            post(sign_in_magic_link).layer(Extension(config.clone())),
        ),
        AxumPluginRoute::new(
            "/magic-link/verify",
            get(verify_magic_link).layer(Extension(config)),
        ),
    ]
}

async fn sign_in_magic_link(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<MagicLinkConfig>>,
    peer: PeerAddress,
    headers: HeaderMap,
    BetterAuthBody(input): BetterAuthBody<SignInMagicLinkRequest>,
) -> Response {
    let context = MagicLinkRequestContext {
        origin: header_text(&headers, header::ORIGIN).map(str::to_owned),
        ip_address: client_ip(&service, &headers, peer),
        user_agent: user_agent(&headers),
    };
    let request = MagicLinkRequest {
        email: input.email,
        name: input.name,
        callback_url: input.callback_url,
        new_user_callback_url: input.new_user_callback_url,
        error_callback_url: input.error_callback_url,
        metadata: input.metadata,
        context,
    };
    match service.send_magic_link(&config, request).await {
        Ok(()) => Json(StatusResponse { status: true }).into_response(),
        Err(error) => auth_error(error),
    }
}

async fn verify_magic_link(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<MagicLinkConfig>>,
    peer: PeerAddress,
    headers: HeaderMap,
    Query(query): Query<VerifyMagicLinkQuery>,
) -> Response {
    let callback = query.callback_url.filter(|value| !value.is_empty());
    let callback_url = match service.magic_link_callback_url(callback.as_deref()) {
        Ok(url) => url,
        Err(error) => return auth_error(error),
    };
    let error_callback_url = match service
        .magic_link_callback_url(query.error_callback_url.as_deref().or(Some(&callback_url)))
    {
        Ok(url) => url,
        Err(error) => return auth_error(error),
    };
    let new_user_callback_url = match service.magic_link_callback_url(
        query
            .new_user_callback_url
            .as_deref()
            .or(Some(&callback_url)),
    ) {
        Ok(url) => url,
        Err(error) => return auth_error(error),
    };
    match service
        .verify_magic_link(
            &config,
            &query.token,
            client_ip(&service, &headers, peer),
            user_agent(&headers),
        )
        .await
    {
        Ok(verified) => {
            let token = verified.result.token.clone();
            let response = match callback {
                Some(_) if verified.is_new_user => redirect(&new_user_callback_url),
                Some(_) => redirect(&callback_url),
                None => {
                    let user = match service
                        .better_auth_user(&verified.result.session.user)
                        .await
                    {
                        Ok(user) => user,
                        Err(error) => return auth_error(error),
                    };
                    Json(json!({
                        "token": verified.result.token,
                        "user": user,
                        "session": BetterAuthSession::from_session(
                            &verified.result.session.session,
                            &token,
                        ),
                    }))
                    .into_response()
                }
            };
            with_session_cookie(&service, &token, Some(true), response)
        }
        Err(MagicLinkVerificationError::Redirect { code, description }) => {
            redirect_error(&error_callback_url, code, description)
        }
        Err(MagicLinkVerificationError::Auth(error)) => auth_error(error),
    }
}

fn redirect(location: &str) -> Response {
    match HeaderValue::from_str(location) {
        Ok(location) => (StatusCode::FOUND, [(header::LOCATION, location)]).into_response(),
        Err(_) => auth_error(crate::AuthError::InvalidCallbackUrl),
    }
}

fn redirect_error(location: &str, code: &str, description: Option<&str>) -> Response {
    let mut url = match url::Url::parse(location) {
        Ok(url) => url,
        Err(_) => return auth_error(crate::AuthError::InvalidCallbackUrl),
    };
    set_query_pair(&mut url, "error", code);
    if let Some(description) = description {
        set_query_pair(&mut url, "error_description", description);
    }
    redirect(url.as_str())
}

fn set_query_pair(url: &mut url::Url, name: &str, value: &str) {
    let mut replaced = false;
    let mut pairs = Vec::new();
    for (key, existing) in url.query_pairs() {
        if key == name {
            if !replaced {
                pairs.push((name.to_owned(), value.to_owned()));
                replaced = true;
            }
        } else {
            pairs.push((key.into_owned(), existing.into_owned()));
        }
    }
    if !replaced {
        pairs.push((name.to_owned(), value.to_owned()));
    }
    url.query_pairs_mut().clear().extend_pairs(pairs);
}

fn header_text(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_query_updates_match_url_search_params_set() {
        let mut url = url::Url::parse(
            "https://example.com/retry?error=stale&keep=yes&error=duplicate#result",
        )
        .unwrap();
        set_query_pair(&mut url, "error", "INVALID_TOKEN");
        assert_eq!(
            url.as_str(),
            "https://example.com/retry?error=INVALID_TOKEN&keep=yes#result"
        );
    }
}
