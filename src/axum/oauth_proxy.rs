use super::{
    http::{
        PeerAddress, client_ip, cookie_value, serialize_cookie, user_agent,
        with_bound_session_cookie, with_cookie,
    },
    oauth::{redirect, redirect_error, with_provider_account_cookie},
};
use crate::{AuthError, AuthService, SocialSignInInput};
use axum::{
    Extension,
    extract::Query,
    http::{HeaderMap, HeaderValue, StatusCode, Uri, header},
    response::Response,
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::Arc;
use url::Url;

pub(crate) struct OAuthProxyPreparation {
    pub redirect_uri: String,
}

pub(crate) fn prepare_social_sign_in(
    service: &AuthService,
    headers: &HeaderMap,
    uri: &Uri,
    input: &mut SocialSignInInput,
) -> Result<Option<OAuthProxyPreparation>, AuthError> {
    let Some(plugin) = service.oauth_proxy_plugin() else {
        return Ok(None);
    };
    let base_url = service.oauth_base_url()?;
    let request_url = request_url(service, headers, uri);
    let request_origin_is_trusted = request_url
        .as_deref()
        .and_then(|value| Url::parse(value).ok())
        .is_some_and(|url| service.trusts_origin(&url.origin().ascii_serialization()));
    let vendor_url = crate::oauth_proxy::url::vendor_base_url();
    let better_auth_url = std::env::var("BETTER_AUTH_URL").ok();
    let skip_header = headers
        .get("x-skip-oauth-proxy")
        .and_then(|value| value.to_str().ok());
    let resolved = crate::oauth_proxy::url::resolve(
        plugin.config(),
        crate::oauth_proxy::url::OAuthProxyUrlSources {
            request_url: request_url.as_deref(),
            request_origin_is_trusted,
            vendor_url: vendor_url.as_deref(),
            better_auth_url: better_auth_url.as_deref(),
            base_url: &base_url,
            skip_header,
        },
    )?;
    if resolved.skip {
        return Ok(None);
    }
    let original_callback = input
        .callback_url
        .as_deref()
        .filter(|url| !url.is_empty())
        .unwrap_or(&base_url);
    input.callback_url = Some(crate::oauth_proxy::url::proxy_callback_url(
        &resolved.current,
        service.base_path(),
        original_callback,
    ));
    let redirect_uri = plugin.config().production_url.as_ref().map_or_else(
        || service.oauth_callback_url(&input.provider),
        |_| {
            Ok(format!(
                "{}/callback/{}",
                crate::oauth_proxy::url::auth_base_url(&resolved.production, service.base_path()),
                input.provider
            ))
        },
    )?;
    Ok(Some(OAuthProxyPreparation { redirect_uri }))
}

pub(crate) async fn wrap_social_sign_in(
    service: &AuthService,
    result: &mut crate::SocialSignInResult,
) {
    if let Some(plugin) = service.oauth_proxy_plugin() {
        crate::oauth_proxy::service::wrap_authorization(service, plugin, result).await;
    }
}

pub(crate) async fn provider_callback(
    service: &AuthService,
    provider_id: &str,
    query: &super::oauth::OAuthCallbackQuery,
) -> Option<Response> {
    let plugin = service.oauth_proxy_plugin()?;
    let state = query.state.as_deref()?;
    let provider_user = query
        .user
        .as_deref()
        .and_then(|value| serde_json::from_str::<Value>(value).ok());
    crate::oauth_proxy::service::provider_callback(
        service,
        plugin,
        provider_id,
        state,
        query.code.as_deref(),
        query.error.as_deref(),
        provider_user.as_ref(),
    )
    .await
    .map(proxy_callback_response)
}

fn proxy_callback_response(outcome: crate::oauth_proxy::service::ProxyCallbackOutcome) -> Response {
    match outcome {
        crate::oauth_proxy::service::ProxyCallbackOutcome::Redirect(location) => {
            redirect(&location)
        }
        crate::oauth_proxy::service::ProxyCallbackOutcome::Error {
            error_url,
            code,
            description,
        } => redirect_error(&error_url, &code, description.as_deref()),
        crate::oauth_proxy::service::ProxyCallbackOutcome::InternalError => {
            super::http::auth_error(AuthError::Worker)
        }
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OAuthProxyQuery {
    #[serde(rename = "callbackURL")]
    callback_url: Option<String>,
    profile: Option<String>,
}

pub(crate) async fn oauth_proxy_callback(
    Extension(service): Extension<Arc<AuthService>>,
    Query(query): Query<OAuthProxyQuery>,
    peer: PeerAddress,
    headers: HeaderMap,
) -> Response {
    if query.callback_url.is_none() {
        return super::error::dynamic_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "[query.callbackURL] Invalid input: expected string, received undefined",
        );
    }
    let default_error_url = service.oauth_proxy_default_error_url();
    let Some(profile) = query.profile.as_deref() else {
        return redirect_error(&default_error_url, "missing_profile", None);
    };
    let cookie = service.plugin_cookie(service.oauth_state_cookie_name());
    let state_cookie = cookie_value(&headers, &cookie.name);
    match crate::oauth_proxy::service::finish_callback(
        &service,
        service
            .oauth_proxy_plugin()
            .expect("the plugin owns this route"),
        profile,
        state_cookie.as_deref(),
        client_ip(&service, &headers, peer),
        user_agent(&headers),
    )
    .await
    {
        Ok((result, is_new_user, payload)) => {
            let destination = if is_new_user {
                payload.new_user_url.unwrap_or(payload.callback_url)
            } else {
                payload.callback_url
            };
            let response = with_bound_session_cookie(
                &service,
                &headers,
                result.session.user.id,
                &result.token,
                Some(true),
                redirect(&destination),
            )
            .await;
            let response = with_provider_account_cookie(
                &service,
                &headers,
                result.session.user.id,
                &payload.account.provider_id,
                response,
            )
            .await;
            clear_state_cookie(&service, response)
        }
        Err(error) => {
            let response = redirect_error(
                error.error_url.as_deref().unwrap_or(&default_error_url),
                &error.code,
                error.description.as_deref(),
            );
            if error.clear_state_cookie {
                clear_state_cookie(&service, response)
            } else {
                response
            }
        }
    }
}

pub(crate) fn after_response(
    service: &AuthService,
    plugin: &crate::OAuthProxyPlugin,
    request: &crate::PluginRequestContext,
    mut response: Response,
) -> Response {
    if !request.path.starts_with("/callback/") {
        return response;
    }
    let Some(location) = response
        .headers()
        .get(header::LOCATION)
        .and_then(|value| value.to_str().ok())
        .filter(|location| {
            location.starts_with("http") && location.contains("/oauth-proxy-callback?callbackURL")
        })
    else {
        return response;
    };
    let Ok(location_url) = Url::parse(location) else {
        return response;
    };
    let production = plugin.config().production_url.clone().or_else(|| {
        service
            .oauth_base_url()
            .ok()
            .and_then(|url| Url::parse(&url).ok())
    });
    let Some(production) = production else {
        return response;
    };
    if location_url.origin() != production.origin() {
        return response;
    }
    let Some(destination) = location_url
        .query_pairs()
        .find(|(name, _)| name == "callbackURL")
        .map(|(_, value)| value.into_owned())
    else {
        return response;
    };
    if let Ok(location) = HeaderValue::from_str(&destination) {
        response.headers_mut().insert(header::LOCATION, location);
    }
    response
}

fn clear_state_cookie(service: &AuthService, response: Response) -> Response {
    with_cookie(
        response,
        serialize_cookie(
            &service.plugin_cookie(service.oauth_state_cookie_name()),
            "",
            Some(0),
        ),
    )
}

fn request_url(service: &AuthService, headers: &HeaderMap, uri: &Uri) -> Option<String> {
    if uri.scheme().is_some() && uri.authority().is_some() {
        return Some(uri.to_string());
    }
    let forwarded = if service.trusted_proxy_headers() {
        header_text(headers, "x-forwarded-proto").zip(header_text(headers, "x-forwarded-host"))
    } else {
        None
    };
    let (scheme, host) = forwarded.unwrap_or_else(|| {
        (
            if service.cookie_secure() {
                "https"
            } else {
                "http"
            },
            header_text(headers, header::HOST.as_str()).unwrap_or_default(),
        )
    });
    if host.is_empty() {
        return None;
    }
    Url::parse(&format!("{scheme}://{host}{uri}"))
        .ok()
        .map(|url| url.to_string())
}

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}
