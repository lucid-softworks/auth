use axum::{
    body::Body,
    extract::{OriginalUri, RawQuery, State},
    http::{HeaderMap, StatusCode, header},
    response::Response,
};
use std::sync::Arc;
use url::Url;

pub(super) async fn authorization_proxy(
    State(service): State<Arc<crate::AuthService>>,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    RawQuery(query): RawQuery,
) -> Response {
    let Some(query) = parse_query(query.as_deref()) else {
        return crate::axum::api_error(
            StatusCode::BAD_REQUEST,
            "VALIDATION_ERROR",
            "[query.authorizationURL] Invalid input: expected string, received undefined",
        );
    };
    let authorization_url = &query.authorization_url;
    if authorization_url.contains('#') {
        return invalid_authorization_url();
    }
    let Ok(target) = Url::parse(authorization_url) else {
        return invalid_authorization_url();
    };
    if target.scheme() != "https"
        || request_origin(&service, &headers, &uri)
            .is_some_and(|origin| origin == target.origin().ascii_serialization())
    {
        return invalid_authorization_url();
    }

    let (cookie_name, cookie_value, max_age) =
        match query.oauth_state.filter(|value| !value.is_empty()) {
            Some(value) => (
                "oauth_state",
                crate::cookie::encode_cookie_component(&value),
                600,
            ),
            None => {
                let Some(state) = target
                    .query_pairs()
                    .find(|(name, _)| name == "state")
                    .map(|(_, value)| value.into_owned())
                    .filter(|value| !value.is_empty())
                else {
                    return crate::axum::api_error(
                        StatusCode::BAD_REQUEST,
                        "BAD_REQUEST",
                        "Unexpected error",
                    );
                };
                ("state", service.signed_cookie_value(&state), 300)
            }
        };

    let Some(location) = super::location_header(authorization_url) else {
        return invalid_authorization_url();
    };
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::FOUND;
    response.headers_mut().insert(header::LOCATION, location);
    crate::axum::http::with_cookie(
        response,
        crate::axum::http::serialize_cookie(
            &service.plugin_cookie(cookie_name),
            &cookie_value,
            Some(max_age),
        ),
    )
}

struct ProxyQuery {
    authorization_url: String,
    oauth_state: Option<String>,
}

fn parse_query(query: Option<&str>) -> Option<ProxyQuery> {
    let mut authorization_url = None;
    let mut oauth_state = None;
    for (name, value) in url::form_urlencoded::parse(query?.as_bytes()) {
        match name.as_ref() {
            "authorizationURL" if authorization_url.is_none() => {
                authorization_url = Some(value.into_owned());
            }
            "oauthState" if oauth_state.is_none() => oauth_state = Some(value.into_owned()),
            _ => {}
        }
    }
    Some(ProxyQuery {
        authorization_url: authorization_url?,
        oauth_state,
    })
}

fn request_origin(
    service: &crate::AuthService,
    headers: &HeaderMap,
    uri: &axum::http::Uri,
) -> Option<String> {
    if let Some(configured) = service.configured_base_url() {
        return Some(configured.origin().ascii_serialization());
    }
    if let (Some(scheme), Some(authority)) = (uri.scheme_str(), uri.authority()) {
        return Url::parse(&format!("{scheme}://{authority}"))
            .ok()
            .map(|url| url.origin().ascii_serialization());
    }
    let forwarded = service.trusted_proxy_headers().then(|| {
        header_text(headers, "x-forwarded-proto").zip(header_text(headers, "x-forwarded-host"))
    });
    let (scheme, host) = forwarded.flatten().unwrap_or_else(|| {
        (
            if service.cookie_secure() {
                "https"
            } else {
                "http"
            },
            header_text(headers, header::HOST.as_str()).unwrap_or_default(),
        )
    });
    (!host.is_empty())
        .then(|| Url::parse(&format!("{scheme}://{host}")).ok())
        .flatten()
        .map(|url| url.origin().ascii_serialization())
}

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn invalid_authorization_url() -> Response {
    crate::axum::api_error(
        StatusCode::BAD_REQUEST,
        "BAD_REQUEST",
        "Invalid authorizationURL",
    )
}
