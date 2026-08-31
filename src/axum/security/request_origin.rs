use crate::{AuthService, TrustedOrigin};
use axum::http::{HeaderMap, header};

pub(crate) fn request_origin(headers: &HeaderMap) -> Option<&str> {
    header_text(headers, header::ORIGIN.as_str()).or_else(|| header_text(headers, "referer"))
}

pub(crate) fn origin_is_trusted(
    service: &AuthService,
    headers: &HeaderMap,
    candidate: &str,
) -> bool {
    service.trusts_origin(candidate)
        || (service.auth_base_url().is_none()
            && request_host_origin(service, headers).is_some_and(|origin| {
                TrustedOrigin::parse(&origin).is_ok_and(|trusted| trusted.matches(candidate))
            }))
}

pub(super) fn request_host_origin(
    service: &AuthService,
    headers: &HeaderMap,
) -> Option<String> {
    if service.trusted_proxy_headers()
        && let (Some(scheme), Some(host)) = (
            first_header(headers, "x-forwarded-proto"),
            first_header(headers, "x-forwarded-host"),
        )
        && let Some(origin) = validated_request_origin(scheme, host)
    {
        return Some(origin);
    }
    let scheme = if service.cookie_secure() {
        "https"
    } else {
        "http"
    };
    validated_request_origin(scheme, first_header(headers, header::HOST.as_str())?)
}

fn validated_request_origin(scheme: &str, host: &str) -> Option<String> {
    if !matches!(scheme, "http" | "https") {
        return None;
    }
    let parsed = url::Url::parse(&format!("{scheme}://{host}")).ok()?;
    if parsed.host().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return None;
    }
    Some(parsed.origin().ascii_serialization())
}

fn first_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    header_text(headers, name)
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}
