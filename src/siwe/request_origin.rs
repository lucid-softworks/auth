use crate::AuthService;
use axum::http::{HeaderMap, Uri, header};

pub(super) fn request_base_origin(
    service: &AuthService,
    headers: &HeaderMap,
    uri: &Uri,
) -> Option<String> {
    if service.trusted_proxy_headers()
        && let (Some(host), Some(scheme)) = (
            header_text(headers, "x-forwarded-host"),
            header_text(headers, "x-forwarded-proto"),
        )
        && let Some(origin) = validated_origin(scheme, host, true)
    {
        return Some(origin);
    }
    if let (Some(scheme), Some(authority)) = (uri.scheme_str(), uri.authority())
        && let Some(origin) = validated_origin(scheme, authority.as_str(), false)
    {
        return Some(origin);
    }
    let host = header_text(headers, header::HOST.as_str())?;
    let scheme = if service.cookie_secure() {
        "https"
    } else {
        "http"
    };
    validated_origin(scheme, host, false)
}

fn header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn validated_origin(scheme: &str, authority: &str, proxy: bool) -> Option<String> {
    if !matches!(scheme, "http" | "https")
        || authority.contains(['/', '\\', '@', '\0'])
        || authority.chars().any(char::is_whitespace)
        || (proxy
            && (authority.contains("..")
                || authority.starts_with('.')
                || authority.contains(['<', '>', '\'', '"'])))
    {
        return None;
    }
    let parsed = url::Url::parse(&format!("{scheme}://{authority}")).ok()?;
    (parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.path() == "/"
        && parsed.query().is_none()
        && parsed.fragment().is_none()
        && (!proxy || valid_proxy_host(&parsed, authority)))
    .then(|| parsed.origin().ascii_serialization())
}

fn valid_proxy_host(url: &url::Url, authority: &str) -> bool {
    if !authority.is_ascii() {
        return false;
    }
    match url.host() {
        Some(url::Host::Domain("localhost"))
        | Some(url::Host::Ipv4(_))
        | Some(url::Host::Ipv6(_)) => true,
        Some(url::Host::Domain(domain)) => domain.split('.').all(valid_domain_label),
        None => false,
    }
}

fn valid_domain_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        && label
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && label
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
}
