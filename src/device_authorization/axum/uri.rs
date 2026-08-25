use axum::http::{HeaderMap, header};

use crate::AuthService;

pub(super) fn verification_uris(
    service: &AuthService,
    headers: &HeaderMap,
    configured: Option<&str>,
    user_code: &str,
) -> Result<(String, String), url::ParseError> {
    let base_url = request_base_url(service, headers);
    let raw = configured.unwrap_or("/device");
    let verification = url::Url::parse(raw).or_else(|_| url::Url::parse(&base_url)?.join(raw))?;
    let mut complete = verification.clone();
    let retained = complete
        .query_pairs()
        .filter(|(name, _)| name != "user_code")
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    complete
        .query_pairs_mut()
        .clear()
        .extend_pairs(retained)
        .append_pair("user_code", user_code);
    Ok((verification.into(), complete.into()))
}

pub(in crate::device_authorization) fn request_base_url(
    service: &AuthService,
    headers: &HeaderMap,
) -> String {
    if let Some(configured) = service.configured_base_url() {
        return configured.as_str().to_owned();
    }
    let scheme = if service.trusted_proxy_headers() {
        first_header(headers, "x-forwarded-proto")
            .filter(|scheme| matches!(*scheme, "http" | "https"))
            .unwrap_or(if service.cookie_secure() {
                "https"
            } else {
                "http"
            })
    } else if service.cookie_secure() {
        "https"
    } else {
        "http"
    };
    let host = if service.trusted_proxy_headers() {
        first_header(headers, "x-forwarded-host")
            .or_else(|| first_header(headers, header::HOST.as_str()))
    } else {
        first_header(headers, header::HOST.as_str())
    }
    .unwrap_or("localhost");
    format!("{scheme}://{host}{}", service.base_path())
}

fn first_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthConfig, MemoryStore};
    use std::sync::Arc;

    fn service() -> AuthService {
        let mut config = AuthConfig::new([211; 32]).unwrap();
        config
            .set_base_url("https://issuer.example/api/auth")
            .unwrap();
        AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap()
    }

    #[test]
    fn relative_and_absolute_verification_uris_match_javascript_url_resolution() {
        let service = service();
        let headers = HeaderMap::new();
        assert_eq!(
            verification_uris(&service, &headers, None, "ABCD").unwrap(),
            (
                "https://issuer.example/device".into(),
                "https://issuer.example/device?user_code=ABCD".into(),
            )
        );
        assert_eq!(
            verification_uris(&service, &headers, Some("device?from=app"), "A B").unwrap(),
            (
                "https://issuer.example/api/device?from=app".into(),
                "https://issuer.example/api/device?from=app&user_code=A+B".into(),
            )
        );
    }
}
