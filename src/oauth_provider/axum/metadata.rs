use crate::{AuthService, AxumPluginRoute};
use axum::{
    Extension, Json,
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
    routing::get,
};
use serde_json::Value;
use std::{collections::BTreeSet, sync::Arc};

use super::super::OAuthProviderConfig;

mod document;

const METADATA_CACHE_CONTROL: &str =
    "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400";

pub(super) fn routes(config: Arc<OAuthProviderConfig>) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new(
            "/.well-known/oauth-authorization-server",
            get(oauth_metadata).layer(Extension(config.clone())),
        ),
        AxumPluginRoute::new(
            "/.well-known/openid-configuration",
            get(openid_metadata).layer(Extension(config)),
        ),
    ]
}

pub(super) fn root_routes(
    service: &AuthService,
    config: Arc<OAuthProviderConfig>,
) -> Vec<AxumPluginRoute> {
    let issuer_path = discovery_issuer_path(service, &config);
    let base_path = service.base_path().trim_end_matches('/');
    let nested_authorization_server = format!("{base_path}/.well-known/oauth-authorization-server");
    let nested_openid = format!("{base_path}/.well-known/openid-configuration");
    let mut paths = BTreeSet::from([
        format!("/.well-known/oauth-authorization-server{issuer_path}"),
        format!("{issuer_path}/.well-known/oauth-authorization-server"),
    ]);
    if config.oidc_enabled() {
        paths.insert(format!("{issuer_path}/.well-known/openid-configuration"));
    }
    paths
        .into_iter()
        .filter(|path| path != &nested_authorization_server && path != &nested_openid)
        .map(|path| {
            let route = if path.ends_with("/.well-known/openid-configuration") {
                get(openid_metadata)
            } else {
                get(oauth_metadata)
            };
            AxumPluginRoute::new(path, route.layer(Extension(config.clone())))
        })
        .collect()
}

fn discovery_issuer_path(service: &AuthService, config: &OAuthProviderConfig) -> String {
    let issuer = (!config.disable_jwt_plugin)
        .then(|| {
            service
                .jwt()
                .and_then(|jwt| jwt.configured_issuer().map(str::to_owned))
        })
        .flatten()
        .or_else(|| {
            service
                .configured_base_url()
                .map(|url| url.as_str().to_owned())
        });
    issuer
        .as_deref()
        .and_then(|issuer| url::Url::parse(issuer).ok())
        .map(|issuer| issuer.path().trim_end_matches('/').to_owned())
        .filter(|path| !path.is_empty() && path != "/")
        .unwrap_or_else(|| service.base_path().trim_end_matches('/').to_owned())
}

async fn oauth_metadata(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<OAuthProviderConfig>>,
    headers: HeaderMap,
) -> Response {
    metadata_response(document::provider_metadata(
        issuer(&service, &headers),
        &service,
        &config,
        config.oidc_enabled(),
    ))
}

async fn openid_metadata(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(config): Extension<Arc<OAuthProviderConfig>>,
    headers: HeaderMap,
) -> Response {
    if !config.oidc_enabled() {
        return axum::http::StatusCode::NOT_FOUND.into_response();
    }
    metadata_response(document::provider_metadata(
        issuer(&service, &headers),
        &service,
        &config,
        true,
    ))
}

pub(crate) fn issuer(service: &AuthService, headers: &HeaderMap) -> String {
    if let Some(configured) = service.configured_base_url() {
        let mut resolved = configured.clone();
        if resolved.path() == "/" {
            resolved.set_path(service.base_path());
        }
        return resolved.as_str().trim_end_matches('/').to_owned();
    }
    let origin = request_origin(service, headers).unwrap_or_else(|| {
        format!(
            "{}://localhost",
            if service.cookie_secure() {
                "https"
            } else {
                "http"
            }
        )
    });
    format!("{origin}{}", service.base_path())
}

pub(crate) fn provider_issuer(
    service: &AuthService,
    headers: &HeaderMap,
    config: &OAuthProviderConfig,
) -> String {
    let base_url = issuer(service, headers);
    let configured = if config.disable_jwt_plugin {
        None
    } else {
        service
            .jwt()
            .and_then(|jwt| jwt.configured_issuer().map(str::to_owned))
    };
    crate::oauth_provider::issuer::normalize_issuer(configured.as_deref().unwrap_or(&base_url))
}

fn request_origin(service: &AuthService, headers: &HeaderMap) -> Option<String> {
    if service.trusted_proxy_headers()
        && let (Some(scheme), Some(authority)) = (
            first_header(headers, "x-forwarded-proto"),
            first_header(headers, "x-forwarded-host"),
        )
        && let Some(origin) = validated_origin(scheme, authority, true)
    {
        return Some(origin);
    }
    let authority = first_header(headers, header::HOST.as_str())?;
    let scheme = if service.cookie_secure() {
        "https"
    } else {
        "http"
    };
    validated_origin(scheme, authority, false)
}

fn first_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
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

fn metadata_response(body: Value) -> Response {
    let mut response = Json(body).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(METADATA_CACHE_CONTROL),
    );
    response
}

#[cfg(test)]
mod issuer_tests {
    use super::*;
    use crate::{AuthConfig, MemoryStore};

    fn service(trust_proxy: bool) -> AuthService {
        let mut config = AuthConfig::new([91; 32]).unwrap();
        config.trusted_proxy_headers = trust_proxy;
        AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap()
    }

    #[test]
    fn untrusted_forwarded_origin_cannot_spoof_the_issuer() {
        let headers = HeaderMap::from_iter([
            (header::HOST, HeaderValue::from_static("honest.example")),
            (
                "x-forwarded-host".parse().unwrap(),
                HeaderValue::from_static("evil.example"),
            ),
            (
                "x-forwarded-proto".parse().unwrap(),
                HeaderValue::from_static("https"),
            ),
        ]);
        assert_eq!(
            issuer(&service(false), &headers),
            "http://honest.example/api/auth"
        );
        assert_eq!(
            issuer(&service(true), &headers),
            "https://evil.example/api/auth"
        );
    }

    #[test]
    fn invalid_trusted_forwarded_authority_falls_back_to_host() {
        let headers = HeaderMap::from_iter([
            (header::HOST, HeaderValue::from_static("honest.example")),
            (
                "x-forwarded-host".parse().unwrap(),
                HeaderValue::from_static("evil.example/path"),
            ),
            (
                "x-forwarded-proto".parse().unwrap(),
                HeaderValue::from_static("https"),
            ),
        ]);
        assert_eq!(
            issuer(&service(true), &headers),
            "http://honest.example/api/auth"
        );
    }
}
