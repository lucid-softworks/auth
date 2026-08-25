use super::OAuthProxyConfig;
use crate::AuthError;
use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use url::Url;

const ENCODE_URI_COMPONENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'%')
    .add(b'&')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}');

const VENDOR_ENVIRONMENT_KEYS: &[&str] = &[
    "VERCEL_URL",
    "NETLIFY_URL",
    "RENDER_URL",
    "AWS_LAMBDA_FUNCTION_NAME",
    "GOOGLE_CLOUD_FUNCTION_NAME",
    "AZURE_FUNCTION_NAME",
];

pub(crate) struct OAuthProxyUrlSources<'a> {
    pub request_url: Option<&'a str>,
    pub request_origin_is_trusted: bool,
    pub vendor_url: Option<&'a str>,
    pub better_auth_url: Option<&'a str>,
    pub base_url: &'a str,
    pub skip_header: Option<&'a str>,
}

pub(crate) struct ResolvedOAuthProxyUrls {
    pub current: Url,
    pub production: Url,
    pub skip: bool,
}

pub(crate) fn resolve(
    config: &OAuthProxyConfig,
    sources: OAuthProxyUrlSources<'_>,
) -> Result<ResolvedOAuthProxyUrls, AuthError> {
    let raw_current = config
        .current_url
        .as_ref()
        .map(Url::as_str)
        .or(sources.request_url)
        .or(sources.vendor_url);
    let current = config.current_url.clone().map_or_else(
        || {
            let request = sources
                .request_origin_is_trusted
                .then_some(sources.request_url)
                .flatten();
            let vendor = sources
                .vendor_url
                .filter(|value| parsed_origin(value).is_some());
            let value = request.or(vendor).unwrap_or(sources.base_url);
            parse_url(value, "current URL")
        },
        Ok,
    )?;
    let production = config.production_url.clone().map_or_else(
        || {
            parse_url(
                sources.better_auth_url.unwrap_or(sources.base_url),
                "production URL",
            )
        },
        Ok,
    )?;
    let skip = sources.skip_header.is_some_and(|value| !value.is_empty())
        || raw_current
            .and_then(parsed_origin)
            .is_some_and(|current| current == production.origin().ascii_serialization());
    Ok(ResolvedOAuthProxyUrls {
        current,
        production,
        skip,
    })
}

pub(crate) fn vendor_base_url() -> Option<String> {
    vendor_base_url_from(|name| std::env::var(name).ok())
}

pub(crate) fn vendor_base_url_from(mut get: impl FnMut(&str) -> Option<String>) -> Option<String> {
    for name in VENDOR_ENVIRONMENT_KEYS {
        let Some(value) = get(name).filter(|value| !value.is_empty()) else {
            continue;
        };
        return Some(if *name == "VERCEL_URL" {
            format!("https://{value}")
        } else {
            value
        });
    }
    None
}

pub(crate) fn proxy_callback_url(
    current: &Url,
    base_path: &str,
    original_callback_url: &str,
) -> String {
    format!(
        "{}{}{}?callbackURL={}",
        current.origin().ascii_serialization(),
        normalized_base_path(base_path),
        "/oauth-proxy-callback",
        utf8_percent_encode(original_callback_url, ENCODE_URI_COMPONENT)
    )
}

pub(crate) fn auth_base_url(url: &Url, base_path: &str) -> String {
    format!(
        "{}{}",
        url.as_str().trim_end_matches('/'),
        normalized_base_path(base_path)
    )
}

pub(crate) fn callback_destination(proxy_callback: &Url) -> String {
    proxy_callback
        .query_pairs()
        .find(|(name, _)| name == "callbackURL")
        .map_or_else(
            || proxy_callback.to_string(),
            |(_, value)| value.into_owned(),
        )
}

fn parse_url(value: &str, label: &str) -> Result<Url, AuthError> {
    Url::parse(value).map_err(|_| {
        AuthError::InvalidConfiguration(format!("OAuth proxy {label} must be an absolute URL"))
    })
}

fn normalized_base_path(base_path: &str) -> String {
    format!("/{}", base_path.trim_matches('/'))
}

fn parsed_origin(value: &str) -> Option<String> {
    let origin = Url::parse(value).ok()?.origin().ascii_serialization();
    (origin != "null").then_some(origin)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> OAuthProxyConfig {
        OAuthProxyConfig::default()
    }

    #[test]
    fn resolution_prefers_explicit_then_trusted_request_then_vendor_then_base() {
        let mut explicit = config();
        explicit.current_url = Some(Url::parse("https://explicit.example/path").unwrap());
        explicit.production_url = Some(Url::parse("https://production.example").unwrap());
        let resolved = resolve(
            &explicit,
            OAuthProxyUrlSources {
                request_url: Some("https://request.example/api/auth/sign-in/social"),
                request_origin_is_trusted: true,
                vendor_url: Some("https://vendor.example"),
                better_auth_url: Some("https://environment-production.example"),
                base_url: "https://base.example/api/auth",
                skip_header: None,
            },
        )
        .unwrap();
        assert_eq!(resolved.current.as_str(), "https://explicit.example/path");
        assert_eq!(resolved.production.as_str(), "https://production.example/");
        assert!(!resolved.skip);

        let resolved = resolve(
            &config(),
            OAuthProxyUrlSources {
                request_url: Some("https://request.example/api/auth/sign-in/social"),
                request_origin_is_trusted: true,
                vendor_url: Some("https://vendor.example"),
                better_auth_url: None,
                base_url: "https://base.example/api/auth",
                skip_header: None,
            },
        )
        .unwrap();
        assert_eq!(
            resolved.current.origin().ascii_serialization(),
            "https://request.example"
        );

        let resolved = resolve(
            &config(),
            OAuthProxyUrlSources {
                request_url: Some("https://host-header-attacker.example/sign-in/social"),
                request_origin_is_trusted: false,
                vendor_url: Some("https://vendor.example"),
                better_auth_url: None,
                base_url: "https://base.example/api/auth",
                skip_header: None,
            },
        )
        .unwrap();
        assert_eq!(resolved.current.as_str(), "https://vendor.example/");
    }

    #[test]
    fn same_origin_or_skip_header_bypasses_proxying() {
        let same = resolve(
            &config(),
            OAuthProxyUrlSources {
                request_url: Some("https://auth.example/preview"),
                request_origin_is_trusted: true,
                vendor_url: None,
                better_auth_url: None,
                base_url: "https://auth.example/api/auth",
                skip_header: None,
            },
        )
        .unwrap();
        assert!(same.skip);

        let header = resolve(
            &config(),
            OAuthProxyUrlSources {
                request_url: Some("https://preview.example/sign-in/social"),
                request_origin_is_trusted: true,
                vendor_url: None,
                better_auth_url: None,
                base_url: "https://auth.example/api/auth",
                skip_header: Some("false"),
            },
        )
        .unwrap();
        assert!(header.skip);

        let empty_header = resolve(
            &config(),
            OAuthProxyUrlSources {
                request_url: Some("https://preview.example/sign-in/social"),
                request_origin_is_trusted: true,
                vendor_url: None,
                better_auth_url: None,
                base_url: "https://auth.example/api/auth",
                skip_header: Some(""),
            },
        )
        .unwrap();
        assert!(!empty_header.skip);
    }

    #[test]
    fn skip_uses_raw_request_origin_but_receiver_rejects_an_untrusted_request_origin() {
        let resolved = resolve(
            &config(),
            OAuthProxyUrlSources {
                request_url: Some("https://auth.example/untrusted-host"),
                request_origin_is_trusted: false,
                vendor_url: Some("not-a-url"),
                better_auth_url: None,
                base_url: "https://auth.example/api/auth",
                skip_header: None,
            },
        )
        .unwrap();
        assert_eq!(resolved.current.as_str(), "https://auth.example/api/auth");
        assert!(resolved.skip);

        let resolved = resolve(
            &config(),
            OAuthProxyUrlSources {
                request_url: Some("https://attacker.example/untrusted-host"),
                request_origin_is_trusted: false,
                vendor_url: Some("bare-function-name"),
                better_auth_url: None,
                base_url: "https://auth.example/api/auth",
                skip_header: None,
            },
        )
        .unwrap();
        assert_eq!(resolved.current.as_str(), "https://auth.example/api/auth");
        assert!(!resolved.skip);
    }

    #[test]
    fn callback_builder_uses_current_origin_base_path_and_encode_uri_component() {
        let current = Url::parse("https://preview.example/a/path?ignored=1").unwrap();
        assert_eq!(
            proxy_callback_url(
                &current,
                "/api/auth/",
                "https://app.example/done?next=/a b&mode=one+two"
            ),
            "https://preview.example/api/auth/oauth-proxy-callback?callbackURL=https%3A%2F%2Fapp.example%2Fdone%3Fnext%3D%2Fa%20b%26mode%3Done%2Btwo"
        );
    }

    #[test]
    fn vendor_environment_precedence_and_vercel_scheme_match_better_auth() {
        let values = std::collections::BTreeMap::from([
            ("VERCEL_URL", "preview.vercel.app"),
            ("NETLIFY_URL", "https://preview.netlify.app"),
        ]);
        assert_eq!(
            vendor_base_url_from(|name| values.get(name).map(ToString::to_string)).as_deref(),
            Some("https://preview.vercel.app")
        );
        assert_eq!(
            vendor_base_url_from(|name| {
                (name == "NETLIFY_URL").then(|| "https://preview.netlify.app".into())
            })
            .as_deref(),
            Some("https://preview.netlify.app")
        );
    }

    #[test]
    fn callback_destination_prefers_the_embedded_callback_url() {
        let proxy = Url::parse(
            "https://preview.example/api/auth/oauth-proxy-callback?callbackURL=https%3A%2F%2Fapp.example%2Fdone",
        )
        .unwrap();
        assert_eq!(callback_destination(&proxy), "https://app.example/done");

        let plain = Url::parse("https://preview.example/api/auth/callback").unwrap();
        assert_eq!(callback_destination(&plain), plain.to_string());
    }
}
