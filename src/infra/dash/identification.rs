use super::{DashKvClient, ResolvedConnectionOptions, ResolvedKvRetryOptions};
use reqwest::{Method, header::HeaderMap};
use serde::{Deserialize, Serialize};
use serde_json::Value;

mod cache;
mod routing;

const COOKIE_NAME: &str = "__infra-rid";
const DEFAULT_TRUSTED_IP_HEADERS: &[&str] = &[
    "cf-connecting-ip",
    "true-client-ip",
    "x-vercel-forwarded-for",
];

/// Published identification record returned by the Infra KV service.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Identification {
    pub visitor_id: String,
    pub request_id: String,
    pub timestamp: f64,
    pub url: String,
    pub ip: Option<String>,
    pub location: Option<IdentificationGeo>,
    pub browser: Value,
    pub confidence: f64,
    pub incognito: bool,
    pub bot: String,
}

/// Geographic record nested inside an identification response.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IdentificationGeo {
    pub lat: f64,
    pub lng: f64,
    pub city: Option<String>,
    pub region: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<IdentificationCountry>,
    pub timezone: Option<String>,
}

/// Country nested inside an identification response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdentificationCountry {
    pub code: String,
    pub name: String,
}

/// Request location added to the shared auth context.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IdentificationLocation {
    pub ip_address: Option<String>,
    pub city: Option<String>,
    pub country: Option<String>,
    pub country_code: Option<String>,
}

/// Exact advanced IP inputs consumed by the Infra identification hook.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IdentificationIpOptions {
    pub ip_address_headers: Option<Vec<String>>,
    pub disable_ip_tracking: bool,
}

/// Request values consumed by the hook independently of an HTTP framework.
#[derive(Clone, Debug)]
pub struct IdentificationRequest {
    pub method: Method,
    pub path: String,
    pub headers: HeaderMap,
    pub request_id_cookie: Option<String>,
    pub ip_options: IdentificationIpOptions,
}

/// Context values contributed by the identification hook.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct IdentificationContext {
    pub identification: Option<Identification>,
    pub visitor_id: Option<String>,
    pub request_id: Option<String>,
    pub ip: Option<String>,
    pub untrusted_visitor_id: Option<String>,
    pub location: Option<IdentificationLocation>,
}

/// After-hook cookie mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentificationCookie {
    Set {
        name: &'static str,
        value: String,
        max_age_seconds: u64,
        http_only: bool,
        same_site: &'static str,
        path: &'static str,
    },
    Clear {
        name: &'static str,
        max_age_seconds: u64,
        path: &'static str,
    },
}

/// Per-plugin identification service with the configured KV transport.
#[derive(Clone, Debug)]
pub struct IdentificationService {
    kv: DashKvClient,
    retry: ResolvedKvRetryOptions,
}

impl IdentificationService {
    pub fn new(options: &ResolvedConnectionOptions) -> Self {
        Self {
            kv: DashKvClient::new(options),
            retry: options.kv_retry,
        }
    }

    /// Whether the Better Auth before/after hook matcher runs for this request.
    pub fn should_run(request: &IdentificationRequest) -> bool {
        routing::should_run(&request.method, &request.path)
    }

    /// Load and bind identification, visitor, IP, and location context.
    pub async fn identify(&self, request: &IdentificationRequest) -> IdentificationContext {
        let skip_identification = routing::is_dash_route(&request.path);
        let header_visitor_id = (!skip_identification)
            .then(|| raw_header(&request.headers, "x-visitor-id"))
            .flatten();
        let request_id = (!skip_identification)
            .then(|| {
                raw_header(&request.headers, "x-request-id")
                    .or_else(|| request.request_id_cookie.clone())
            })
            .flatten();
        let identification = match request_id
            .as_deref()
            .filter(|request_id| !request_id.is_empty())
        {
            Some(request_id) => cache::get(request_id, &self.kv, self.retry)
                .await
                .and_then(parse_identification),
            None => None,
        };
        let visitor_id = identification
            .as_ref()
            .map(|identification| identification.visitor_id.clone())
            .and_then(|visitor_id| truthy(Some(visitor_id)));
        if header_visitor_id.is_some()
            && header_visitor_id.as_deref() != visitor_id.as_deref()
            && visitor_id.is_some()
        {
            tracing::warn!(
                "[Sentinel] X-Visitor-Id does not match identification; using identification visitorId for security checks."
            );
        }
        let request_ip = resolve_request_ip(&request.headers, &request.ip_options);
        let request_country = truthy_header(&request.headers, "cf-ipcountry")
            .or_else(|| truthy_header(&request.headers, "x-vercel-ip-country"))
            .map(|country| country.to_uppercase());
        let location = resolve_location(
            identification.as_ref(),
            request_ip.as_deref(),
            request_country.as_deref(),
            request.ip_options.disable_ip_tracking,
        );
        let ip = identification
            .as_ref()
            .and_then(|identification| identification.ip.clone())
            .or_else(|| {
                location
                    .as_ref()
                    .and_then(|location| location.ip_address.clone())
            });
        let untrusted_visitor_id = visitor_id
            .clone()
            .or_else(|| {
                ip.as_ref()
                    .filter(|ip| !ip.is_empty())
                    .map(|ip| format!("ip:{ip}"))
            })
            .or_else(|| {
                (!skip_identification)
                    .then_some(header_visitor_id)
                    .flatten()
            });

        IdentificationContext {
            identification,
            visitor_id,
            request_id,
            ip,
            untrusted_visitor_id,
            location,
        }
    }

    /// Reproduce the identification after hook's request-ID cookie lifecycle.
    pub fn cookie_after(
        request: &IdentificationRequest,
        context: &IdentificationContext,
    ) -> Option<IdentificationCookie> {
        if let Some(request_id) =
            raw_header(&request.headers, "x-request-id").filter(|request_id| !request_id.is_empty())
        {
            return Some(IdentificationCookie::Set {
                name: COOKIE_NAME,
                value: request_id,
                max_age_seconds: 600,
                http_only: true,
                same_site: "lax",
                path: "/",
            });
        }
        context
            .request_id
            .as_ref()
            .filter(|request_id| !request_id.is_empty())
            .map(|_| IdentificationCookie::Clear {
                name: COOKIE_NAME,
                max_age_seconds: 0,
                path: "/",
            })
    }
}

fn parse_identification(value: Value) -> Option<Identification> {
    serde_json::from_value(value).ok()
}

fn raw_header(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

fn truthy_header(headers: &HeaderMap, name: &str) -> Option<String> {
    truthy(raw_header(headers, name))
}

fn truthy(value: Option<String>) -> Option<String> {
    value.filter(|value| !value.is_empty())
}

fn resolve_request_ip(headers: &HeaderMap, options: &IdentificationIpOptions) -> Option<String> {
    let configured = options
        .ip_address_headers
        .as_ref()
        .filter(|headers| !headers.is_empty());
    let names: Box<dyn Iterator<Item = &str> + '_> = match configured {
        Some(headers) => Box::new(headers.iter().map(String::as_str)),
        None => Box::new(DEFAULT_TRUSTED_IP_HEADERS.iter().copied()),
    };
    for name in names {
        if let Some(value) = truthy_header(headers, name)
            && let Some(ip) = value
                .split(',')
                .next()
                .map(str::trim)
                .filter(|ip| !ip.is_empty())
        {
            return Some(ip.to_owned());
        }
    }
    None
}

fn resolve_location(
    identification: Option<&Identification>,
    request_ip: Option<&str>,
    request_country: Option<&str>,
    disable_ip_tracking: bool,
) -> Option<IdentificationLocation> {
    if disable_ip_tracking {
        return None;
    }
    if let Some(identification) = identification {
        return Some(IdentificationLocation {
            ip_address: identification
                .ip
                .clone()
                .and_then(|ip| truthy(Some(ip)))
                .or_else(|| request_ip.map(str::to_owned)),
            city: identification
                .location
                .as_ref()
                .and_then(|location| location.city.clone())
                .and_then(|city| truthy(Some(city))),
            country: identification
                .location
                .as_ref()
                .and_then(|location| location.country.as_ref())
                .map(|country| country.name.clone())
                .and_then(|country| truthy(Some(country))),
            country_code: identification
                .location
                .as_ref()
                .and_then(|location| location.country.as_ref())
                .map(|country| country.code.clone())
                .and_then(|country| truthy(Some(country)))
                .or_else(|| request_country.map(str::to_owned)),
        });
    }
    request_ip.map(|ip| IdentificationLocation {
        ip_address: Some(ip.to_owned()),
        country_code: request_country.map(str::to_owned),
        ..IdentificationLocation::default()
    })
}

#[cfg(all(test, feature = "axum"))]
#[path = "identification/contract.rs"]
mod contract;
