use super::metadata::{CimdMetadata, CimdMetadataValidationOptions};
use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;
use url::Url;

pub(super) fn validate_document_uris(
    client_id_url: &str,
    metadata: &CimdMetadata,
    options: &CimdMetadataValidationOptions,
) -> Result<(), String> {
    validate_jwks_uri(metadata)?;
    validate_redirects(metadata)?;
    for field in ["client_uri", "logo_uri", "tos_uri", "policy_uri"] {
        if let Some(value) = metadata.get(field) {
            let value = value
                .as_str()
                .ok_or_else(|| format!("{field} must be a string"))?;
            validate_public_http_url(field, value)?;
        }
    }
    validate_origin_bound_fields(client_id_url, metadata, options)
}

fn validate_jwks_uri(metadata: &CimdMetadata) -> Result<(), String> {
    let Some(uri) = metadata.get("jwks_uri").and_then(Value::as_str) else {
        return Ok(());
    };
    let parsed = Url::parse(uri).map_err(|_| "jwks_uri must be a valid URL".to_owned())?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("jwks_uri must not contain credentials".into());
    }
    if uri.contains('#') {
        return Err("jwks_uri must not contain a fragment".into());
    }
    Ok(())
}

fn validate_redirects(metadata: &CimdMetadata) -> Result<(), String> {
    if metadata
        .get("redirect_uris")
        .and_then(Value::as_array)
        .is_some_and(|redirects| {
            !redirects
                .iter()
                .all(|value| value.as_str().is_some_and(is_absolute_redirect_uri))
        })
    {
        return Err(
            "redirect_uris must be a non-empty array of absolute HTTP(S) or private-use URIs"
                .into(),
        );
    }
    Ok(())
}

fn validate_origin_bound_fields(
    client_id_url: &str,
    metadata: &CimdMetadata,
    options: &CimdMetadataValidationOptions,
) -> Result<(), String> {
    let origin = Url::parse(client_id_url)
        .map_err(|_| "client_id is not a valid URL".to_owned())?
        .origin();
    let origin_label = origin.ascii_serialization();
    for field in &options.origin_bound_fields {
        let Some(value) = metadata.get(field) else { continue; };
        let values = string_values(field, value)?;
        for value in values {
            let uri = Url::parse(value)
                .map_err(|_| format!("{field} contains an invalid URL: \"{value}\""))?;
            let redirect = matches!(field.as_str(), "redirect_uris" | "post_logout_redirect_uris");
            if redirect && is_reverse_domain_private_use_redirect(&uri) { continue; }
            if !matches!(uri.scheme(), "http" | "https") {
                return Err(format!(
                    "all values for {field} must use HTTP(S) or an authority-free private-use scheme"
                ));
            }
            if redirect && is_loopback_host(uri.host_str().unwrap_or_default()) { continue; }
            if uri.origin() != origin {
                return Err(format!(
                    "{field} value \"{value}\" must have the same origin as client_id ({origin_label})"
                ));
            }
        }
    }
    Ok(())
}

fn string_values<'a>(field: &str, value: &'a Value) -> Result<Vec<&'a str>, String> {
    if let Some(value) = value.as_str() { return Ok(vec![value]); }
    value.as_array()
        .and_then(|values| values.iter().map(Value::as_str).collect::<Option<Vec<_>>>())
        .ok_or_else(|| format!("{field} must be a string or an array of strings"))
}

fn validate_public_http_url(field: &str, value: &str) -> Result<(), String> {
    let uri = Url::parse(value).map_err(|_| format!("{field} is not a valid URL"))?;
    if !matches!(uri.scheme(), "http" | "https") { return Err(format!("{field} must use HTTP(S)")); }
    if !uri.username().is_empty() || uri.password().is_some() {
        return Err(format!("{field} must not contain credentials"));
    }
    if uri.host_str().is_none_or(|host| !crate::network_address::is_public_routable_host(host)) {
        return Err(format!("{field} must not point to a private or reserved address"));
    }
    Ok(())
}

fn is_absolute_redirect_uri(value: &str) -> bool {
    Url::parse(value).is_ok_and(|uri| {
        matches!(uri.scheme(), "http" | "https") || is_reverse_domain_private_use_redirect(&uri)
    })
}

fn is_reverse_domain_private_use_redirect(uri: &Url) -> bool {
    static SCHEME: OnceLock<Regex> = OnceLock::new();
    let scheme = SCHEME.get_or_init(|| {
        Regex::new(r"(?i)^[a-z](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$")
            .expect("the static reverse-domain expression is valid")
    });
    let specific = &uri.as_str()[uri.scheme().len() + 1..];
    !matches!(uri.scheme(), "http" | "https")
        && uri.host_str().is_none()
        && specific.starts_with('/')
        && !specific.starts_with("//")
        && scheme.is_match(uri.scheme())
}

fn is_loopback_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    host == "localhost" || host.ends_with(".localhost")
        || host.parse::<std::net::IpAddr>().is_ok_and(|address| address.is_loopback())
}

pub(super) fn client_id_warnings(value: &str) -> Vec<String> {
    let Ok(url) = Url::parse(value) else { return Vec::new(); };
    let mut warnings = Vec::new();
    if url.path() == "/" { warnings.push("client_id URL path / is NOT RECOMMENDED (§3)".into()); }
    if url.query().is_some() {
        warnings.push("client_id URL SHOULD NOT contain a query string (§3)".into());
    }
    warnings
}
