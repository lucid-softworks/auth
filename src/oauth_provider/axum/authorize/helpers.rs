use axum::{
    Json,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde_json::Value;
use std::collections::BTreeSet;

use crate::{AuthService, OAuthProviderError};

use super::{AuthorizationInput, OAuthAuthorizationQuery};
use crate::oauth_provider::{
    OAuthCallbackContext, OAuthProviderClient, OAuthProviderConfig, OAuthProviderStore,
    crypto::constant_time_equal,
};

pub(super) fn redirect(headers: &HeaderMap, location: &str) -> Response {
    let browser_fetch = headers
        .get("sec-fetch-mode")
        .and_then(|value| value.to_str().ok())
        == Some("cors");
    let accepts_json = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("application/json"));
    if browser_fetch || accepts_json {
        return Json(serde_json::json!({
            "redirect": true,
            "url": location,
        }))
        .into_response();
    }
    let mut response = StatusCode::FOUND.into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    if let Ok(value) = HeaderValue::from_str(location) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}

pub(super) fn validate_pkce<'a>(
    client: &OAuthProviderClient,
    query: &'a OAuthAuthorizationQuery,
    scopes: &[String],
) -> Result<(), &'a str> {
    let required = if client.token_endpoint_auth_method.as_deref() == Some("none") {
        Some("pkce is required for public clients")
    } else if scopes.iter().any(|scope| scope == "offline_access")
        && !(scopes.iter().any(|scope| scope == "openid")
            && query.nonce.as_ref().is_some_and(|nonce| !nonce.is_empty()))
    {
        Some("pkce or OIDC nonce is required when requesting offline_access scope")
    } else if client.require_pkce.unwrap_or(true) {
        Some("pkce is required for this client")
    } else {
        None
    };
    if let Some(reason) = required
        && (query.code_challenge.is_none() || query.code_challenge_method.is_none())
    {
        return Err(reason);
    }
    if query.code_challenge.is_some() != query.code_challenge_method.is_some() {
        return Err("code_challenge and code_challenge_method must both be provided");
    }
    if query
        .code_challenge_method
        .as_deref()
        .is_some_and(|method| method != "S256")
    {
        return Err("invalid code_challenge method, only S256 is supported");
    }
    Ok(())
}

pub(super) async fn validate_resources(
    config: &OAuthProviderConfig,
    store: &dyn OAuthProviderStore,
    client: &OAuthProviderClient,
    resources: &[String],
    scopes: &[String],
) -> Result<(), OAuthProviderError> {
    if resources.is_empty() {
        return Ok(());
    }
    let links = if config.enforce_per_client_resources {
        store
            .list_oauth_client_resources(&client.client_id)
            .await
            .map_err(storage_error)?
    } else {
        Vec::new()
    };
    for identifier in resources {
        let resource = store
            .find_oauth_resource(identifier)
            .await
            .map_err(storage_error)?
            .filter(|resource| !resource.disabled)
            .ok_or_else(|| {
                OAuthProviderError::InvalidRequest("requested resource invalid".into())
            })?;
        if config.enforce_per_client_resources && !resource_is_linked(&links, &resource) {
            return Err(OAuthProviderError::InvalidRequest(
                "requested resource invalid".into(),
            ));
        }
        if let Some(allowed) = &resource.allowed_scopes
            && !scopes.iter().any(|scope| allowed.contains(scope))
        {
            return Err(OAuthProviderError::InvalidScope(
                "requested scopes are not allowed for the resource".into(),
            ));
        }
    }
    Ok(())
}

fn resource_is_linked(
    links: &[crate::OAuthProviderClientResource],
    resource: &crate::OAuthProviderResource,
) -> bool {
    links
        .iter()
        .any(|link| link.resource_id == resource.identifier)
}

pub(super) fn client_allows_grant(client: &OAuthProviderClient, grant: &str) -> bool {
    client
        .grant_types
        .as_ref()
        .is_none_or(|grants| grants.iter().any(|candidate| candidate == grant))
}

pub(super) fn registered_redirect_matches(registered: &[String], requested: &str) -> bool {
    if registered.iter().any(|candidate| candidate == requested) {
        return true;
    }
    let Ok(requested) = url::Url::parse(requested) else {
        return false;
    };
    registered.iter().any(|candidate| {
        let Ok(candidate) = url::Url::parse(candidate) else {
            return false;
        };
        loopback_host(candidate.host_str())
            && candidate.host_str() == requested.host_str()
            && candidate.scheme() == requested.scheme()
            && candidate.path() == requested.path()
            && candidate.query() == requested.query()
    })
}

fn loopback_host(host: Option<&str>) -> bool {
    match host {
        Some("::1") | Some("[::1]") => true,
        Some(host) => host
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|address| address.octets()[0] == 127),
        None => false,
    }
}

pub(super) fn callback_context(
    headers: &HeaderMap,
    session: &crate::SessionWithUser,
    scopes: &[String],
) -> OAuthCallbackContext {
    OAuthCallbackContext {
        headers: headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.to_string(), value.to_owned()))
            })
            .collect(),
        user: serde_json::to_value(&session.user).ok(),
        session: serde_json::to_value(&session.session).ok(),
        scopes: scopes.to_vec(),
    }
}

pub(super) fn signed_query(
    service: &AuthService,
    config: &OAuthProviderConfig,
    query: &OAuthAuthorizationQuery,
) -> String {
    let mut pairs = query_pairs(query);
    let issued_at = Utc::now().timestamp_millis();
    pairs.push(("ba_iat".into(), issued_at.to_string()));
    pairs.push((
        "exp".into(),
        (issued_at / 1_000 + config.code_expires_in as i64).to_string(),
    ));
    let names = pairs
        .iter()
        .map(|(name, _)| name.clone())
        .chain(std::iter::once("ba_param".into()))
        .collect::<BTreeSet<_>>();
    pairs.extend(names.into_iter().map(|name| ("ba_param".into(), name)));
    let canonical = encode_sorted(&pairs);
    pairs.push((
        "sig".into(),
        service.sign_oauth_provider_value(canonical.as_bytes()),
    ));
    encode_pairs(&pairs)
}

pub(super) struct VerifiedSignedQuery {
    pub(super) query: OAuthAuthorizationQuery,
    pub(super) issued_at_ms: Option<i64>,
}

pub(super) fn verified_signed_query(
    service: &AuthService,
    raw: &str,
) -> Result<VerifiedSignedQuery, OAuthProviderError> {
    let mut pairs = url::form_urlencoded::parse(raw.as_bytes())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect::<Vec<_>>();
    let signatures = pairs
        .iter()
        .filter(|(name, _)| name == "sig")
        .map(|(_, value)| value.clone())
        .collect::<Vec<_>>();
    pairs.retain(|(name, _)| name != "sig");
    let expected = service.sign_oauth_provider_value(encode_sorted(&pairs).as_bytes());
    let expires = pairs
        .iter()
        .find(|(name, _)| name == "exp")
        .and_then(|(_, value)| value.parse::<i64>().ok())
        .unwrap_or_default();
    let issued_at_ms = pairs
        .iter()
        .find(|(name, _)| name == "ba_iat")
        .and_then(|(_, value)| value.parse::<i64>().ok())
        .filter(|value| *value > 0);
    if signatures.len() != 1
        || !constant_time_equal(signatures[0].as_bytes(), expected.as_bytes())
        || expires < Utc::now().timestamp()
    {
        return Err(OAuthProviderError::InvalidRequest(
            "invalid_signature".into(),
        ));
    }
    let signed_names = pairs
        .iter()
        .filter(|(name, _)| name == "ba_param")
        .map(|(_, value)| value.clone())
        .collect::<BTreeSet<_>>();
    let filtered = pairs
        .into_iter()
        .filter(|(name, _)| {
            !matches!(name.as_str(), "ba_param" | "ba_iat" | "ba_pl" | "exp")
                && signed_names.contains(name.as_str())
        })
        .collect::<Vec<_>>();
    let input: AuthorizationInput = serde_urlencoded::from_str(&encode_pairs(&filtered))
        .map_err(|_| OAuthProviderError::InvalidRequest("invalid oauth_query".into()))?;
    input.into_query().map(|query| VerifiedSignedQuery {
        query,
        issued_at_ms,
    })
}

fn query_pairs(query: &OAuthAuthorizationQuery) -> Vec<(String, String)> {
    let value = serde_json::to_value(query).unwrap_or(Value::Null);
    let Some(object) = value.as_object() else {
        return Vec::new();
    };
    let mut pairs = Vec::new();
    for (name, value) in object {
        match value {
            Value::Null => {}
            Value::Array(values) => {
                pairs.extend(values.iter().filter_map(|value| {
                    value.as_str().map(|value| (name.clone(), value.to_owned()))
                }))
            }
            Value::String(value) => pairs.push((name.clone(), value.clone())),
            Value::Number(value) => pairs.push((name.clone(), value.to_string())),
            other => pairs.push((name.clone(), other.to_string())),
        }
    }
    pairs
}

fn encode_sorted(pairs: &[(String, String)]) -> String {
    let mut pairs = pairs.to_vec();
    pairs.sort();
    encode_pairs(&pairs)
}

fn encode_pairs(pairs: &[(String, String)]) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (name, value) in pairs {
        serializer.append_pair(name, value);
    }
    serializer.finish()
}

pub(super) fn split_scopes(value: &str) -> Vec<String> {
    value.split_ascii_whitespace().map(str::to_owned).collect()
}

pub(super) fn storage_error(error: impl std::fmt::Display) -> OAuthProviderError {
    OAuthProviderError::ServerError(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn resource_links_compare_the_resource_identifier_not_its_row_id() {
        let resource = crate::OAuthProviderResource {
            id: Uuid::new_v4(),
            identifier: "https://api.example.com".into(),
            name: "API".into(),
            access_token_ttl: None,
            refresh_token_ttl: None,
            signing_algorithm: None,
            signing_key_id: None,
            allowed_scopes: None,
            custom_claims: None,
            dpop_bound_access_tokens_required: false,
            disabled: false,
            created_at: Some(Utc::now()),
            updated_at: Some(Utc::now()),
            policy_version: 1,
            metadata: None,
        };
        let link = crate::OAuthProviderClientResource {
            id: Uuid::new_v4(),
            client_id: "client".into(),
            resource_id: resource.identifier.clone(),
            metadata: None,
            created_at: Some(Utc::now()),
        };
        assert!(resource_is_linked(&[link], &resource));
    }
}
