use crate::OAuthProviderError;
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn singleton<'a>(
    parameters: &'a BTreeMap<String, Vec<String>>,
    name: &str,
) -> Result<Option<&'a str>, OAuthProviderError> {
    let values = parameters
        .get(name)
        .into_iter()
        .flatten()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if values.len() > 1 {
        return Err(OAuthProviderError::InvalidRequest(format!(
            "{name} must not be repeated"
        )));
    }
    Ok(values.first().map(|value| value.as_str()))
}

pub(super) fn nonempty_values(
    parameters: &BTreeMap<String, Vec<String>>,
    name: &str,
) -> Option<Vec<String>> {
    let values = parameters
        .get(name)?
        .iter()
        .filter(|value| !value.is_empty())
        .cloned()
        .collect::<Vec<_>>();
    (!values.is_empty()).then_some(values)
}

pub(super) fn string_parameters(
    parameters: &BTreeMap<String, Vec<Value>>,
) -> Result<BTreeMap<String, Vec<String>>, OAuthProviderError> {
    const OAUTH_FIELDS: &[&str] = &[
        "client_secret",
        "client_assertion",
        "client_assertion_type",
        "resource",
    ];
    let mut strings = BTreeMap::new();
    let mut invalid_fields = Vec::new();
    for (name, values) in parameters {
        if name == "resource" && values.is_empty() {
            invalid_fields.push("resource");
        }
        let mut converted = Vec::new();
        for value in values {
            match value {
                Value::String(value) => converted.push(value.clone()),
                _ if OAUTH_FIELDS.contains(&name.as_str()) => invalid_fields.push(name.as_str()),
                _ => {}
            }
        }
        if !converted.is_empty() {
            strings.insert(name.clone(), converted);
        }
    }
    if invalid_fields.iter().all(|field| *field == "resource") && !invalid_fields.is_empty() {
        return Err(OAuthProviderError::InvalidTarget(
            "Invalid resource indicator".into(),
        ));
    }
    if let Some(field) = invalid_fields.first() {
        return Err(OAuthProviderError::InvalidRequest(format!(
            "{field} must be a string"
        )));
    }
    Ok(strings)
}

pub(super) fn has_client_authentication(
    headers: &axum::http::HeaderMap,
    parameters: &BTreeMap<String, Vec<String>>,
) -> bool {
    headers.contains_key(axum::http::header::AUTHORIZATION)
        || ["client_secret", "client_assertion", "client_assertion_type"]
            .iter()
            .any(|field| {
                parameters
                    .get(*field)
                    .is_some_and(|values| values.iter().any(|value| !value.is_empty()))
            })
}

pub(super) fn header_parameters(headers: &axum::http::HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect()
}

pub(super) fn split_scopes(scope: Option<&str>) -> Vec<String> {
    scope
        .unwrap_or_default()
        .split_whitespace()
        .map(str::to_owned)
        .collect()
}
