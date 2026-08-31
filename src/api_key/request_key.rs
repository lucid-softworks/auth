use super::{ApiKeyConfiguration, ApiKeyGetterValue};
use crate::{AuthService, PluginRequestContext};
use axum::{extract::Request, http::HeaderMap};
use std::collections::BTreeMap;

const METHOD_HEADER: &str = "x-lucid-api-key-method";
const PATH_HEADER: &str = "x-lucid-api-key-path";
const QUERY_HEADER: &str = "x-lucid-api-key-query";

pub(super) fn context(service: &AuthService, request: &Request) -> PluginRequestContext {
    from_headers(
        request.method().as_str(),
        &relative_path(request.uri().path(), service.base_path()),
        request.uri().query(),
        request.headers(),
    )
}

pub(super) fn from_headers(
    method: &str,
    path: &str,
    query: Option<&str>,
    headers: &HeaderMap,
) -> PluginRequestContext {
    PluginRequestContext {
        method: method.into(),
        path: path.into(),
        query: query.map(str::to_owned),
        headers: public_headers(headers),
        body: None,
    }
}

pub(super) fn marked_context(headers: &HeaderMap) -> Option<PluginRequestContext> {
    Some(PluginRequestContext {
        method: headers.get(METHOD_HEADER)?.to_str().ok()?.to_owned(),
        path: headers.get(PATH_HEADER)?.to_str().ok()?.to_owned(),
        query: headers
            .get(QUERY_HEADER)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        headers: public_headers(headers),
        body: None,
    })
}

pub(super) fn mark(headers: &mut HeaderMap, context: &PluginRequestContext) {
    insert(headers, METHOD_HEADER, &context.method);
    insert(headers, PATH_HEADER, &context.path);
    headers.remove(QUERY_HEADER);
    if let Some(query) = &context.query {
        insert(headers, QUERY_HEADER, query);
    }
}

pub(super) fn find<'a>(
    configurations: &'a [ApiKeyConfiguration],
    context: &PluginRequestContext,
) -> Option<(&'a ApiKeyConfiguration, ApiKeyGetterValue)> {
    for configuration in configurations {
        if !configuration.enable_session_for_api_keys {
            continue;
        }
        let value = match &configuration.key_getter {
            Some(getter) => getter.get(context),
            None => configuration
                .headers
                .iter()
                .find_map(|header| {
                    context
                        .headers
                        .get(&header.to_ascii_lowercase())
                        .filter(|key| !key.is_empty())
                })
                .map_or(ApiKeyGetterValue::Missing, |key| {
                    ApiKeyGetterValue::Key(key.clone())
                }),
        };
        if matches!(&value, ApiKeyGetterValue::Invalid)
            || matches!(&value, ApiKeyGetterValue::Key(key) if !key.is_empty())
        {
            return Some((configuration, value));
        }
    }
    None
}

fn public_headers(headers: &HeaderMap) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter(|(name, _)| !matches!(name.as_str(), METHOD_HEADER | PATH_HEADER | QUERY_HEADER))
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.to_string(), value.to_owned()))
        })
        .collect()
}

fn insert(headers: &mut HeaderMap, name: &'static str, value: &str) {
    headers.remove(name);
    if let Ok(value) = value.parse() {
        headers.insert(name, value);
    }
}

fn relative_path(path: &str, base_path: &str) -> String {
    let base = base_path.trim_end_matches('/');
    if path == base {
        return "/".into();
    }
    path.strip_prefix(base)
        .filter(|relative| relative.starts_with('/'))
        .unwrap_or(path)
        .to_owned()
}
