#![allow(clippy::result_large_err)] // Axum responses are the deliberate error channel.

use super::super::{
    AgentAuthState, auth,
    input::{AgentInput, AgentQuery, Field, FieldKind},
};
use crate::{AgentCapability, AgentHostSession, AgentSession, AuthService};
use axum::{
    Extension, Json,
    extract::OriginalUri,
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::sync::Arc;

#[derive(Debug, Default, Deserialize)]
pub(in crate::agent_auth::axum) struct ListQuery {
    query: Option<String>,
    cursor: Option<String>,
    limit: Option<f64>,
}

impl AgentInput for ListQuery {
    const FIELDS: &'static [Field] = &[
        Field::optional("query", FieldKind::String { min: None }),
        Field::optional("cursor", FieldKind::String { min: None }),
        Field::optional(
            "limit",
            FieldKind::Number {
                coerce: true,
                min: None,
            },
        ),
    ];
}

#[derive(Debug, Deserialize)]
pub(in crate::agent_auth::axum) struct DescribeQuery {
    name: String,
}

impl AgentInput for DescribeQuery {
    const FIELDS: &'static [Field] = &[Field::required("name", FieldKind::String { min: None })];
}

pub(in crate::agent_auth::axum) async fn list(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    AgentQuery(query): AgentQuery<ListQuery>,
) -> Response {
    let sessions = match sessions(
        &service,
        &state,
        &headers,
        &uri,
        &method,
        "/capability/list",
    )
    .await
    {
        Ok(sessions) => sessions,
        Err(response) => return response,
    };
    if state.config.require_auth_for_capabilities && !sessions.authenticated() {
        return authentication_required(&service, &headers);
    }
    let mut capabilities = state.config.capabilities.clone();
    if let Some(resolver) = &state.config.resolve_capabilities {
        capabilities = resolver
            .resolve(crate::AgentResolveCapabilitiesContext {
                capabilities,
                query: query.query.clone(),
                agent_session: sessions.agent.clone(),
                host_session: sessions.host.clone(),
            })
            .await;
    }
    if let Some(search) = query.query.as_deref()
        && state.config.resolve_capabilities.is_none()
    {
        capabilities = if let Some(resolver) = &state.config.resolve_query {
            resolver.resolve(search.to_owned(), capabilities).await
        } else {
            super::search::match_query(search, capabilities)
        };
    }
    if capabilities.is_empty() {
        return Json(json!({"capabilities": [], "has_more": false})).into_response();
    }
    let cursor = query.cursor.as_deref().map(parse_int).unwrap_or(0.0);
    let limit = query.limit.unwrap_or(100.0);
    let end = cursor + limit;
    let (start_index, end_index) = slice_range(cursor, end, capabilities.len());
    let page = capabilities[start_index..end_index].iter();
    let has_more = end < capabilities.len() as f64;
    let mut body = Map::from_iter([
        (
            "capabilities".into(),
            Value::Array(
                page.map(|capability| summary(capability, &sessions))
                    .collect(),
            ),
        ),
        ("has_more".into(), Value::Bool(has_more)),
    ]);
    if has_more {
        body.insert("next_cursor".into(), Value::String(js_number_string(end)));
    }
    cached_json(Value::Object(body), sessions.cache_control())
}

fn parse_int(value: &str) -> f64 {
    let value = value.trim_start();
    let (sign, digits) = match value.as_bytes().first() {
        Some(b'-') => (-1.0, &value[1..]),
        Some(b'+') => (1.0, &value[1..]),
        _ => (1.0, value),
    };
    let digits: String = digits.chars().take_while(char::is_ascii_digit).collect();
    if digits.is_empty() {
        f64::NAN
    } else {
        sign * digits.parse::<f64>().unwrap_or(f64::INFINITY)
    }
}

fn slice_range(start: f64, end: f64, len: usize) -> (usize, usize) {
    let start = relative_index(start, len);
    let end = relative_index(end, len).max(start);
    (start, end)
}

fn relative_index(value: f64, len: usize) -> usize {
    let value = if value.is_nan() { 0.0 } else { value.trunc() };
    if value < 0.0 {
        (len as f64 + value).max(0.0) as usize
    } else {
        value.min(len as f64) as usize
    }
}

fn js_number_string(value: f64) -> String {
    if value.fract() == 0.0 {
        format!("{value:.0}")
    } else {
        value.to_string()
    }
}

pub(in crate::agent_auth::axum) async fn describe(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    AgentQuery(query): AgentQuery<DescribeQuery>,
) -> Response {
    let sessions = match sessions(
        &service,
        &state,
        &headers,
        &uri,
        &method,
        "/capability/describe",
    )
    .await
    {
        Ok(sessions) => sessions,
        Err(response) => return response,
    };
    if state.config.require_auth_for_capabilities && !sessions.authenticated() {
        return authentication_required(&service, &headers);
    }
    let mut capabilities = state.config.capabilities.clone();
    if let Some(resolver) = &state.config.resolve_capabilities {
        capabilities = resolver
            .resolve(crate::AgentResolveCapabilitiesContext {
                capabilities,
                query: None,
                agent_session: sessions.agent.clone(),
                host_session: sessions.host.clone(),
            })
            .await;
    }
    let Some(capability) = capabilities
        .iter()
        .find(|capability| capability.name == query.name)
    else {
        return error(
            StatusCode::NOT_FOUND,
            "capability_not_found",
            format!("Capability \"{}\" does not exist.", query.name),
        );
    };
    let mut body = serde_json::to_value(capability)
        .expect("Agent Auth capability serializes")
        .as_object()
        .cloned()
        .unwrap_or_default();
    body.remove("grant_status");
    if let Some(strength) = body.remove("approvalStrength") {
        body.insert("approval_strength".into(), strength);
    }
    if let Some(granted) = sessions.granted(&capability.name) {
        body.insert(
            "grant_status".into(),
            Value::String(if granted { "granted" } else { "not_granted" }.into()),
        );
    }
    cached_json(Value::Object(body), sessions.cache_control())
}

#[derive(Default)]
struct Sessions {
    agent: Option<AgentSession>,
    host: Option<AgentHostSession>,
}

impl Sessions {
    fn authenticated(&self) -> bool {
        self.agent.is_some() || self.host.is_some()
    }

    fn cache_control(&self) -> &'static str {
        if self.authenticated() {
            "private, max-age=300"
        } else {
            "public, max-age=300"
        }
    }

    fn granted(&self, capability: &str) -> Option<bool> {
        if let Some(agent) = &self.agent {
            return Some(
                agent
                    .agent
                    .capability_grants
                    .iter()
                    .any(|grant| grant.capability == capability && grant.status == "active"),
            );
        }
        self.host.as_ref().map(|host| {
            host.host
                .default_capabilities
                .iter()
                .any(|granted| granted == capability)
        })
    }
}

async fn sessions(
    service: &AuthService,
    state: &AgentAuthState,
    headers: &HeaderMap,
    uri: &axum::http::Uri,
    method: &Method,
    path: &'static str,
) -> Result<Sessions, Response> {
    let base_url = super::super::issuer(service, headers);
    let url = auth::request_url(service, headers, uri);
    let request = auth::AgentRequestContext {
        path,
        method: method.as_str(),
        base_url: &base_url,
        url: &url,
        headers,
        serialized_body: None,
    };
    match auth::authenticate_scoped(service, state, request).await {
        Ok(auth::ScopedAgentAuthentication::Agent(session)) => Ok(Sessions {
            agent: Some(*session),
            host: None,
        }),
        Ok(auth::ScopedAgentAuthentication::Host(session)) => Ok(Sessions {
            agent: None,
            host: Some(session),
        }),
        Ok(auth::ScopedAgentAuthentication::NotApplicable) => Ok(Sessions::default()),
        Err(error) => Err(auth::error_response(error, &base_url)),
    }
}

fn summary(capability: &AgentCapability, sessions: &Sessions) -> Value {
    let mut entry = Map::from_iter([
        ("name".into(), json!(capability.name)),
        ("description".into(), json!(capability.description)),
    ]);
    if let Some(location) = &capability.location {
        entry.insert("location".into(), json!(location));
    }
    if let Some(strength) = capability.approval_strength {
        entry.insert("approval_strength".into(), json!(strength));
    }
    if let Some(granted) = sessions.granted(&capability.name) {
        entry.insert(
            "grant_status".into(),
            Value::String(if granted { "granted" } else { "not_granted" }.into()),
        );
    }
    if let Some(properties) = capability
        .input
        .as_ref()
        .and_then(|input| input.get("properties"))
        .and_then(Value::as_object)
    {
        entry.insert(
            "input_fields".into(),
            Value::Array(
                properties
                    .iter()
                    .map(|(name, property)| {
                        json!({
                            "name": name,
                            "type": property.get("type").cloned().unwrap_or(Value::Null),
                            "description": property
                                .get("description")
                                .cloned()
                                .unwrap_or(Value::Null),
                        })
                    })
                    .collect(),
            ),
        );
    }
    Value::Object(entry)
}

fn authentication_required(service: &AuthService, headers: &HeaderMap) -> Response {
    let mut response = error(
        StatusCode::UNAUTHORIZED,
        "authentication_required",
        "This server requires authentication to list capabilities. Connect an agent first, then retry with the agent JWT.",
    );
    let base_url = super::super::issuer(service, headers);
    if let Ok(challenge) = crate::agent_auth_challenge(&base_url)
        && let Ok(value) = axum::http::HeaderValue::from_str(&challenge)
    {
        response
            .headers_mut()
            .insert(axum::http::header::WWW_AUTHENTICATE, value);
    }
    response
}

fn error(status: StatusCode, code: &str, message: impl Into<String>) -> Response {
    (
        status,
        Json(json!({"error": code, "message": message.into()})),
    )
        .into_response()
}

fn cached_json(body: Value, cache_control: &'static str) -> Response {
    let mut response = Json(body).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static(cache_control),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_and_limit_follow_javascript_number_coercion() {
        assert_eq!(parse_int("  -2items"), -2.0);
        assert!(parse_int("items").is_nan());
        assert_eq!(slice_range(-2.0, 1.0, 5), (3, 3));
        assert_eq!(slice_range(f64::NAN, f64::NAN, 5), (0, 0));
    }
}
