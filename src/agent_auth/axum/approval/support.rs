#![allow(clippy::result_large_err)] // Axum responses are the deliberate error channel.

use super::error::{FlowError, Result};
use crate::{
    AgentAuthAuditEvent, AgentAuthAuditEventType, AgentAuthConfig, AgentAuthEvent,
    AgentAuthEventFields, AgentCapabilityConstraints, AgentCapabilityGrant, AgentCapabilityRequest,
    AgentGrantStatus, AgentGrantTtlContext, AgentIdentity,
};
use axum::http::StatusCode;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Duration, Utc};
use rand::RngExt as _;
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, HashMap};

use crate::agent_auth::axum::{AgentAuthState, auth};

pub(super) async fn scoped_auth(
    service: &crate::AuthService,
    state: &AgentAuthState,
    headers: &axum::http::HeaderMap,
    uri: &axum::http::Uri,
    method: &axum::http::Method,
    path: &'static str,
    body: Option<&str>,
) -> std::result::Result<auth::ScopedAgentAuthentication, axum::response::Response> {
    let base_url = super::super::issuer(service, headers);
    let url = auth::request_url(service, headers, uri);
    let request = auth::AgentRequestContext {
        path,
        method: method.as_str(),
        base_url: &base_url,
        url: &url,
        headers,
        serialized_body: body,
    };
    auth::authenticate_scoped(service, state, request)
        .await
        .map_err(|error| auth::error_response(error, &base_url))
}

pub(super) const APPROVAL_EXPIRES_IN: i64 = 300;
pub(super) const APPROVAL_INTERVAL: f64 = 5.0;

pub(super) async fn emit(
    config: &AgentAuthConfig,
    event_type: AgentAuthAuditEventType,
    fields: AgentAuthEventFields,
) {
    super::super::events::emit(
        config,
        AgentAuthEvent::Audit(Box::new(AgentAuthAuditEvent {
            r#type: event_type,
            fields,
        })),
    );
}

pub(super) fn validate_nonempty<T>(values: &[T]) -> Result<()> {
    if values.is_empty() {
        return Err(FlowError::code(
            StatusCode::BAD_REQUEST,
            crate::AgentAuthErrorCode::InvalidRequest,
        ));
    }
    Ok(())
}

pub(super) fn validate_positive(value: Option<f64>) -> Result<()> {
    if value.is_some_and(|value| !value.is_finite() || value <= 0.0) {
        return Err(FlowError::code(
            StatusCode::BAD_REQUEST,
            crate::AgentAuthErrorCode::InvalidRequest,
        ));
    }
    Ok(())
}

pub(super) fn normalize_requests(
    values: &[AgentCapabilityRequest],
) -> Vec<(String, Option<AgentCapabilityConstraints>)> {
    crate::normalize_capability_requests(values)
}

pub(super) async fn validate_capabilities(
    config: &AgentAuthConfig,
    requested: &[(String, Option<AgentCapabilityConstraints>)],
    blocked_code: crate::AgentAuthErrorCode,
) -> Result<()> {
    let ids = requested
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    let blocked =
        crate::agent_auth::policy::find_blocked_capabilities(&ids, &config.blocked_capabilities);
    if !blocked.is_empty() {
        return Err(
            if blocked_code == crate::AgentAuthErrorCode::CapabilityBlocked {
                FlowError::message(
                    StatusCode::BAD_REQUEST,
                    blocked_code,
                    format!("Blocked capabilities: {}", blocked.join(", ")),
                )
            } else {
                FlowError::code(StatusCode::BAD_REQUEST, blocked_code)
            },
        );
    }
    if !config.capabilities.is_empty() {
        let unknown = ids
            .iter()
            .filter(|name| {
                !config
                    .capabilities
                    .iter()
                    .any(|item| item.name == name.as_str())
            })
            .cloned()
            .collect::<Vec<_>>();
        if !unknown.is_empty() {
            return Err(FlowError::with_extra(
                StatusCode::BAD_REQUEST,
                crate::AgentAuthErrorCode::InvalidCapabilities,
                "invalid_capabilities",
                json!(unknown),
            ));
        }
    }
    if let Some(validator) = &config.validate_capabilities
        && !validator.validate(ids).await
    {
        return Err(FlowError::code(
            StatusCode::BAD_REQUEST,
            crate::AgentAuthErrorCode::InvalidCapabilities,
        ));
    }
    Ok(())
}

pub(super) fn validate_required_constraints(
    config: &AgentAuthConfig,
    requested: &[(String, Option<AgentCapabilityConstraints>)],
) -> Result<()> {
    for (name, constraints) in requested {
        let Some(definition) = config.capabilities.iter().find(|item| item.name == *name) else {
            continue;
        };
        let required = definition
            .required_constraints
            .as_deref()
            .unwrap_or_default();
        if required.is_empty() {
            continue;
        }
        let Some(constraints) = constraints else {
            return Err(FlowError::message(
                StatusCode::BAD_REQUEST,
                crate::AgentAuthErrorCode::InvalidRequest,
                format!(
                    "Capability \"{name}\" requires constraints on: {}. Request it as: {{ name: \"{name}\", constraints: {{ {} }} }}",
                    required.join(", "),
                    required
                        .iter()
                        .map(|field| format!("{field}: ..."))
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
        };
        let missing = required
            .iter()
            .filter(|field| !constraints.contains_key(field.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(FlowError::message(
                StatusCode::BAD_REQUEST,
                crate::AgentAuthErrorCode::InvalidRequest,
                format!(
                    "Capability \"{name}\" is missing required constraint fields: {}.",
                    missing.join(", ")
                ),
            ));
        }
    }
    Ok(())
}

pub(super) async fn expires_at(
    config: &AgentAuthConfig,
    capability: &str,
    agent: &AgentIdentity,
    explicit: Option<f64>,
) -> Option<DateTime<Utc>> {
    let ttl = if explicit.is_some_and(|value| value > 0.0) {
        explicit.map(|value| value as u64)
    } else if let Some(resolver) = &config.resolve_grant_ttl {
        resolver
            .resolve(AgentGrantTtlContext {
                capability: capability.to_owned(),
                agent_id: agent.id.clone(),
                host_id: Some(agent.host_id.clone()),
                user_id: agent.user_id.clone(),
            })
            .await
    } else {
        config
            .capabilities
            .iter()
            .find(|item| item.name == capability)
            .and_then(|item| item.grant_ttl)
    };
    ttl.filter(|ttl| *ttl > 0)
        .map(|ttl| Utc::now() + Duration::seconds(ttl as i64))
}

pub(super) fn normalize_user_code(code: &str) -> String {
    let stripped = code
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .map(|character| character.to_ascii_uppercase())
        .collect::<String>();
    if stripped.len() == 8 {
        format!("{}-{}", &stripped[..4], &stripped[4..])
    } else {
        code.to_ascii_uppercase()
    }
}

pub(super) fn hash_token(token: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(token.as_bytes()))
}

pub(super) fn generate_user_code() -> String {
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::rng();
    let raw = (0..8)
        .map(|_| CHARS[rng.random_range(0..CHARS.len())] as char)
        .collect::<String>();
    format!("{}-{}", &raw[..4], &raw[4..])
}

pub(super) fn sanitize_display(value: Option<String>, limit: usize) -> Option<String> {
    value.map(|value| {
        let mut result = String::new();
        let mut in_tag = false;
        for character in value.chars() {
            match character {
                '<' => in_tag = true,
                '>' if in_tag => in_tag = false,
                _ if in_tag || character.is_control() => {}
                _ => result.push(character),
            }
        }
        result.trim().chars().take(limit).collect()
    })
}

pub(super) fn format_grants(grants: &[AgentCapabilityGrant], config: &AgentAuthConfig) -> Value {
    let priority = |status: AgentGrantStatus| match status {
        AgentGrantStatus::Active => 0,
        AgentGrantStatus::Pending => 1,
        AgentGrantStatus::Denied => 2,
        AgentGrantStatus::Revoked => 3,
        AgentGrantStatus::Consumed => 9,
    };
    let mut best = HashMap::<&str, &AgentCapabilityGrant>::new();
    for grant in grants
        .iter()
        .filter(|grant| grant.status != AgentGrantStatus::Consumed)
    {
        let replace = best.get(grant.capability.as_str()).is_none_or(|current| {
            priority(grant.status) < priority(current.status)
                || (priority(grant.status) == priority(current.status)
                    && grant.created_at > current.created_at)
        });
        if replace {
            best.insert(&grant.capability, grant);
        }
    }
    Value::Array(
        best.into_values()
            .map(|grant| {
                let mut value = Map::from_iter([
                    ("capability".into(), json!(grant.capability)),
                    ("status".into(), json!(grant.status.as_str())),
                ]);
                if grant.status == AgentGrantStatus::Active {
                    if let Some(granted_by) = grant.granted_by.as_ref() {
                        value.insert("granted_by".into(), json!(granted_by));
                    }
                    if let Some(constraints) = &grant.constraints {
                        value.insert("constraints".into(), json!(constraints));
                    }
                    if let Some(expires_at) = grant.expires_at {
                        value.insert("expires_at".into(), json!(expires_at));
                    }
                    if let Some(definition) = config
                        .capabilities
                        .iter()
                        .find(|item| item.name == grant.capability)
                    {
                        value.insert("description".into(), json!(definition.description));
                        if let Some(input) = &definition.input {
                            value.insert("input".into(), json!(input));
                        }
                        if let Some(output) = &definition.output {
                            value.insert("output".into(), json!(output));
                        }
                    }
                } else if matches!(
                    grant.status,
                    AgentGrantStatus::Denied | AgentGrantStatus::Pending
                ) && let Some(reason) = &grant.reason
                {
                    value.insert("reason".into(), json!(reason));
                }
                Value::Object(value)
            })
            .collect(),
    )
}

pub(super) fn constraint_map(
    normalized: &[(String, Option<AgentCapabilityConstraints>)],
) -> BTreeMap<String, Option<AgentCapabilityConstraints>> {
    normalized.iter().cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_codes_match_upstream_normalization_and_hashing() {
        assert_eq!(normalize_user_code("abcd 2345"), "ABCD-2345");
        assert_eq!(normalize_user_code("abc"), "ABC");
        assert_eq!(hash_token("ABCD-2345").len(), 43);
        let code = generate_user_code();
        assert_eq!(code.len(), 9);
        assert_eq!(code.as_bytes()[4], b'-');
    }

    #[test]
    fn sanitization_removes_tags_controls_and_applies_character_limit() {
        assert_eq!(
            sanitize_display(Some(" <b>Hello</b>\u{7} world ".into()), 8).as_deref(),
            Some("Hello wo")
        );
    }
}
