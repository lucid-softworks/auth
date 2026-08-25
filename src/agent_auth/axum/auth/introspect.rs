use std::{sync::Arc, time::Duration};

use axum::{Extension, Json, http::HeaderMap};
use chrono::Utc;
use serde::Deserialize;

use super::super::input::{AgentInput, AgentJson, Field, FieldKind};
use super::{
    AgentAuthState, active_grants, expected_location, model::IntrospectionGrant,
    model::IntrospectionResponse, parse_optional_jwk,
};
use crate::{
    AgentStatus, AuthService,
    agent_auth::jwt::{
        AgentAudience, AgentJwtKeySource, AgentJwtKind, AgentJwtVerifyOptions, VerifiedAgentJwt,
        decode_agent_jwt,
    },
};

#[derive(Debug, Deserialize)]
pub(in crate::agent_auth::axum) struct IntrospectionRequest {
    token: String,
}

impl AgentInput for IntrospectionRequest {
    const FIELDS: &'static [Field] = &[Field::required("token", FieldKind::String { min: None })];
}

pub(in crate::agent_auth::axum) async fn introspect(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    headers: HeaderMap,
    AgentJson(body): AgentJson<IntrospectionRequest>,
) -> Json<IntrospectionResponse> {
    let base_url = super::issuer(&service, &headers);
    Json(
        introspect_token(&state, &headers, &base_url, &body.token)
            .await
            .unwrap_or_else(IntrospectionResponse::inactive),
    )
}

async fn introspect_token(
    state: &AgentAuthState,
    headers: &HeaderMap,
    base_url: &str,
    token: &str,
) -> Option<IntrospectionResponse> {
    let decoded = decode_agent_jwt(token).ok()?;
    if decoded.header.typ != "agent+jwt" {
        return None;
    }
    let agent_id = decoded.claims.subject.as_deref()?;
    let agent = state.store.find_agent(agent_id).await.ok()??;
    if agent.status != AgentStatus::Active {
        return None;
    }
    let inline = parse_optional_jwk(Some(&agent.public_key)).ok()?;
    if inline.is_none() && agent.jwks_url.is_none() {
        return None;
    }
    let expected_location = expected_location(state, &decoded);
    let replay_partition = decoded.claims.jti.as_ref().map(|_| agent.id.as_str());
    let verified = state
        .verifier
        .verify(
            token,
            AgentJwtKeySource {
                inline_public_jwk: inline.as_ref(),
                jwks_url: agent.jwks_url.as_deref(),
            },
            AgentJwtVerifyOptions {
                kind: AgentJwtKind::Agent,
                allowed_key_algorithms: &state.config.allowed_key_algorithms,
                max_age: Duration::from_secs(state.config.jwt_max_age),
                audience: AgentAudience::new(
                    base_url,
                    headers.get("host").and_then(|value| value.to_str().ok()),
                    headers
                        .get("x-forwarded-proto")
                        .and_then(|value| value.to_str().ok()),
                    state.config.trust_proxy,
                    expected_location,
                ),
                require_audience: false,
                expected_issuer: None,
                request: None,
                replay_partition,
                skip_replay_check: decoded.claims.jti.is_none(),
                now: Utc::now(),
            },
        )
        .await
        .ok()?;
    if agent
        .expires_at
        .is_some_and(|expires| expires <= Utc::now())
    {
        return None;
    }
    let mut grants = active_grants(state.store.list_grants(&agent.id).await.ok()?);
    if !verified.claims.capabilities.is_empty() {
        grants.retain(|grant| verified.claims.capabilities.contains(&grant.capability));
    }
    Some(active_response(agent, grants, verified))
}

fn active_response(
    agent: crate::AgentIdentity,
    grants: Vec<crate::AgentCapabilityGrant>,
    _verified: VerifiedAgentJwt,
) -> IntrospectionResponse {
    IntrospectionResponse::active(
        agent.id,
        agent.host_id,
        agent.user_id,
        grants.into_iter().map(IntrospectionGrant::from).collect(),
        agent.mode,
        agent.expires_at,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inactive_response_has_only_the_active_member() {
        assert_eq!(
            serde_json::to_value(IntrospectionResponse::inactive()).unwrap(),
            serde_json::json!({"active": false})
        );
    }
}
