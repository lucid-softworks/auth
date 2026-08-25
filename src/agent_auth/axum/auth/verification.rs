use super::{AgentAuthState, AgentAuthenticationError, AgentRequestContext};
use crate::agent_auth::jwt::{
    AgentAudience, AgentBoundRequest, AgentJwtKind, AgentJwtVerifyOptions, VerifiedAgentJwt,
};
use chrono::Utc;
use serde_json::Value;
use std::time::Duration;

pub(super) fn verification_options<'a>(
    state: &'a AgentAuthState,
    request: &'a AgentRequestContext<'a>,
    kind: AgentJwtKind,
    expected_issuer: Option<&'a str>,
    replay_partition: Option<&'a str>,
    skip_request_binding: bool,
    expected_location: Option<&'a str>,
) -> AgentJwtVerifyOptions<'a> {
    AgentJwtVerifyOptions {
        kind,
        allowed_key_algorithms: &state.config.allowed_key_algorithms,
        max_age: Duration::from_secs(state.config.jwt_max_age),
        audience: audience(state, request, expected_location),
        require_audience: true,
        expected_issuer,
        request: (!skip_request_binding).then_some(AgentBoundRequest {
            method: request.method,
            url: request.url,
            serialized_body: request.serialized_body,
        }),
        replay_partition,
        skip_replay_check: state.config.dangerously_skip_jti_check,
        now: Utc::now(),
    }
}

fn audience<'a>(
    state: &'a AgentAuthState,
    request: &'a AgentRequestContext<'a>,
    expected_location: Option<&'a str>,
) -> AgentAudience<'a> {
    AgentAudience::new(
        request.base_url,
        request
            .headers
            .get("host")
            .and_then(|value| value.to_str().ok()),
        request
            .headers
            .get("x-forwarded-proto")
            .and_then(|value| value.to_str().ok()),
        state.config.trust_proxy,
        expected_location,
    )
}

pub(super) fn expected_location<'a>(
    state: &'a AgentAuthState,
    verified: &VerifiedAgentJwt,
) -> Option<&'a str> {
    (verified.claims.capabilities.len() == 1)
        .then(|| {
            state
                .config
                .capabilities
                .iter()
                .find(|capability| capability.name == verified.claims.capabilities[0])
                .and_then(|capability| capability.location.as_deref())
        })
        .flatten()
}

pub(super) fn parse_optional_jwk(
    value: Option<&str>,
) -> Result<Option<Value>, AgentAuthenticationError> {
    value
        .filter(|value| !value.is_empty())
        .map(|value| {
            serde_json::from_str::<Value>(value)
                .map_err(|_| AgentAuthenticationError::invalid_public_key())
        })
        .transpose()
}
