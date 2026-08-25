use super::error::{HostError, store_error};
use crate::{
    AgentHost, AgentHostStatus, AuthService,
    agent_auth::{
        axum::{AgentAuthState, issuer},
        jwt::{
            AgentAudience, AgentJwtKeySource, AgentJwtKind, AgentJwtVerifier,
            AgentJwtVerifyOptions, decode_agent_jwt,
        },
    },
};
use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use serde_json::Value;
use std::{sync::Arc, time::Duration};

#[derive(Clone)]
pub(in crate::agent_auth::axum) struct HostAuthState {
    verifier: Arc<AgentJwtVerifier>,
}

impl HostAuthState {
    pub(in crate::agent_auth::axum) fn from_verifier(verifier: Arc<AgentJwtVerifier>) -> Self {
        Self { verifier }
    }
}

pub(super) async fn host_authorization(
    service: &AuthService,
    state: &AgentAuthState,
    auth: &HostAuthState,
    headers: &HeaderMap,
    skip_replay_check: bool,
) -> Result<Option<AgentHost>, HostError> {
    let Some(token) = bearer(headers) else {
        return Ok(None);
    };
    let decoded = decode_agent_jwt(token).map_err(|_| HostError::invalid_jwt())?;
    if decoded.header.typ != "host+jwt" {
        return Err(HostError::invalid_jwt());
    }
    let host_id = decoded
        .claims
        .issuer
        .as_deref()
        .ok_or_else(HostError::invalid_jwt)?;
    let host = match state.store.find_host(host_id).await.map_err(store_error)? {
        Some(host) => host,
        None if skip_replay_check => state
            .store
            .find_host_by_kid(host_id)
            .await
            .map_err(store_error)?
            .ok_or_else(HostError::agent_not_found)?,
        None => return Err(HostError::host_not_found()),
    };
    if host.status == AgentHostStatus::Revoked {
        return Err(HostError::host_revoked());
    }
    if host.public_key.as_deref().unwrap_or_default().is_empty() && host.jwks_url.is_none() {
        return Err(HostError::host_revoked());
    }
    let inline = host
        .public_key
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(serde_json::from_str::<Value>)
        .transpose()
        .map_err(|_| HostError::invalid_public_key())?;
    let base_url = issuer(service, headers);
    auth.verifier
        .verify(
            token,
            AgentJwtKeySource {
                inline_public_jwk: inline.as_ref(),
                jwks_url: host.jwks_url.as_deref(),
            },
            AgentJwtVerifyOptions {
                kind: AgentJwtKind::Host,
                allowed_key_algorithms: &state.config.allowed_key_algorithms,
                max_age: Duration::from_secs(state.config.jwt_max_age),
                audience: AgentAudience::new(
                    &base_url,
                    headers.get("host").and_then(|value| value.to_str().ok()),
                    headers
                        .get("x-forwarded-proto")
                        .and_then(|value| value.to_str().ok()),
                    state.config.trust_proxy,
                    None,
                ),
                require_audience: true,
                expected_issuer: Some(&host.id),
                request: None,
                replay_partition: Some(&format!("host:{}", host.id)),
                skip_replay_check: skip_replay_check || state.config.dangerously_skip_jti_check,
                now: Utc::now(),
            },
        )
        .await
        .map_err(map_jwt_error)?;
    Ok(Some(host))
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get("authorization")?.to_str().ok()?;
    value
        .get(..7)
        .filter(|prefix| prefix.eq_ignore_ascii_case("bearer "))?;
    value.get(7..).filter(|token| !token.is_empty())
}

fn map_jwt_error(error: crate::agent_auth::jwt::AgentJwtError) -> HostError {
    match error {
        crate::agent_auth::jwt::AgentJwtError::Replay => HostError::new(
            StatusCode::UNAUTHORIZED,
            "jti_replay",
            "JWT has already been used",
        ),
        crate::agent_auth::jwt::AgentJwtError::UnsupportedAlgorithm
        | crate::agent_auth::jwt::AgentJwtError::InvalidPublicKey => {
            HostError::invalid_public_key()
        }
        _ => HostError::invalid_jwt(),
    }
}
