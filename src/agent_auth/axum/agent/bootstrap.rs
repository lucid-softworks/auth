use super::error::AgentError;
use crate::{
    AgentDefaultHostCapabilitiesContext, AgentEndpointContext, AgentHost, AgentHostStatus,
    AgentMode, AgentStoreCreateOutcome,
    agent_auth::{
        axum::AgentAuthState,
        jwt::{
            AgentAudience, AgentJwtKeySource, AgentJwtKind, AgentJwtVerifyOptions, decode_agent_jwt,
        },
    },
};
use axum::http::{HeaderMap, StatusCode};
use chrono::Utc;
use serde_json::Value;
use std::{collections::BTreeMap, time::Duration};
use uuid::Uuid;

pub(super) struct Bootstrap {
    pub(super) host: AgentHost,
    pub(super) new_host: Option<AgentHost>,
    pub(super) claims: serde_json::Map<String, Value>,
}

struct HostResolution<'a> {
    headers: &'a HeaderMap,
    base_url: &'a str,
    path: &'a str,
    mode: AgentMode,
    body_host_name: Option<String>,
    token: &'a str,
    decoded: &'a crate::agent_auth::jwt::VerifiedAgentJwt,
    found: Option<AgentHost>,
}

pub(super) async fn verify(
    state: &AgentAuthState,
    headers: &HeaderMap,
    base_url: &str,
    path: &str,
    mode: AgentMode,
    body_host_name: Option<String>,
) -> Result<Bootstrap, AgentError> {
    let token = bearer(headers).ok_or_else(invalid_jwt)?;
    let decoded = decode_agent_jwt(token).map_err(|_| invalid_jwt())?;
    if decoded.header.typ != "host+jwt" {
        return Err(invalid_jwt());
    }
    let found = find_existing_host(state, decoded.claims.issuer.as_deref()).await?;
    let (host, is_new) = resolve_host(
        state,
        HostResolution {
            headers,
            base_url,
            path,
            mode,
            body_host_name,
            token,
            decoded: &decoded,
            found,
        },
    )
    .await?;
    persist_dynamic_host(state, path, &host, is_new).await?;
    Ok(Bootstrap {
        new_host: (is_new && path == "/agent/register").then(|| host.clone()),
        host,
        claims: decoded.claims.extra,
    })
}

async fn find_existing_host(
    state: &AgentAuthState,
    issuer: Option<&str>,
) -> Result<Option<AgentHost>, AgentError> {
    match issuer {
        Some(issuer) => Ok(state
            .store
            .find_host(issuer)
            .await
            .map_err(AgentError::store)?
            .or(state
                .store
                .find_host_by_kid(issuer)
                .await
                .map_err(AgentError::store)?)),
        None => Ok(None),
    }
}

async fn resolve_host(
    state: &AgentAuthState,
    request: HostResolution<'_>,
) -> Result<(AgentHost, bool), AgentError> {
    if let Some(existing) = request.found {
        validate_existing_host(request.decoded.claims.issuer.as_deref(), &existing)?;
        verify_token(
            state,
            request.headers,
            request.base_url,
            request.token,
            &existing,
        )
        .await?;
        Ok((existing, false))
    } else {
        dynamic_host(state, request).await
    }
}

fn validate_existing_host(issuer: Option<&str>, host: &AgentHost) -> Result<(), AgentError> {
    if issuer.is_none_or(|issuer| issuer != host.id && host.kid.as_deref() != Some(issuer)) {
        return Err(invalid_jwt());
    }
    if host.status == AgentHostStatus::Revoked
        || (host.public_key.as_deref().unwrap_or_default().is_empty() && host.jwks_url.is_none())
    {
        return Err(AgentError::new(
            StatusCode::FORBIDDEN,
            "host_revoked",
            "Host has been revoked",
        ));
    }
    if !matches!(
        host.status,
        AgentHostStatus::Active | AgentHostStatus::Pending
    ) {
        return Err(AgentError::new(
            StatusCode::FORBIDDEN,
            "host_expired",
            "Host session has expired",
        ));
    }
    Ok(())
}

async fn persist_dynamic_host(
    state: &AgentAuthState,
    path: &str,
    host: &AgentHost,
    is_new: bool,
) -> Result<(), AgentError> {
    if !is_new || path == "/agent/register" {
        return Ok(());
    }
    match state
        .store
        .create_host(host.clone())
        .await
        .map_err(AgentError::store)?
    {
        AgentStoreCreateOutcome::Created(_) => {}
        AgentStoreCreateOutcome::UniqueConflict => {
            return Err(AgentError::new(
                StatusCode::CONFLICT,
                "host_already_linked",
                "Host is already linked to a different user",
            ));
        }
    }
    Ok(())
}

async fn dynamic_host(
    state: &AgentAuthState,
    request: HostResolution<'_>,
) -> Result<(AgentHost, bool), AgentError> {
    let endpoint = endpoint(request.headers, request.base_url, request.path);
    let allowed = match &state.config.resolve_dynamic_host_registration {
        Some(resolve) => resolve.allow(endpoint.clone()).await,
        None => state.config.allow_dynamic_host_registration,
    };
    if !allowed {
        return Err(AgentError::new(
            StatusCode::FORBIDDEN,
            "dynamic_host_registration_disabled",
            "Dynamic host registration is disabled",
        ));
    }
    let mut host = ephemeral_host(request.decoded, request.mode)?;
    verify_token(
        state,
        request.headers,
        request.base_url,
        request.token,
        &host,
    )
    .await?;
    if let Some(public_key) = host.public_key.as_deref()
        && let Some(existing) = state
            .store
            .find_host_by_public_key(public_key)
            .await
            .map_err(AgentError::store)?
    {
        return Ok((existing, false));
    }
    host.id = Uuid::new_v4().to_string();
    host.name = request
        .decoded
        .claims
        .extra
        .get("host_name")
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or(request.body_host_name);
    host.default_capabilities = match &state.config.resolve_default_host_capabilities {
        Some(resolve) => {
            resolve
                .resolve(AgentDefaultHostCapabilitiesContext {
                    endpoint,
                    mode: request.mode,
                    user_id: None,
                    host_id: None,
                    host_name: host.name.clone(),
                })
                .await
        }
        None => state.config.default_host_capabilities.clone(),
    };
    Ok((host, true))
}

fn ephemeral_host(
    decoded: &crate::agent_auth::jwt::VerifiedAgentJwt,
    mode: AgentMode,
) -> Result<AgentHost, AgentError> {
    let key = decoded
        .claims
        .extra
        .get("host_public_key")
        .filter(|value| value.is_object())
        .cloned();
    let jwks_url = decoded
        .claims
        .extra
        .get("host_jwks_url")
        .and_then(Value::as_str)
        .map(str::to_owned);
    if key.is_none() && jwks_url.is_none() {
        return Err(invalid_jwt());
    }
    let now = Utc::now();
    Ok(AgentHost {
        id: decoded
            .claims
            .issuer
            .clone()
            .unwrap_or_else(|| "dynamic".into()),
        name: None,
        user_id: None,
        default_capabilities: Vec::new(),
        public_key: key
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|_| invalid_jwt())?,
        kid: key
            .as_ref()
            .and_then(|key| key.get("kid"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        jwks_url,
        enrollment_token_hash: None,
        enrollment_token_expires_at: None,
        status: if mode == AgentMode::Autonomous {
            AgentHostStatus::Active
        } else {
            AgentHostStatus::Pending
        },
        activated_at: (mode == AgentMode::Autonomous).then_some(now),
        expires_at: None,
        last_used_at: None,
        created_at: now,
        updated_at: now,
    })
}

async fn verify_token(
    state: &AgentAuthState,
    headers: &HeaderMap,
    base_url: &str,
    token: &str,
    host: &AgentHost,
) -> Result<(), AgentError> {
    let inline = host
        .public_key
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(serde_json::from_str::<Value>)
        .transpose()
        .map_err(|_| invalid_public_key())?;
    state
        .verifier
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
                    base_url,
                    headers.get("host").and_then(|value| value.to_str().ok()),
                    headers
                        .get("x-forwarded-proto")
                        .and_then(|value| value.to_str().ok()),
                    state.config.trust_proxy,
                    None,
                ),
                require_audience: true,
                expected_issuer: None,
                request: None,
                replay_partition: Some(&format!("host:{}", host.id)),
                skip_replay_check: state.config.dangerously_skip_jti_check,
                now: Utc::now(),
            },
        )
        .await
        .map_err(|error| match error {
            crate::agent_auth::jwt::AgentJwtError::Replay => AgentError::new(
                StatusCode::UNAUTHORIZED,
                "jti_replay",
                "JWT has already been used",
            ),
            crate::agent_auth::jwt::AgentJwtError::InvalidPublicKey
            | crate::agent_auth::jwt::AgentJwtError::UnsupportedAlgorithm => invalid_public_key(),
            _ => invalid_jwt(),
        })?;
    Ok(())
}

fn endpoint(headers: &HeaderMap, base_url: &str, path: &str) -> AgentEndpointContext {
    AgentEndpointContext {
        method: "POST".into(),
        path: path.into(),
        base_url: base_url.into(),
        headers: headers
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect::<BTreeMap<_, _>>(),
    }
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get("authorization")?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && token.split('.').count() == 3).then_some(token)
}

fn invalid_jwt() -> AgentError {
    AgentError::new(
        StatusCode::UNAUTHORIZED,
        "invalid_jwt",
        "JWT is invalid, expired, or signature failed",
    )
}

fn invalid_public_key() -> AgentError {
    AgentError::new(
        StatusCode::UNAUTHORIZED,
        "invalid_public_key",
        "Public key is invalid or malformed",
    )
}
