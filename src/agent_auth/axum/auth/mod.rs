mod error;
pub(in crate::agent_auth::axum) mod introspect;
mod lifecycle;
mod model;
mod session;
mod user;
mod verification;

use axum::{
    Extension,
    body::{Body, to_bytes},
    extract::State,
    http::{HeaderMap, Request},
    middleware::Next,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use serde_json::Value;

use super::{AgentAuthState, issuer};
use crate::{
    AgentHostStatus, AgentIdentity, AuthService,
    agent_auth::jwt::{AgentJwtKeySource, AgentJwtKind, VerifiedAgentJwt, decode_agent_jwt},
};

pub(super) use introspect::introspect;
pub(super) use session::session;

use error::AgentAuthenticationError;
pub(in crate::agent_auth::axum) use lifecycle::active_grants;
use lifecycle::{
    enforce_absolute_lifetime, heartbeat, needs_reactivation, transparent_reactivation,
    validate_agent_status,
};
use model::AuthenticatedAgent;
use user::resolve_autonomous_user;
use verification::{expected_location, parse_optional_jwk, verification_options};

const OPTIONAL_AUTH_PATHS: [&str; 2] = ["/capability/list", "/capability/describe"];
const UNAUTHENTICATED_PATHS: [&str; 2] = ["/agent/register", "/agent/claim"];

pub(super) struct AgentRequestContext<'a> {
    pub path: &'a str,
    pub method: &'a str,
    pub base_url: &'a str,
    pub url: &'a str,
    pub headers: &'a HeaderMap,
    pub serialized_body: Option<&'a str>,
}

pub(super) enum ScopedAgentAuthentication {
    NotApplicable,
    Host(crate::AgentHostSession),
    Agent(Box<crate::AgentSession>),
}

pub(super) async fn validate_before_hook(
    State(state): State<AgentAuthState>,
    Extension(service): Extension<std::sync::Arc<AuthService>>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let path = request
        .uri()
        .path()
        .strip_prefix(service.base_path())
        .unwrap_or_else(|| request.uri().path())
        .to_owned();
    if scoped_bearer(&path, request.headers()).is_none() {
        return next.run(request).await;
    }
    let bytes = match to_bytes(std::mem::take(request.body_mut()), 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return axum::http::StatusCode::BAD_REQUEST.into_response(),
    };
    *request.body_mut() = Body::from(bytes.clone());
    if request.method() == axum::http::Method::POST
        && let Err(response) = super::input::validate_raw_json(
            &bytes,
            request.headers().get(axum::http::header::CONTENT_TYPE),
        )
    {
        return response.into_response();
    }
    let serialized = serde_json::from_slice::<Value>(&bytes)
        .ok()
        .map(|body| crate::agent_auth::json::javascript_stringify(&body));
    let base_url = issuer(&service, request.headers());
    let url = request_url(&service, request.headers(), request.uri());
    let context = AgentRequestContext {
        path: &path,
        method: request.method().as_str(),
        base_url: &base_url,
        url: &url,
        headers: request.headers(),
        serialized_body: serialized.as_deref(),
    };
    match authenticate_scoped(&service, &state, context).await {
        Ok(_) => next.run(request).await,
        Err(error) => error_response(error, &base_url),
    }
}

pub(super) async fn authenticate_scoped(
    service: &AuthService,
    state: &AgentAuthState,
    request: AgentRequestContext<'_>,
) -> Result<ScopedAgentAuthentication, AgentAuthenticationError> {
    let Some(token) = scoped_bearer(request.path, request.headers) else {
        return Ok(ScopedAgentAuthentication::NotApplicable);
    };
    let optional = OPTIONAL_AUTH_PATHS.contains(&request.path);
    let result = authenticate_token(service, state, &request, token).await;
    if optional && result.is_err() {
        Ok(ScopedAgentAuthentication::NotApplicable)
    } else {
        result
    }
}

async fn authenticate_token(
    service: &AuthService,
    state: &AgentAuthState,
    request: &AgentRequestContext<'_>,
    token: &str,
) -> Result<ScopedAgentAuthentication, AgentAuthenticationError> {
    let decoded = decode_agent_jwt(token).map_err(AgentAuthenticationError::from_jwt)?;
    match decoded.header.typ.as_str() {
        "host+jwt" => authenticate_host(state, request, token, decoded).await,
        "agent+jwt" => authenticate_agent(service, state, request, token, decoded).await,
        _ => Err(AgentAuthenticationError::invalid_jwt()),
    }
}

async fn authenticate_host(
    state: &AgentAuthState,
    request: &AgentRequestContext<'_>,
    token: &str,
    decoded: VerifiedAgentJwt,
) -> Result<ScopedAgentAuthentication, AgentAuthenticationError> {
    let issuer = decoded
        .claims
        .issuer
        .as_deref()
        .ok_or_else(AgentAuthenticationError::invalid_jwt)?;
    let host = state
        .store
        .find_host(issuer)
        .await
        .map_err(AgentAuthenticationError::storage)?
        .or(state
            .store
            .find_host_by_kid(issuer)
            .await
            .map_err(AgentAuthenticationError::storage)?)
        .filter(|host| host.public_key.is_some() || host.jwks_url.is_some())
        .filter(|host| {
            host.status == AgentHostStatus::Active
                || (host.status == AgentHostStatus::Pending && request.path == "/agent/status")
        })
        .ok_or_else(AgentAuthenticationError::agent_not_found)?;
    let inline = parse_optional_jwk(host.public_key.as_deref())?;
    state
        .verifier
        .verify(
            token,
            AgentJwtKeySource {
                inline_public_jwk: inline.as_ref(),
                jwks_url: host.jwks_url.as_deref(),
            },
            verification_options(state, request, AgentJwtKind::Host, None, None, false, None),
        )
        .await
        .map_err(AgentAuthenticationError::from_jwt)?;
    Ok(ScopedAgentAuthentication::Host(model::host_session(host)))
}

async fn authenticate_agent(
    service: &AuthService,
    state: &AgentAuthState,
    request: &AgentRequestContext<'_>,
    token: &str,
    decoded: VerifiedAgentJwt,
) -> Result<ScopedAgentAuthentication, AgentAuthenticationError> {
    let agent_id = decoded
        .claims
        .subject
        .as_deref()
        .ok_or_else(AgentAuthenticationError::invalid_jwt)?;
    let mut agent = state
        .store
        .find_agent(agent_id)
        .await
        .map_err(AgentAuthenticationError::storage)?
        .ok_or_else(AgentAuthenticationError::agent_not_found)?;
    validate_agent_status(&agent)?;
    enforce_absolute_lifetime(state, &agent, Utc::now()).await?;
    let reactivation_needed = needs_reactivation(&agent, &state.config);
    if let Err(failure) = verify_agent_token(state, request, token, &decoded, &agent).await {
        if failure.expires_agent
            && reactivation_needed
            && agent.status == crate::AgentStatus::Active
        {
            lifecycle::mark_agent_expired(state, &agent, Utc::now()).await;
        }
        return Err(failure.error);
    }
    if reactivation_needed {
        agent = transparent_reactivation(state, agent, Utc::now())
            .await?
            .ok_or_else(AgentAuthenticationError::agent_expired)?;
        lifecycle::emit_transparent_reactivation(state, &agent);
    }
    let authenticated = build_agent_session(service, state, request, agent, decoded).await?;
    if !reactivation_needed {
        heartbeat(state, &authenticated.agent).await;
    }
    Ok(ScopedAgentAuthentication::Agent(Box::new(
        authenticated.session,
    )))
}

async fn verify_agent_token(
    state: &AgentAuthState,
    request: &AgentRequestContext<'_>,
    token: &str,
    decoded: &VerifiedAgentJwt,
    agent: &AgentIdentity,
) -> Result<(), AgentVerificationFailure> {
    let inline =
        parse_optional_jwk(Some(&agent.public_key)).map_err(|error| AgentVerificationFailure {
            error,
            expires_agent: false,
        })?;
    let expected_location = expected_location(state, decoded);
    state
        .verifier
        .verify(
            token,
            AgentJwtKeySource {
                inline_public_jwk: inline.as_ref(),
                jwks_url: agent.jwks_url.as_deref(),
            },
            verification_options(
                state,
                request,
                AgentJwtKind::Agent,
                Some(agent.host_id.as_str()),
                Some(agent.id.as_str()),
                false,
                expected_location,
            ),
        )
        .await
        .map(|_| ())
        .map_err(|error| AgentVerificationFailure {
            expires_agent: invalidates_expired_agent(&error),
            error: AgentAuthenticationError::from_jwt(error),
        })
}

struct AgentVerificationFailure {
    error: AgentAuthenticationError,
    expires_agent: bool,
}

fn invalidates_expired_agent(error: &crate::agent_auth::jwt::AgentJwtError) -> bool {
    matches!(
        error,
        crate::agent_auth::jwt::AgentJwtError::Expired
            | crate::agent_auth::jwt::AgentJwtError::TooOld
            | crate::agent_auth::jwt::AgentJwtError::IssuedInFuture
            | crate::agent_auth::jwt::AgentJwtError::InvalidSignature
            | crate::agent_auth::jwt::AgentJwtError::InvalidClaim("nbf")
            | crate::agent_auth::jwt::AgentJwtError::MissingClaim("iat")
    )
}

async fn build_agent_session(
    service: &AuthService,
    state: &AgentAuthState,
    request: &AgentRequestContext<'_>,
    agent: AgentIdentity,
    verified: VerifiedAgentJwt,
) -> Result<AuthenticatedAgent, AgentAuthenticationError> {
    let host = state
        .store
        .find_host(&agent.host_id)
        .await
        .map_err(AgentAuthenticationError::storage)?;
    let user_id = agent
        .user_id
        .or(host.as_ref().and_then(|host| host.user_id));
    let user = match user_id {
        Some(user_id) => service
            .auth_user_by_id(user_id)
            .await
            .map_err(AgentAuthenticationError::storage)?
            .map(model::agent_session_user)
            .ok_or_else(AgentAuthenticationError::autonomous_owner_required)?,
        None => resolve_autonomous_user(state, request, &agent, host.as_ref())
            .await
            .ok_or_else(AgentAuthenticationError::autonomous_owner_required)?,
    };
    let mut grants = active_grants(
        state
            .store
            .list_grants(&agent.id)
            .await
            .map_err(AgentAuthenticationError::storage)?,
    );
    if verified.claims.capabilities_present {
        grants.retain(|grant| verified.claims.capabilities.contains(&grant.capability));
    }
    let session = model::agent_session(&agent, host.as_ref(), user_id, user, grants);
    Ok(AuthenticatedAgent { agent, session })
}

fn scoped_bearer<'a>(path: &str, headers: &'a HeaderMap) -> Option<&'a str> {
    if !is_agent_auth_path(path) || UNAUTHENTICATED_PATHS.contains(&path) {
        return None;
    }
    let authorization = headers.get("authorization")?.to_str().ok()?;
    let (scheme, token) = authorization.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") || token.is_empty() || token.split('.').count() != 3 {
        return None;
    }
    Some(token)
}

fn is_agent_auth_path(path: &str) -> bool {
    ["/agent/", "/capability/", "/host/"]
        .iter()
        .any(|prefix| path.starts_with(prefix))
}

pub(super) fn request_url(
    service: &AuthService,
    headers: &HeaderMap,
    uri: &axum::http::Uri,
) -> String {
    let base = issuer(service, headers);
    let origin = url::Url::parse(&base)
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or(base);
    format!("{origin}{uri}")
}

pub(super) fn error_response(
    error: AgentAuthenticationError,
    base_url: &str,
) -> axum::response::Response {
    let origin = url::Url::parse(base_url)
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|_| base_url.trim_end_matches('/').to_owned());
    error.into_response(&origin)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderValue, header};

    #[test]
    fn bearer_matcher_is_strictly_scoped_and_skips_bootstrap_routes() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer a.b.c"),
        );
        assert_eq!(scoped_bearer("/agent/session", &headers), Some("a.b.c"));
        assert_eq!(
            scoped_bearer("/capability/execute", &headers),
            Some("a.b.c")
        );
        assert_eq!(scoped_bearer("/host/revoke", &headers), Some("a.b.c"));
        assert_eq!(scoped_bearer("/oauth2/token", &headers), None);
        assert_eq!(scoped_bearer("/agent/register", &headers), None);
        assert_eq!(scoped_bearer("/agent/claim", &headers), None);
    }

    #[test]
    fn non_jwt_and_non_bearer_credentials_are_left_for_other_auth_layers() {
        let mut headers = HeaderMap::new();
        for value in ["Bearer opaque", "Basic a.b.c", "DPoP a.b.c"] {
            headers.insert(header::AUTHORIZATION, HeaderValue::from_str(value).unwrap());
            assert_eq!(scoped_bearer("/agent/session", &headers), None);
        }
    }
}
