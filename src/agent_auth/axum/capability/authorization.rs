use super::{execute::ExecuteBody, grants, response};
use crate::{AgentAuthErrorCode, AgentCapability, AgentCapabilityGrant, AgentSession};
use axum::{http::StatusCode, response::Response};
use serde_json::{Map, json};

use super::super::AgentAuthState;

pub(super) struct AuthorizedExecution {
    pub definition: AgentCapability,
    pub grant: AgentCapabilityGrant,
}

pub(super) struct AuthorizationError(Box<Response>);

impl AuthorizationError {
    pub(super) fn into_response(self) -> Response {
        *self.0
    }
}

impl From<Response> for AuthorizationError {
    fn from(response: Response) -> Self {
        Self(Box::new(response))
    }
}

pub(super) async fn authorize(
    state: &AgentAuthState,
    session: &AgentSession,
    body: &ExecuteBody,
) -> Result<AuthorizedExecution, AuthorizationError> {
    let Some(definition) = definition(state, session, &body.capability).await else {
        return Err(response::api_error(
            StatusCode::NOT_FOUND,
            AgentAuthErrorCode::CapabilityNotFound,
            Some(format!(
                "Capability \"{}\" does not exist.",
                body.capability
            )),
            Map::new(),
        )
        .into());
    };
    let all_grants = state
        .store
        .list_grants(&session.agent.id)
        .await
        .map_err(|_| internal_error())?;
    let session_has_grant = session
        .agent
        .capability_grants
        .iter()
        .any(|grant| grant.capability == body.capability);
    let active = if session_has_grant {
        grants::active_for(state, &session.agent.id, &body.capability)
            .await
            .map_err(|_| internal_error())?
    } else {
        Vec::new()
    };
    let mut grant = grants::matching(&active, body.arguments.as_ref());
    if grant.is_none() {
        validate_first_constrained(&active, body)?;
        grant = grants::auto_grant(state, session, &body.capability)
            .await
            .map_err(|_| internal_error())?;
    }
    match grant {
        Some(grant) => Ok(AuthorizedExecution { definition, grant }),
        None => Err(not_granted(body, &all_grants)),
    }
}

async fn definition(
    state: &AgentAuthState,
    session: &AgentSession,
    name: &str,
) -> Option<AgentCapability> {
    if let Some(definition) = state
        .config
        .capabilities
        .iter()
        .find(|item| item.name == name)
    {
        return Some(definition.clone());
    }
    let resolver = state.config.resolve_capabilities.as_ref()?;
    resolver
        .resolve(crate::AgentResolveCapabilitiesContext {
            capabilities: state.config.capabilities.clone(),
            query: None,
            agent_session: Some(session.clone()),
            host_session: None,
        })
        .await
        .into_iter()
        .find(|item| item.name == name)
}

fn validate_first_constrained(
    active: &[AgentCapabilityGrant],
    body: &ExecuteBody,
) -> Result<(), AuthorizationError> {
    let Some(constraints) = active.iter().find_map(|grant| grant.constraints.as_ref()) else {
        return Ok(());
    };
    let validation =
        crate::agent_auth::policy::validate_constraints(constraints, body.arguments.as_ref());
    if !validation.unknown_operators.is_empty() {
        return Err(response::api_error(
            StatusCode::BAD_REQUEST,
            AgentAuthErrorCode::UnknownConstraintOperator,
            None,
            Map::from_iter([("operators".into(), json!(validation.unknown_operators))]),
        )
        .into());
    }
    if !validation.violations.is_empty() {
        return Err(response::api_error(
            StatusCode::FORBIDDEN,
            AgentAuthErrorCode::ConstraintViolated,
            None,
            Map::from_iter([("violations".into(), json!(validation.violations))]),
        )
        .into());
    }
    Ok(())
}

fn not_granted(body: &ExecuteBody, all: &[AgentCapabilityGrant]) -> AuthorizationError {
    let revoked = all.iter().any(|grant| {
        grant.capability == body.capability && grant.status == crate::AgentGrantStatus::Revoked
    });
    let (code, message) = if revoked {
        (
            AgentAuthErrorCode::GrantRevoked,
            format!(
                "Grant for capability \"{}\" has been revoked.",
                body.capability
            ),
        )
    } else {
        (
            AgentAuthErrorCode::CapabilityNotGranted,
            format!(
                "Agent does not have an active grant for capability \"{}\".",
                body.capability
            ),
        )
    };
    response::api_error(StatusCode::FORBIDDEN, code, Some(message), Map::new()).into()
}

fn internal_error() -> AuthorizationError {
    response::api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        AgentAuthErrorCode::InternalError,
        None,
        Map::new(),
    )
    .into()
}
