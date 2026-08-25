use super::{execute, grants, response};
use crate::{
    AgentAuthErrorCode, AgentExecuteContext, AgentExecuteResult, AgentGrantRevoker, AgentSession,
    AuthService,
};
use axum::{
    Extension, Json,
    extract::OriginalUri,
    http::{HeaderMap, Method, StatusCode},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Instant};
use tokio::{sync::Semaphore, task::JoinSet};

use super::super::{
    AgentAuthState,
    input::{AgentInput, AgentJson, Field, FieldKind},
};

const MAX_BATCH_SIZE: usize = 50;
const DEFAULT_CONCURRENCY: usize = 20;

#[derive(Debug, Deserialize, Serialize)]
pub(in crate::agent_auth::axum) struct BatchBody {
    requests: Vec<BatchRequest>,
}

impl AgentInput for BatchBody {
    const FIELDS: &'static [Field] = &[Field::required(
        "requests",
        FieldKind::BatchRequestArray {
            min: Some(1),
            max: Some(MAX_BATCH_SIZE),
        },
    )];
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct BatchRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<String>,
    capability: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    arguments: Option<Map<String, Value>>,
}

pub(in crate::agent_auth::axum) async fn batch_execute(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    AgentJson(body): AgentJson<BatchBody>,
) -> Response {
    let serialized = crate::agent_auth::json::javascript_stringify(
        &serde_json::to_value(&body).expect("batch body serializes"),
    );
    let session = match execute::authenticate(
        &service,
        &state,
        &uri,
        &method,
        &headers,
        "/capability/batch-execute",
        &serialized,
    )
    .await
    {
        Ok(Some(session)) => session,
        Ok(None) => return response::unauthorized(&service, &headers),
        Err(error) => return error,
    };
    if state.config.on_execute.is_none() {
        return response::api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            AgentAuthErrorCode::ExecuteNotConfigured,
            None,
            Map::new(),
        );
    }
    let requests: Vec<_> = body
        .requests
        .into_iter()
        .enumerate()
        .map(|(index, mut request)| {
            request.id.get_or_insert_with(|| index.to_string());
            request
        })
        .collect();
    let definitions = definitions(&state, &session).await;
    let grant_map = match grant_map(&state, &session, &requests).await {
        Ok(grants) => grants,
        Err(_) => {
            return response::api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                AgentAuthErrorCode::InternalError,
                None,
                Map::new(),
            );
        }
    };
    let base_url = super::super::issuer(&service, &headers);
    let responses = process(
        state,
        session,
        headers,
        base_url,
        requests,
        definitions,
        grant_map,
    )
    .await;
    Json(json!({"responses": responses})).into_response()
}

async fn definitions(
    state: &AgentAuthState,
    session: &AgentSession,
) -> BTreeMap<String, crate::AgentCapability> {
    let mut definitions = state.config.capabilities.clone();
    if definitions.is_empty()
        && let Some(resolver) = &state.config.resolve_capabilities
    {
        definitions = resolver
            .resolve(crate::AgentResolveCapabilitiesContext {
                capabilities: definitions,
                query: None,
                agent_session: Some(session.clone()),
                host_session: None,
            })
            .await;
    }
    definitions
        .into_iter()
        .map(|definition| (definition.name.clone(), definition))
        .collect()
}

async fn grant_map(
    state: &AgentAuthState,
    session: &AgentSession,
    requests: &[BatchRequest],
) -> Result<BTreeMap<String, Vec<crate::AgentCapabilityGrant>>, crate::AuthError> {
    let mut map = BTreeMap::new();
    for capability in requests
        .iter()
        .map(|request| request.capability.as_str())
        .collect::<std::collections::BTreeSet<_>>()
    {
        let active = grants::active_for(state, &session.agent.id, capability).await?;
        if !active.is_empty() {
            map.insert(capability.to_owned(), active);
        }
    }
    for capability in requests
        .iter()
        .map(|request| request.capability.as_str())
        .collect::<std::collections::BTreeSet<_>>()
    {
        if !map.contains_key(capability)
            && let Some(grant) = grants::auto_grant(state, session, capability).await?
        {
            map.insert(capability.to_owned(), vec![grant]);
        }
    }
    Ok(map)
}

#[allow(clippy::too_many_arguments)]
async fn process(
    state: AgentAuthState,
    session: AgentSession,
    headers: HeaderMap,
    base_url: String,
    requests: Vec<BatchRequest>,
    definitions: BTreeMap<String, crate::AgentCapability>,
    grant_map: BTreeMap<String, Vec<crate::AgentCapabilityGrant>>,
) -> Vec<Value> {
    let semaphore = Arc::new(Semaphore::new(DEFAULT_CONCURRENCY));
    let mut tasks = JoinSet::new();
    let count = requests.len();
    for (index, request) in requests.into_iter().enumerate() {
        let state = state.clone();
        let session = session.clone();
        let headers = headers.clone();
        let base_url = base_url.clone();
        let definition = definitions.get(&request.capability).cloned();
        let grants = grant_map.get(&request.capability).cloned();
        let permit = semaphore.clone().acquire_owned().await.expect("open");
        tasks.spawn(async move {
            let _permit = permit;
            (
                index,
                process_one(
                    state, session, headers, base_url, request, definition, grants,
                )
                .await,
            )
        });
    }
    let mut responses = vec![Value::Null; count];
    while let Some(result) = tasks.join_next().await {
        if let Ok((index, response)) = result {
            responses[index] = response;
        }
    }
    responses
}

async fn process_one(
    state: AgentAuthState,
    session: AgentSession,
    headers: HeaderMap,
    base_url: String,
    mut request: BatchRequest,
    definition: Option<crate::AgentCapability>,
    grants: Option<Vec<crate::AgentCapabilityGrant>>,
) -> Value {
    let id = request.id.take().expect("batch ids normalized");
    let authorized = match authorize_request(&id, request, definition, grants) {
        Ok(authorized) => authorized,
        Err(response) => return response,
    };
    execute_one(state, session, headers, base_url, id, authorized).await
}

struct AuthorizedBatchRequest {
    capability: String,
    arguments: Option<Map<String, Value>>,
    definition: crate::AgentCapability,
    grant: crate::AgentCapabilityGrant,
}

fn authorize_request(
    id: &str,
    request: BatchRequest,
    definition: Option<crate::AgentCapability>,
    grants: Option<Vec<crate::AgentCapabilityGrant>>,
) -> Result<AuthorizedBatchRequest, Value> {
    let Some(definition) = definition else {
        return Err(failed(
            id.to_owned(),
            AgentAuthErrorCode::CapabilityNotFound.code(),
            format!("Capability \"{}\" does not exist.", request.capability),
        ));
    };
    let grant = grants
        .as_deref()
        .and_then(|grants| grants::matching(grants, request.arguments.as_ref()));
    let Some(grant) = grant else {
        let has_any = grants.is_some_and(|grants| !grants.is_empty());
        return Err(if has_any {
            failed(
                id.to_owned(),
                AgentAuthErrorCode::ConstraintViolated.code(),
                format!(
                    "No grant for \"{}\" covers the provided arguments.",
                    request.capability
                ),
            )
        } else {
            failed(
                id.to_owned(),
                AgentAuthErrorCode::CapabilityNotGranted.code(),
                format!(
                    "Agent does not have an active grant for capability \"{}\".",
                    request.capability
                ),
            )
        });
    };
    Ok(AuthorizedBatchRequest {
        capability: request.capability,
        arguments: request.arguments,
        definition,
        grant: grant.clone(),
    })
}

async fn execute_one(
    state: AgentAuthState,
    session: AgentSession,
    headers: HeaderMap,
    base_url: String,
    id: String,
    authorized: AuthorizedBatchRequest,
) -> Value {
    let body = execute::ExecuteBody {
        capability: authorized.capability.clone(),
        arguments: authorized.arguments.clone(),
    };
    let started = Instant::now();
    let result = state
        .config
        .on_execute
        .as_ref()
        .expect("checked")
        .execute(AgentExecuteContext {
            endpoint: execute::endpoint_context(&headers, &base_url, "/capability/batch-execute"),
            capability: authorized.capability,
            capability_definition: authorized.definition,
            arguments: authorized.arguments,
            agent_session: session.clone(),
            grant: authorized.grant.clone(),
            revoke_grant: AgentGrantRevoker::new(state.store.clone(), authorized.grant.id),
        })
        .await;
    match result {
        Err(error) => {
            let message = error.to_string();
            execute::emit_execution(
                &state,
                &session,
                &body,
                crate::AgentCapabilityExecutionStatus::Error,
                started.elapsed().as_millis() as u64,
                Some(message.clone()),
            );
            let code = match &error {
                crate::AgentExecuteError::Api { error, .. } => error.code.code(),
                crate::AgentExecuteError::Internal(_) => "internal_error",
            };
            failed(id, code, message)
        }
        Ok(result) => {
            execute::emit_execution(
                &state,
                &session,
                &body,
                crate::AgentCapabilityExecutionStatus::Success,
                started.elapsed().as_millis() as u64,
                None,
            );
            match result {
                AgentExecuteResult::Data(data) => {
                    json!({"id": id, "status": "completed", "data": data})
                }
                AgentExecuteResult::Async { .. } | AgentExecuteResult::Stream(_) => failed(
                    id,
                    "batch_unsupported_result_type",
                    "Async and streaming results are not supported in batch mode. Execute this capability individually.",
                ),
            }
        }
    }
}

fn failed(id: String, code: &str, message: impl Into<String>) -> Value {
    json!({
        "id": id,
        "status": "failed",
        "error": {"code": code, "message": message.into()},
    })
}
