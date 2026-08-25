#![allow(clippy::result_large_err)] // Axum responses are the deliberate error channel.

use super::{authorization, response};
use crate::{
    AgentAuthCapabilityExecutionEvent, AgentAuthErrorCode, AgentAuthEvent,
    AgentAuthExecutionEventFields, AgentCapabilityExecutedEventType,
    AgentCapabilityExecutionStatus, AgentExecuteContext, AgentExecuteResult, AgentGrantRevoker,
    AgentSession, AuthService,
};
use axum::{
    Extension, Json,
    body::{Body, Bytes},
    extract::OriginalUri,
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{collections::BTreeMap, sync::Arc, time::Instant};
use tokio_stream::{StreamExt, wrappers::ReceiverStream};

use super::super::{
    AgentAuthState, auth,
    input::{AgentInput, AgentJson, Field, FieldKind},
};

#[derive(Debug, Deserialize, Serialize)]
pub(in crate::agent_auth::axum) struct ExecuteBody {
    pub(super) capability: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) arguments: Option<Map<String, Value>>,
}

impl AgentInput for ExecuteBody {
    const FIELDS: &'static [Field] = &[
        Field::required("capability", FieldKind::String { min: None }),
        Field::optional("arguments", FieldKind::Record),
    ];
}

pub(in crate::agent_auth::axum) async fn execute(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
    AgentJson(body): AgentJson<ExecuteBody>,
) -> Response {
    let serialized = crate::agent_auth::json::javascript_stringify(
        &serde_json::to_value(&body).expect("execution body serializes"),
    );
    let session = match authenticate(
        &service,
        &state,
        &uri,
        &method,
        &headers,
        "/capability/execute",
        &serialized,
    )
    .await
    {
        Ok(Some(session)) => session,
        Ok(None) => return response::unauthorized(&service, &headers),
        Err(error) => return error,
    };
    let base_url = super::super::issuer(&service, &headers);
    execute_authenticated(&state, &headers, &base_url, body, session).await
}

async fn execute_authenticated(
    state: &AgentAuthState,
    headers: &HeaderMap,
    base_url: &str,
    body: ExecuteBody,
    session: AgentSession,
) -> Response {
    let authorized = match authorization::authorize(state, &session, &body).await {
        Ok(authorized) => authorized,
        Err(error) => return error.into_response(),
    };
    let Some(handler) = &state.config.on_execute else {
        return response::api_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            AgentAuthErrorCode::ExecuteNotConfigured,
            None,
            Map::new(),
        );
    };
    let started = Instant::now();
    let result = handler
        .execute(AgentExecuteContext {
            endpoint: endpoint_context(headers, base_url, "/capability/execute"),
            capability: body.capability.clone(),
            capability_definition: authorized.definition,
            arguments: body.arguments.clone(),
            agent_session: session.clone(),
            grant: authorized.grant.clone(),
            revoke_grant: AgentGrantRevoker::new(state.store.clone(), authorized.grant.id),
        })
        .await;
    match result {
        Ok(result) => {
            emit_execution(
                state,
                &session,
                &body,
                AgentCapabilityExecutionStatus::Success,
                started.elapsed().as_millis() as u64,
                None,
            );
            execute_response(result)
        }
        Err(error) => {
            let message = error.to_string();
            emit_execution(
                state,
                &session,
                &body,
                AgentCapabilityExecutionStatus::Error,
                started.elapsed().as_millis() as u64,
                Some(message.clone()),
            );
            match error {
                crate::AgentExecuteError::Api { error, .. } => response::provided_error(error),
                crate::AgentExecuteError::Internal(_) => response::api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    AgentAuthErrorCode::InternalError,
                    Some(message),
                    Map::new(),
                ),
            }
        }
    }
}

pub(super) async fn authenticate(
    service: &AuthService,
    state: &AgentAuthState,
    uri: &axum::http::Uri,
    method: &Method,
    headers: &HeaderMap,
    path: &'static str,
    serialized_body: &str,
) -> Result<Option<AgentSession>, Response> {
    let base_url = super::super::issuer(service, headers);
    let url = auth::request_url(service, headers, uri);
    match auth::authenticate_scoped(
        service,
        state,
        auth::AgentRequestContext {
            path,
            method: method.as_str(),
            base_url: &base_url,
            url: &url,
            headers,
            serialized_body: Some(serialized_body),
        },
    )
    .await
    {
        Ok(auth::ScopedAgentAuthentication::Agent(session)) => Ok(Some(*session)),
        Ok(_) => Ok(None),
        Err(error) => Err(auth::error_response(error, &base_url)),
    }
}

pub(super) fn endpoint_context(
    headers: &HeaderMap,
    base_url: &str,
    path: &str,
) -> crate::AgentEndpointContext {
    crate::AgentEndpointContext {
        method: "POST".into(),
        path: path.into(),
        base_url: base_url.to_owned(),
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

pub(super) fn emit_execution(
    state: &AgentAuthState,
    session: &AgentSession,
    body: &ExecuteBody,
    status: AgentCapabilityExecutionStatus,
    duration_ms: u64,
    error: Option<String>,
) {
    let event = AgentAuthEvent::CapabilityExecuted(Box::new(AgentAuthCapabilityExecutionEvent {
        event_type: AgentCapabilityExecutedEventType::CapabilityExecuted,
        capability: body.capability.clone(),
        status,
        fields: AgentAuthExecutionEventFields {
            base: crate::AgentAuthEventFields {
                agent_id: Some(session.agent.id.clone()),
                host_id: Some(session.agent.host_id.clone()),
                ..crate::AgentAuthEventFields::default()
            },
            agent_name: Some(session.agent.name.clone()),
            user_id: session.host.as_ref().and_then(|host| host.user_id),
            arguments: body.arguments.clone(),
            duration_ms: Some(duration_ms),
            error,
            ..AgentAuthExecutionEventFields::default()
        },
    }));
    super::super::events::emit(&state.config, event);
}

pub(super) fn execute_response(result: AgentExecuteResult) -> Response {
    match result {
        AgentExecuteResult::Data(data) => Json(json!({"data": data})).into_response(),
        AgentExecuteResult::Async {
            status_url,
            retry_after,
        } => {
            let mut body = Map::from_iter([
                ("status".into(), Value::String("pending".into())),
                ("status_url".into(), Value::String(status_url)),
            ]);
            if let Some(retry_after) = retry_after {
                body.insert("retry_after".into(), retry_after.into());
            }
            let mut response = (StatusCode::ACCEPTED, Json(Value::Object(body))).into_response();
            if let Some(retry_after) = retry_after
                && let Ok(value) = HeaderValue::from_str(&retry_after.to_string())
            {
                response.headers_mut().insert(header::RETRY_AFTER, value);
            }
            response
        }
        AgentExecuteResult::Stream(stream) => {
            let body = Body::from_stream(
                ReceiverStream::new(stream.body)
                    .map(|chunk| chunk.map(Bytes::from).map_err(std::io::Error::other)),
            );
            let mut response = Response::new(body);
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/event-stream"),
            );
            response
                .headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
            response
                .headers_mut()
                .insert(header::CONNECTION, HeaderValue::from_static("keep-alive"));
            for (name, value) in stream.headers {
                if let (Ok(name), Ok(value)) =
                    (HeaderName::try_from(name), HeaderValue::from_str(&value))
                {
                    response.headers_mut().insert(name, value);
                }
            }
            response
        }
    }
}
