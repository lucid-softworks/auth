use std::{collections::BTreeMap, fmt, sync::Arc};

use async_trait::async_trait;
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde_json::{Map, Value};

use super::{
    parse::{OpenApiOperation, js_string, operation_map},
    response::response_result,
    transport::{AgentOpenApiHttpRequest, AgentOpenApiTransport, ReqwestAgentOpenApiTransport},
};
use crate::{
    AgentEndpointContext, AgentExecuteContext, AgentExecuteHandler, AgentExecuteResult,
    AgentSession,
};

const URI_COMPONENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'!')
    .remove(b'~')
    .remove(b'*')
    .remove(b'\'')
    .remove(b'(')
    .remove(b')');

#[derive(Debug, Clone)]
pub struct AgentOpenApiHeadersContext {
    pub endpoint: AgentEndpointContext,
    pub capability: String,
    pub agent_session: AgentSession,
}

#[async_trait]
pub trait AgentOpenApiHeaderResolver: Send + Sync {
    async fn resolve(&self, context: AgentOpenApiHeadersContext) -> BTreeMap<String, String>;
}

#[derive(Clone)]
pub struct AgentOpenApiHandlerOptions {
    pub base_url: String,
    pub resolve_headers: Option<Arc<dyn AgentOpenApiHeaderResolver>>,
    pub transport: Arc<dyn AgentOpenApiTransport>,
}

impl AgentOpenApiHandlerOptions {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            resolve_headers: None,
            transport: Arc::new(ReqwestAgentOpenApiTransport::default()),
        }
    }
}

impl fmt::Debug for AgentOpenApiHandlerOptions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AgentOpenApiHandlerOptions")
            .field("base_url", &self.base_url)
            .field("resolve_headers", &self.resolve_headers.is_some())
            .finish_non_exhaustive()
    }
}

pub(super) struct OpenApiExecuteHandler {
    operations: Vec<OpenApiOperation>,
    headers: Option<Arc<dyn AgentOpenApiHeaderResolver>>,
    transport: Arc<dyn AgentOpenApiTransport>,
}

impl OpenApiExecuteHandler {
    pub(super) fn new(spec: &Value, options: AgentOpenApiHandlerOptions) -> Self {
        Self {
            operations: operation_map(spec, &options.base_url),
            headers: options.resolve_headers,
            transport: options.transport,
        }
    }

    async fn execute_operation(
        &self,
        context: AgentExecuteContext,
    ) -> Result<AgentExecuteResult, String> {
        let operation = self
            .operations
            .iter()
            .find(|operation| operation.capability == context.capability)
            .ok_or_else(|| {
                format!(
                    "No OpenAPI operation found for capability \"{}\".",
                    context.capability
                )
            })?;
        let mut url = operation.url.clone();
        let mut query = Vec::new();
        let mut headers = BTreeMap::from_iter([("content-type".into(), "application/json".into())]);
        if let Some(resolve) = &self.headers {
            headers.extend(
                resolve
                    .resolve(AgentOpenApiHeadersContext {
                        endpoint: context.endpoint.clone(),
                        capability: context.capability.clone(),
                        agent_session: context.agent_session.clone(),
                    })
                    .await,
            );
        }
        let mut consumed = std::collections::BTreeSet::new();
        for parameter in &operation.parameters {
            let Some(value) = context
                .arguments
                .as_ref()
                .and_then(|arguments| arguments.get(&parameter.name))
            else {
                continue;
            };
            consumed.insert(parameter.name.clone());
            let value = js_string(value);
            match parameter.location.as_str() {
                "path" => {
                    url = url.replacen(
                        &format!("{{{}}}", parameter.name),
                        &utf8_percent_encode(&value, URI_COMPONENT).to_string(),
                        1,
                    );
                }
                "query" => query.push((parameter.name.clone(), value)),
                "header" => {
                    headers.insert(parameter.name.clone(), value);
                }
                _ => {}
            }
        }
        append_query(&mut url, &query);
        let body = request_body(operation, context.arguments.as_ref(), &consumed)?;
        let response = self
            .transport
            .send(AgentOpenApiHttpRequest {
                method: operation.method.clone(),
                url,
                headers,
                body,
            })
            .await?;
        response_result(response).await
    }
}

#[async_trait]
impl AgentExecuteHandler for OpenApiExecuteHandler {
    async fn execute(
        &self,
        context: AgentExecuteContext,
    ) -> Result<AgentExecuteResult, crate::AgentExecuteError> {
        self.execute_operation(context).await.map_err(Into::into)
    }
}

fn append_query(url: &mut String, pairs: &[(String, String)]) {
    if pairs.is_empty() {
        return;
    }
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.extend_pairs(
        pairs
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    );
    let query = serializer.finish();
    url.push(if url.contains('?') { '&' } else { '?' });
    url.push_str(&query);
}

fn request_body(
    operation: &OpenApiOperation,
    arguments: Option<&Map<String, Value>>,
    consumed: &std::collections::BTreeSet<String>,
) -> Result<Option<Vec<u8>>, String> {
    if !operation.has_request_body || matches!(operation.method.as_str(), "GET" | "HEAD") {
        return Ok(None);
    }
    let body = arguments
        .into_iter()
        .flat_map(Map::iter)
        .filter(|(name, _)| !consumed.contains(*name))
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<Map<_, _>>();
    if body.is_empty() {
        Ok(None)
    } else {
        serde_json::to_vec(&body)
            .map(Some)
            .map_err(|error| error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::super::transport::AgentOpenApiResponseBody;
    use super::*;
    use crate::{
        AgentCapability, AgentCapabilityGrant, AgentEndpointContext, AgentGrantRevoker,
        AgentGrantStatus, AgentMode, AgentSession, AgentSessionHost, AgentSessionIdentity,
        AgentSessionUser, MemoryAgentAuthStore,
    };
    use chrono::Utc;
    use serde_json::json;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingTransport {
        requests: Mutex<Vec<AgentOpenApiHttpRequest>>,
    }

    #[async_trait]
    impl AgentOpenApiTransport for RecordingTransport {
        async fn send(
            &self,
            request: AgentOpenApiHttpRequest,
        ) -> Result<super::super::transport::AgentOpenApiHttpResponse, String> {
            self.requests.lock().unwrap().push(request);
            Ok(super::super::transport::AgentOpenApiHttpResponse {
                status: 200,
                headers: BTreeMap::from_iter([("content-type".into(), "application/json".into())]),
                body: AgentOpenApiResponseBody::Bytes(
                    serde_json::to_vec(&json!({"id":"message/1","ok":true})).unwrap(),
                ),
            })
        }
    }

    struct OracleHeaders;

    #[async_trait]
    impl AgentOpenApiHeaderResolver for OracleHeaders {
        async fn resolve(&self, context: AgentOpenApiHeadersContext) -> BTreeMap<String, String> {
            BTreeMap::from_iter([
                (
                    "authorization".into(),
                    format!("Agent {}", context.agent_session.agent.id),
                ),
                ("x-capability".into(), context.capability),
            ])
        }
    }

    #[tokio::test]
    async fn site_example_maps_path_query_header_and_omits_get_body() {
        let transport = Arc::new(RecordingTransport::default());
        let handler = OpenApiExecuteHandler::new(
            &super::super::test_support::fixture(),
            AgentOpenApiHandlerOptions {
                base_url: "https://upstream.example".into(),
                resolve_headers: Some(Arc::new(OracleHeaders)),
                transport: transport.clone(),
            },
        );
        let result = handler
            .execute(context(
                "messages.get",
                json!({"id":"message/1","verbose":true,"x-tenant":"oracle"}),
            ))
            .await
            .unwrap();
        assert!(
            matches!(result, AgentExecuteResult::Data(value) if value == json!({"id":"message/1","ok":true}))
        );
        let request = &transport.requests.lock().unwrap()[0];
        assert_eq!(
            request.url,
            "https://upstream.example/messages/message%2F1?verbose=true"
        );
        assert_eq!(request.method, "GET");
        assert_eq!(request.headers["authorization"], "Agent agent-1");
        assert_eq!(request.headers["x-capability"], "messages.get");
        assert_eq!(request.headers["x-tenant"], "oracle");
        assert!(request.body.is_none());
    }

    #[tokio::test]
    async fn request_body_contains_only_unconsumed_arguments() {
        let transport = Arc::new(RecordingTransport::default());
        let handler = OpenApiExecuteHandler::new(
            &super::super::test_support::fixture(),
            AgentOpenApiHandlerOptions {
                base_url: "https://upstream.example".into(),
                resolve_headers: None,
                transport: transport.clone(),
            },
        );
        handler
            .execute(context(
                "messages.create",
                json!({"id":"message/1","subject":"Hello"}),
            ))
            .await
            .unwrap();
        let request = &transport.requests.lock().unwrap()[0];
        assert_eq!(request.url, "https://upstream.example/messages/message%2F1");
        assert_eq!(request.method, "POST");
        assert_eq!(
            serde_json::from_slice::<Value>(request.body.as_ref().unwrap()).unwrap(),
            json!({"subject":"Hello"})
        );
    }

    fn context(capability: &str, arguments: Value) -> AgentExecuteContext {
        AgentExecuteContext {
            endpoint: AgentEndpointContext::default(),
            capability: capability.into(),
            capability_definition: AgentCapability::new(capability, capability),
            arguments: arguments.as_object().cloned(),
            agent_session: AgentSession {
                r#type: AgentMode::Delegated,
                agent_id: "agent-1".into(),
                user_id: None,
                agent: AgentSessionIdentity {
                    id: "agent-1".into(),
                    name: "Agent".into(),
                    mode: AgentMode::Delegated,
                    capability_grants: Vec::new(),
                    host_id: "host-1".into(),
                    created_at: Utc::now(),
                    activated_at: None,
                    metadata: None,
                },
                host: Some(AgentSessionHost {
                    id: "host-1".into(),
                    user_id: None,
                    status: "active".into(),
                }),
                user: AgentSessionUser {
                    id: "user-1".into(),
                    name: "User".into(),
                    email: "user@example.test".into(),
                    attributes: Map::new(),
                },
            },
            grant: AgentCapabilityGrant {
                id: "grant-1".into(),
                agent_id: "agent-1".into(),
                capability: capability.into(),
                constraints: None,
                denied_by: None,
                granted_by: None,
                expires_at: None,
                status: AgentGrantStatus::Active,
                reason: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
            revoke_grant: AgentGrantRevoker::new(
                Arc::new(MemoryAgentAuthStore::default()),
                "grant-1".into(),
            ),
        }
    }
}
