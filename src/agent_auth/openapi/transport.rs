use std::{collections::BTreeMap, fmt};

use async_trait::async_trait;
use tokio::sync::mpsc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentOpenApiHttpRequest {
    pub method: String,
    pub url: String,
    pub headers: BTreeMap<String, String>,
    pub body: Option<Vec<u8>>,
}

pub enum AgentOpenApiResponseBody {
    Bytes(Vec<u8>),
    Stream(mpsc::Receiver<Result<Vec<u8>, String>>),
}

impl fmt::Debug for AgentOpenApiResponseBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes(bytes) => formatter.debug_tuple("Bytes").field(&bytes.len()).finish(),
            Self::Stream(_) => formatter.write_str("Stream(..)"),
        }
    }
}

#[derive(Debug)]
pub struct AgentOpenApiHttpResponse {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body: AgentOpenApiResponseBody,
}

#[async_trait]
pub trait AgentOpenApiTransport: Send + Sync {
    async fn send(
        &self,
        request: AgentOpenApiHttpRequest,
    ) -> Result<AgentOpenApiHttpResponse, String>;
}

#[derive(Debug, Clone)]
pub struct ReqwestAgentOpenApiTransport {
    client: reqwest::Client,
}

impl Default for ReqwestAgentOpenApiTransport {
    fn default() -> Self {
        Self {
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl AgentOpenApiTransport for ReqwestAgentOpenApiTransport {
    async fn send(
        &self,
        request: AgentOpenApiHttpRequest,
    ) -> Result<AgentOpenApiHttpResponse, String> {
        let method = reqwest::Method::from_bytes(request.method.as_bytes())
            .map_err(|error| error.to_string())?;
        let mut builder = self.client.request(method, request.url);
        for (name, value) in request.headers {
            builder = builder.header(name, value);
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
        }
        let mut response = builder.send().await.map_err(|error| error.to_string())?;
        let status = response.status().as_u16();
        let headers = response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                value
                    .to_str()
                    .ok()
                    .map(|value| (name.as_str().to_owned(), value.to_owned()))
            })
            .collect::<BTreeMap<_, _>>();
        let is_stream = headers
            .get("content-type")
            .is_some_and(|value| value.contains("text/event-stream"));
        let body = if is_stream {
            let (sender, receiver) = mpsc::channel(8);
            tokio::spawn(async move {
                loop {
                    match response.chunk().await {
                        Ok(Some(chunk)) => {
                            if sender.send(Ok(chunk.to_vec())).await.is_err() {
                                break;
                            }
                        }
                        Ok(None) => break,
                        Err(error) => {
                            let _ = sender.send(Err(error.to_string())).await;
                            break;
                        }
                    }
                }
            });
            AgentOpenApiResponseBody::Stream(receiver)
        } else {
            AgentOpenApiResponseBody::Bytes(
                response
                    .bytes()
                    .await
                    .map_err(|error| error.to_string())?
                    .to_vec(),
            )
        };
        Ok(AgentOpenApiHttpResponse {
            status,
            headers,
            body,
        })
    }
}

pub(super) fn into_stream(
    body: AgentOpenApiResponseBody,
) -> mpsc::Receiver<Result<Vec<u8>, String>> {
    match body {
        AgentOpenApiResponseBody::Stream(receiver) => receiver,
        AgentOpenApiResponseBody::Bytes(bytes) => {
            let (sender, receiver) = mpsc::channel(1);
            let _ = sender.try_send(Ok(bytes));
            receiver
        }
    }
}

pub(super) async fn into_bytes(body: AgentOpenApiResponseBody) -> Result<Vec<u8>, String> {
    match body {
        AgentOpenApiResponseBody::Bytes(bytes) => Ok(bytes),
        AgentOpenApiResponseBody::Stream(mut receiver) => {
            let mut bytes = Vec::new();
            while let Some(chunk) = receiver.recv().await {
                bytes.extend_from_slice(&chunk?);
            }
            Ok(bytes)
        }
    }
}
