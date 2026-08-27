use super::{InfraConnectionOptions, ResolvedConnectionOptions, USER_AGENT};
use reqwest::{Method, StatusCode, header};
use serde_json::{Map, Value};
use std::{collections::BTreeMap, fmt, sync::Arc, time::Duration};

/// One request made through the shared managed-infrastructure clients.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DashRequest {
    pub method: Method,
    pub path: String,
    pub headers: BTreeMap<String, String>,
    pub body: Option<Value>,
}

impl DashRequest {
    pub fn get(path: impl Into<String>) -> Self {
        Self {
            method: Method::GET,
            path: path.into(),
            headers: BTreeMap::new(),
            body: None,
        }
    }

    pub fn post(path: impl Into<String>, body: Value) -> Self {
        Self {
            method: Method::POST,
            path: path.into(),
            headers: BTreeMap::new(),
            body: Some(body),
        }
    }
}

/// Better Fetch-shaped response envelope retained at the native boundary.
#[derive(Clone, Debug, PartialEq)]
pub struct DashClientResponse {
    pub status: StatusCode,
    pub data: Option<Value>,
    pub error: Option<Value>,
}

/// Transport failures that Better Fetch would reject rather than envelope.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DashClientError {
    #[error("{0}")]
    Transport(String),
}

#[derive(Clone)]
struct ManagedClient {
    http: reqwest::Client,
    base_url: Arc<str>,
    api_key: Arc<str>,
    include_empty_key: bool,
}

impl ManagedClient {
    fn new(base_url: String, api_key: String, timeout: Duration, include_empty_key: bool) -> Self {
        let builder = if timeout.is_zero() {
            reqwest::Client::builder()
        } else {
            reqwest::Client::builder().timeout(timeout)
        };
        Self {
            http: builder
                .build()
                .expect("managed infrastructure HTTP client configuration is valid"),
            base_url: Arc::from(base_url),
            api_key: Arc::from(api_key),
            include_empty_key,
        }
    }

    async fn execute(&self, request: DashRequest) -> Result<DashClientResponse, DashClientError> {
        let mut headers = header::HeaderMap::new();
        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_static(USER_AGENT),
        );
        if self.include_empty_key || !self.api_key.is_empty() {
            headers.insert(
                header::HeaderName::from_static("x-api-key"),
                header::HeaderValue::from_str(&self.api_key)
                    .map_err(|error| DashClientError::Transport(error.to_string()))?,
            );
        }
        for (name, value) in request.headers {
            headers.insert(
                header::HeaderName::from_bytes(name.as_bytes())
                    .map_err(|error| DashClientError::Transport(error.to_string()))?,
                header::HeaderValue::from_str(&value)
                    .map_err(|error| DashClientError::Transport(error.to_string()))?,
            );
        }
        let mut builder = self
            .http
            .request(request.method, operation_url(&self.base_url, &request.path))
            .headers(headers);
        if let Some(body) = request.body {
            builder = builder.json(&body);
        }
        let response = builder
            .send()
            .await
            .map_err(|error| DashClientError::Transport(error.to_string()))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|error| DashClientError::Transport(error.to_string()))?;
        if status.is_success() {
            Ok(DashClientResponse {
                status,
                data: Some(parse_success_response(&body)),
                error: None,
            })
        } else {
            Ok(DashClientResponse {
                status,
                data: None,
                error: Some(parse_error_response(&body, status)),
            })
        }
    }
}

impl fmt::Debug for ManagedClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedClient")
            .field("base_url", &self.base_url)
            .field("api_key", &"[REDACTED]")
            .field("include_empty_key", &self.include_empty_key)
            .finish_non_exhaustive()
    }
}

/// Shared Dash API client. It always sends `x-api-key`, including an empty one.
#[derive(Clone, Debug)]
pub struct DashApiClient(ManagedClient);

impl DashApiClient {
    pub fn new(options: &ResolvedConnectionOptions) -> Self {
        Self(ManagedClient::new(
            options.api_url.clone(),
            options.api_key().to_owned(),
            options.api_timeout,
            true,
        ))
    }

    pub async fn execute(
        &self,
        request: DashRequest,
    ) -> Result<DashClientResponse, DashClientError> {
        self.0.execute(request).await
    }
}

/// Shared Dash KV client. It omits `x-api-key` when the credential is empty.
#[derive(Clone, Debug)]
pub struct DashKvClient(ManagedClient);

impl DashKvClient {
    pub fn new(options: &ResolvedConnectionOptions) -> Self {
        Self(ManagedClient::new(
            options.kv_url.clone(),
            options.api_key().to_owned(),
            options.kv_timeout,
            false,
        ))
    }

    pub async fn execute(
        &self,
        request: DashRequest,
    ) -> Result<DashClientResponse, DashClientError> {
        self.0.execute(request).await
    }
}

impl From<InfraConnectionOptions> for (DashApiClient, DashKvClient) {
    fn from(options: InfraConnectionOptions) -> Self {
        let resolved = options.resolve();
        (DashApiClient::new(&resolved), DashKvClient::new(&resolved))
    }
}

fn operation_url(base_url: &str, path: &str) -> String {
    let base_url = if base_url.ends_with('/') {
        base_url.to_owned()
    } else {
        format!("{base_url}/")
    };
    url::Url::parse(&base_url)
        .and_then(|base_url| base_url.join(path.trim_start_matches('/')))
        .map_or_else(
            |_| format!("{base_url}{}", path.trim_start_matches('/')),
            |url| url.into(),
        )
}

fn parse_success_response(body: &[u8]) -> Value {
    serde_json::from_slice(body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(body).into_owned()))
}

fn parse_error_response(body: &[u8], status: StatusCode) -> Value {
    let mut error = Map::new();
    if let Ok(value) = serde_json::from_slice::<Value>(body) {
        spread_json_value(&mut error, value);
    }
    error.insert("status".into(), Value::from(status.as_u16()));
    error.insert(
        "statusText".into(),
        Value::String(status.canonical_reason().unwrap_or_default().to_owned()),
    );
    Value::Object(error)
}

fn spread_json_value(target: &mut Map<String, Value>, value: Value) {
    match value {
        Value::Object(object) => target.extend(object),
        Value::Array(values) => target.extend(
            values
                .into_iter()
                .enumerate()
                .map(|(index, value)| (index.to_string(), value)),
        ),
        Value::String(value) => target.extend(
            value
                .chars()
                .enumerate()
                .map(|(index, value)| (index.to_string(), Value::String(value.to_string()))),
        ),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

#[cfg(all(test, feature = "axum"))]
mod tests {
    use super::*;
    use axum::{
        Json, Router,
        extract::State,
        http::{HeaderMap, StatusCode},
        routing::{get, post},
    };
    use serde_json::json;
    use tokio::sync::mpsc;

    #[derive(Debug)]
    struct RecordedRequest {
        path: &'static str,
        headers: HeaderMap,
        body: Option<Value>,
    }

    async fn api(
        State(sender): State<mpsc::UnboundedSender<RecordedRequest>>,
        headers: HeaderMap,
    ) -> Json<Value> {
        sender
            .send(RecordedRequest {
                path: "api",
                headers,
                body: None,
            })
            .unwrap();
        Json(json!({ "ok": true }))
    }

    async fn kv(
        State(sender): State<mpsc::UnboundedSender<RecordedRequest>>,
        headers: HeaderMap,
        Json(body): Json<Value>,
    ) -> Json<Value> {
        sender
            .send(RecordedRequest {
                path: "kv",
                headers,
                body: Some(body),
            })
            .unwrap();
        Json(json!({ "valid": true }))
    }

    async fn rejected() -> (StatusCode, Json<Value>) {
        (
            StatusCode::IM_A_TEAPOT,
            Json(json!({ "message": "no", "status": 999 })),
        )
    }

    async fn empty() -> StatusCode {
        StatusCode::NO_CONTENT
    }

    async fn server() -> (
        String,
        mpsc::UnboundedReceiver<RecordedRequest>,
        tokio::task::JoinHandle<()>,
    ) {
        let (sender, receiver) = mpsc::unbounded_channel();
        let app = Router::new()
            .route("/api/auth/jwks", get(api))
            .route("/identify/request", post(kv))
            .route("/rejected", get(rejected))
            .route("/empty", get(empty))
            .with_state(sender);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (format!("http://{address}"), receiver, task)
    }

    fn resolved(api_url: String, api_key: &str) -> ResolvedConnectionOptions {
        InfraConnectionOptions {
            api_url: Some(api_url.clone()),
            kv_url: Some(api_url),
            api_key: Some(api_key.into()),
            ..InfraConnectionOptions::default()
        }
        .resolve()
    }

    #[tokio::test]
    async fn clients_match_exact_headers_and_body() {
        let (url, mut requests, server) = server().await;
        let options = resolved(url, "managed-key");
        let api = DashApiClient::new(&options);
        let kv = DashKvClient::new(&options);

        assert_eq!(
            api.execute(DashRequest::get("/api/auth/jwks"))
                .await
                .unwrap()
                .data,
            Some(json!({ "ok": true }))
        );
        kv.execute(DashRequest::post(
            "/identify/request",
            json!({ "requestId": "request" }),
        ))
        .await
        .unwrap();

        let api_request = requests.recv().await.unwrap();
        assert_eq!(api_request.path, "api");
        assert_eq!(api_request.headers[header::USER_AGENT], USER_AGENT);
        assert_eq!(api_request.headers["x-api-key"], "managed-key");
        let kv_request = requests.recv().await.unwrap();
        assert_eq!(kv_request.path, "kv");
        assert_eq!(kv_request.headers[header::USER_AGENT], USER_AGENT);
        assert_eq!(kv_request.headers["x-api-key"], "managed-key");
        assert_eq!(kv_request.body, Some(json!({ "requestId": "request" })));
        server.abort();
    }

    #[tokio::test]
    async fn empty_key_is_sent_to_api_and_omitted_from_kv() {
        let (url, mut requests, server) = server().await;
        let options = resolved(url, "");
        DashApiClient::new(&options)
            .execute(DashRequest::get("/api/auth/jwks"))
            .await
            .unwrap();
        DashKvClient::new(&options)
            .execute(DashRequest::post("/identify/request", json!({})))
            .await
            .unwrap();

        assert_eq!(requests.recv().await.unwrap().headers["x-api-key"], "");
        assert!(
            !requests
                .recv()
                .await
                .unwrap()
                .headers
                .contains_key("x-api-key")
        );
        server.abort();
    }

    #[tokio::test]
    async fn request_headers_override_defaults_and_errors_match_better_fetch() {
        let (url, mut requests, server) = server().await;
        let options = resolved(url, "managed-key");
        let api = DashApiClient::new(&options);
        let mut request = DashRequest::get("/api/auth/jwks");
        request
            .headers
            .insert("x-api-key".into(), "route-key".into());
        request
            .headers
            .insert("user-agent".into(), "route-agent".into());
        api.execute(request).await.unwrap();
        let recorded = requests.recv().await.unwrap();
        assert_eq!(recorded.headers["x-api-key"], "route-key");
        assert_eq!(recorded.headers[header::USER_AGENT], "route-agent");

        let rejected = api.execute(DashRequest::get("/rejected")).await.unwrap();
        assert_eq!(rejected.status, StatusCode::IM_A_TEAPOT);
        assert_eq!(
            rejected.error,
            Some(json!({
                "message": "no",
                "status": 418,
                "statusText": "I'm a teapot"
            }))
        );
        let empty = api.execute(DashRequest::get("/empty")).await.unwrap();
        assert_eq!(empty.data, Some(Value::String(String::new())));
        server.abort();
    }
}
