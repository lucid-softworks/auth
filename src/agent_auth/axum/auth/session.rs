use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::OriginalUri,
    http::{HeaderMap, Method},
    response::IntoResponse,
};

use super::{
    AgentAuthState, AgentRequestContext, ScopedAgentAuthentication, authenticate_scoped,
    request_url,
};
use crate::AuthService;

pub(in crate::agent_auth::axum) async fn session(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    OriginalUri(uri): OriginalUri,
    method: Method,
    headers: HeaderMap,
) -> axum::response::Response {
    let base_url = super::issuer(&service, &headers);
    let url = request_url(&service, &headers, &uri);
    let request = AgentRequestContext {
        path: "/agent/session",
        method: method.as_str(),
        base_url: &base_url,
        url: &url,
        headers: &headers,
        serialized_body: None,
    };
    match authenticate_scoped(&service, &state, request).await {
        Ok(ScopedAgentAuthentication::Agent(session)) => Json(session).into_response(),
        Ok(ScopedAgentAuthentication::NotApplicable | ScopedAgentAuthentication::Host(_)) => {
            Json(serde_json::Value::Null).into_response()
        }
        Err(error) => error.into_response(&discovery_origin(&base_url)),
    }
}

fn discovery_origin(base_url: &str) -> String {
    url::Url::parse(base_url)
        .map(|url| url.origin().ascii_serialization())
        .unwrap_or_else(|_| base_url.trim_end_matches('/').to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_discovery_is_always_origin_root() {
        assert_eq!(
            discovery_origin("https://auth.example.test/api/auth"),
            "https://auth.example.test"
        );
    }
}
