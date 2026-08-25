use super::{AgentAuthState, issuer};
use crate::AuthService;
use axum::{Extension, Json, http::HeaderMap, response::IntoResponse};
use serde_json::{Map, Value, json};
use std::sync::Arc;

pub(super) async fn configuration(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<AgentAuthState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let issuer = issuer(&service, &headers);
    let paths = [
        ("register", "/agent/register"),
        ("capabilities", "/capability/list"),
        ("describe_capability", "/capability/describe"),
        ("execute", "/capability/execute"),
        ("request_capability", "/agent/request-capability"),
        ("status", "/agent/status"),
        ("reactivate", "/agent/reactivate"),
        ("revoke", "/agent/revoke"),
        ("revoke_host", "/host/revoke"),
        ("rotate_key", "/agent/rotate-key"),
        ("rotate_host_key", "/host/rotate-key"),
        ("introspect", "/agent/introspect"),
    ];
    let endpoints = Map::from_iter(
        paths
            .into_iter()
            .map(|(name, path)| (name.into(), Value::String(format!("{issuer}{path}")))),
    );
    let mut document = Map::from_iter([
        ("version".into(), json!("1.0-draft")),
        (
            "provider_name".into(),
            json!(
                state
                    .config
                    .provider_name
                    .as_deref()
                    .unwrap_or("agent-auth")
            ),
        ),
        (
            "description".into(),
            json!(
                state
                    .config
                    .provider_description
                    .as_deref()
                    .unwrap_or("Agent Auth enabled service")
            ),
        ),
        ("issuer".into(), json!(issuer)),
        (
            "default_location".into(),
            json!(format!("{issuer}/capability/execute")),
        ),
        (
            "algorithms".into(),
            json!(state.config.allowed_key_algorithms),
        ),
        ("modes".into(), json!(state.config.modes)),
        (
            "approval_methods".into(),
            json!(state.config.approval_methods),
        ),
        ("endpoints".into(), Value::Object(endpoints)),
    ]);
    if let Some(jwks_uri) = &state.config.jwks_uri {
        document.insert("jwks_uri".into(), json!(jwks_uri));
    }
    let mut response = Json(Value::Object(document)).into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("public, max-age=3600"),
    );
    response
}
