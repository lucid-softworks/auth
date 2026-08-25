pub(super) use axum::{
    Router,
    body::Body,
    http::{HeaderMap, Request, StatusCode, header},
};
pub(super) use http_body_util::BodyExt;
pub(super) use lucid_auth::{
    AuthConfig, AuthPlugin, AuthService, JwtPlugin, McpDpopOptions, McpJwtVerifyOptions, McpPlugin,
    McpPluginConfig, McpProtectedRequest, McpProtectedRequestHandlerOptions,
    McpProtectedRequestOutcome, MemoryStore, OAuthProviderPluginConfig, RequireMcpAuthOptions,
    create_mcp_protected_request_handler, require_mcp_auth,
};
pub(super) use serde_json::{Value, json};
pub(super) use std::sync::Arc;
pub(super) use tower::ServiceExt;

pub(super) const RESOURCE: &str = "http://localhost/mcp";

pub(super) fn plugin() -> McpPlugin {
    let mut provider = OAuthProviderPluginConfig::new("/login", "/consent");
    provider.scopes.push("mcp.read".into());
    McpPlugin::in_memory(McpPluginConfig::new(RESOURCE, provider)).unwrap()
}

pub(super) fn app() -> Router {
    let mut config = AuthConfig::new([213_u8; 32]).unwrap();
    config.set_base_url("http://localhost").unwrap();
    config.add_plugin(JwtPlugin::default()).unwrap();
    config.add_plugin(plugin()).unwrap();
    let service = Arc::new(AuthService::try_new(Arc::new(MemoryStore::default()), config).unwrap());
    lucid_auth::axum::router(service)
}

pub(super) async fn request(
    app: &Router,
    method: &str,
    path: &str,
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (status, headers, body.to_vec())
}

pub(super) fn handler_options() -> McpProtectedRequestHandlerOptions {
    McpProtectedRequestHandlerOptions {
        issuer: "https://issuer.example".into(),
        audience: "https://api.example/mcp".into(),
        jwt_verify_options: McpJwtVerifyOptions::default(),
        jwks_url: None,
        remote_verify: None,
        required_scopes: Some(vec!["mcp.read".into()]),
        challenge_scopes: Some(vec!["mcp.read".into(), "mcp.write".into()]),
        is_scope_satisfied: None,
        dpop: McpDpopOptions::default(),
    }
}
