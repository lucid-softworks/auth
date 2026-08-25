use super::PROTECTED_RESOURCE_METADATA_PATH;
use crate::{AuthService, OAuthProviderPluginConfig};
use axum::{
    Extension, Json,
    body::Body,
    http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use serde_json::{Map, Value, json};
use std::{collections::BTreeSet, sync::Arc};

const METADATA_CACHE_CONTROL: &str =
    "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400";
const OIDC_SCOPES: &[&str] = &[
    "openid",
    "profile",
    "email",
    "phone",
    "address",
    "offline_access",
];

#[derive(Clone)]
pub(super) struct MetadataState {
    config: Arc<OAuthProviderPluginConfig>,
    resource: String,
    served_paths: BTreeSet<String>,
    skip_trailing_slashes: bool,
}

impl MetadataState {
    pub(super) fn new(
        config: Arc<OAuthProviderPluginConfig>,
        resource: String,
        skip_trailing_slashes: bool,
    ) -> Self {
        let parsed = url::Url::parse(&resource)
            .expect("MCP resource is validated while the plugin registry is built");
        let resource_path = parsed
            .path()
            .strip_suffix('/')
            .unwrap_or_else(|| parsed.path())
            .to_owned();
        let served_paths = BTreeSet::from([
            PROTECTED_RESOURCE_METADATA_PATH.to_owned(),
            format!("{PROTECTED_RESOURCE_METADATA_PATH}{resource_path}"),
        ]);
        Self {
            config,
            resource,
            served_paths,
            skip_trailing_slashes,
        }
    }

    fn serves(&self, path: &str) -> bool {
        let path = if self.skip_trailing_slashes {
            path.trim_end_matches('/')
        } else {
            path
        };
        self.served_paths.contains(path)
    }
}

pub(super) async fn protected_resource(
    Extension(service): Extension<Arc<AuthService>>,
    Extension(state): Extension<MetadataState>,
    method: Method,
    headers: HeaderMap,
    uri: Uri,
) -> Response {
    if !state.serves(uri.path()) {
        return StatusCode::NOT_FOUND.into_response();
    }
    if method != Method::GET && method != Method::HEAD {
        let mut response = StatusCode::METHOD_NOT_ALLOWED.into_response();
        response
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static("GET, HEAD"));
        return response;
    }
    let issuer =
        crate::oauth_provider::axum::metadata::provider_issuer(&service, &headers, &state.config);
    let mut response = metadata_response(document(&state, issuer));
    if method == Method::HEAD {
        *response.body_mut() = Body::empty();
    }
    response
}

fn document(state: &MetadataState, issuer: String) -> Value {
    let mut metadata = Map::from_iter([
        ("resource".into(), json!(state.resource)),
        ("authorization_servers".into(), json!([issuer])),
        ("bearer_methods_supported".into(), json!(["header"])),
        (
            "dpop_signing_alg_values_supported".into(),
            json!(state.config.dpop.signing_algorithms),
        ),
    ]);
    if state
        .config
        .resources
        .iter()
        .find(|resource| resource.identifier == state.resource)
        .is_some_and(|resource| resource.dpop_bound_access_tokens_required == Some(true))
    {
        metadata.insert(
            "dpop_bound_access_tokens_required".into(),
            Value::Bool(true),
        );
    }
    let scopes: Vec<_> = state
        .config
        .advertised_metadata
        .scopes_supported
        .as_ref()
        .unwrap_or(&state.config.scopes)
        .iter()
        .filter(|scope| !OIDC_SCOPES.contains(&scope.as_str()))
        .cloned()
        .collect();
    if !scopes.is_empty() {
        metadata.insert("scopes_supported".into(), json!(scopes));
    }
    Value::Object(metadata)
}

fn metadata_response(body: Value) -> Response {
    let mut response = Json(body).into_response();
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(METADATA_CACHE_CONTROL),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{McpPluginConfig, OAuthProviderPluginConfig, OAuthResourceInput};

    fn state(resource: &str, trailing: bool) -> MetadataState {
        let mut config = OAuthProviderPluginConfig::new("/login", "/consent");
        config.scopes = ["openid", "profile", "mcp.read", "mcp.write"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        config.advertised_metadata.scopes_supported =
            Some(vec!["openid".into(), "mcp.read".into(), "mcp.write".into()]);
        let mut protected = OAuthResourceInput::from(resource);
        protected.dpop_bound_access_tokens_required = Some(true);
        config.resources.push(protected);
        let config = McpPluginConfig::new(resource, config)
            .effective_oauth_provider()
            .unwrap();
        MetadataState::new(Arc::new(config), resource.into(), trailing)
    }

    #[test]
    fn exposes_the_root_and_resource_path_aliases() {
        let exact = state("https://resource.example/mcp/", false);
        assert!(exact.serves(PROTECTED_RESOURCE_METADATA_PATH));
        assert!(exact.serves("/.well-known/oauth-protected-resource/mcp"));
        assert!(!exact.serves("/.well-known/oauth-protected-resource/mcp/"));

        let trailing = state("https://resource.example/mcp/", true);
        assert!(trailing.serves("/.well-known/oauth-protected-resource/mcp///"));
    }

    #[test]
    fn document_matches_the_mcp_metadata_contract() {
        let state = state("https://resource.example/mcp/", false);
        assert_eq!(
            document(&state, "https://issuer.example/api/auth".into()),
            json!({
                "resource": "https://resource.example/mcp/",
                "authorization_servers": ["https://issuer.example/api/auth"],
                "bearer_methods_supported": ["header"],
                "dpop_signing_alg_values_supported": ["EdDSA", "ES256", "ES512", "PS256", "RS256"],
                "dpop_bound_access_tokens_required": true,
                "scopes_supported": ["mcp.read", "mcp.write"]
            })
        );
    }
}
