use crate::{AuthService, AxumPluginRoute, OAuthProviderPluginConfig};
use axum::{Extension, routing::any};
use std::sync::Arc;

mod metadata;

const PROTECTED_RESOURCE_METADATA_PATH: &str = "/.well-known/oauth-protected-resource";

pub(super) fn root_routes(
    service: Arc<AuthService>,
    config: Arc<OAuthProviderPluginConfig>,
    resource: String,
) -> Vec<AxumPluginRoute> {
    let state = metadata::MetadataState::new(config, resource, service.skip_trailing_slashes());
    let route = || any(metadata::protected_resource).layer(Extension(state.clone()));
    vec![
        AxumPluginRoute::new(PROTECTED_RESOURCE_METADATA_PATH, route()),
        AxumPluginRoute::new(
            format!("{PROTECTED_RESOURCE_METADATA_PATH}/{{*mcp_resource_path}}"),
            route(),
        ),
    ]
}
