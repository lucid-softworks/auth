use super::{OAuthProviderConfig, OAuthProviderStore};
use crate::{AuthService, AxumPluginRoute};
use std::sync::Arc;

mod authorize;
mod body;
mod client;
mod logout;
pub(crate) mod management;
mod metadata;
mod provider_api;
mod resource;
pub(crate) mod response;
mod token;

pub use provider_api::*;

pub(super) fn routes(
    config: Arc<OAuthProviderConfig>,
    store: Arc<dyn OAuthProviderStore>,
) -> Vec<AxumPluginRoute> {
    let mut routes = metadata::routes(config.clone());
    routes.extend(authorize::routes(config.clone(), store.clone()));
    routes.extend(logout::routes(config.clone(), store.clone()));
    routes.extend(management::routes(config.clone(), store.clone()));
    routes.extend(token::routes(config.clone(), store.clone()));
    routes.extend(resource::routes(config, store));
    routes
}

pub(super) fn root_routes(
    service: &AuthService,
    config: Arc<OAuthProviderConfig>,
) -> Vec<AxumPluginRoute> {
    metadata::root_routes(service, config)
}
