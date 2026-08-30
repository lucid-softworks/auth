mod management;
mod mutation;
mod registration;
mod sanitize;
mod support;

use super::SsoPlugin;
use crate::{AuthService, AxumPluginRoute};
use axum::{Extension, routing::get};
use std::sync::Arc;

pub(super) fn routes(
    _service: Arc<AuthService>,
    plugin: Arc<SsoPlugin>,
) -> Vec<AxumPluginRoute> {
    vec![
        AxumPluginRoute::new(
            "/sso/providers",
            get(management::list).layer(Extension(plugin.clone())),
        ),
        AxumPluginRoute::new(
            "/sso/get-provider",
            get(management::get).layer(Extension(plugin.clone())),
        ),
        AxumPluginRoute::new(
            "/sso/register",
            axum::routing::post(registration::register).layer(Extension(plugin.clone())),
        ),
        AxumPluginRoute::new(
            "/sso/update-provider",
            axum::routing::post(mutation::update).layer(Extension(plugin.clone())),
        ),
        AxumPluginRoute::new(
            "/sso/delete-provider",
            axum::routing::post(mutation::delete).layer(Extension(plugin)),
        ),
    ]
}
