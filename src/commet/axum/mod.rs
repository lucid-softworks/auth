mod input;
mod routes;
mod support;
mod webhook;

use crate::{AuthService, AxumPluginRoute, commet::CommetPlugin};
use std::sync::Arc;

pub(crate) fn routes(service: Arc<AuthService>, plugin: CommetPlugin) -> Vec<AxumPluginRoute> {
    let mut routes = routes::routes(service, plugin.clone());
    if let Some(options) = plugin.options().webhooks() {
        routes.push(webhook::route(
            Arc::<str>::from(options.secret()),
            options.callbacks.clone(),
        ));
    }
    routes
}
