mod input;
mod route_table;
mod routes;
mod support;

use crate::autumn::{AutumnClient, AutumnOptions, AutumnPlugin};
use std::sync::Arc;

#[derive(Clone)]
pub(crate) struct AutumnRouteState {
    pub(super) options: Arc<AutumnOptions>,
    pub(super) client: Arc<dyn AutumnClient>,
}

impl AutumnRouteState {
    pub(crate) fn from_plugin(plugin: &AutumnPlugin) -> Self {
        Self {
            options: plugin.options.clone(),
            client: plugin.options.client.clone(),
        }
    }
}

pub(crate) fn routes(
    service: Arc<crate::AuthService>,
    state: AutumnRouteState,
) -> Vec<crate::AxumPluginRoute> {
    routes::routes(service, state)
}
