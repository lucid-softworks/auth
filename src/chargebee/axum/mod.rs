mod input;
mod routes;
mod support;

use super::{ChargebeeOptions, ChargebeePlugin, ChargebeeStore};
use crate::{AuthService, AxumPluginRoute};
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct ChargebeeRouteState {
    pub(super) options: Arc<ChargebeeOptions>,
    pub(super) store: Arc<dyn ChargebeeStore>,
}

impl From<ChargebeePlugin> for ChargebeeRouteState {
    fn from(plugin: ChargebeePlugin) -> Self {
        Self {
            options: plugin.options,
            store: plugin.store,
        }
    }
}

pub(crate) fn routes(service: Arc<AuthService>, plugin: ChargebeePlugin) -> Vec<AxumPluginRoute> {
    routes::routes(service, ChargebeeRouteState::from(plugin))
}
